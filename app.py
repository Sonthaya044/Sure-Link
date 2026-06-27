import os
import json
import sqlite3
import time
import logging
import base64
import requests
from urllib.parse import urlparse
from flask import Flask, request, jsonify, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BASE_DIR, '.env')
DB_PATH  = os.path.join(BASE_DIR, 'securescan.db')
LOG_PATH = os.path.join(BASE_DIR, 'scan_backend.log')

load_dotenv(ENV_PATH)
VT_API_KEY = os.getenv("VT_API_KEY")

app = Flask(__name__)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
limiter = Limiter(get_remote_address, app=app, default_limits=["100 per day"], storage_uri="memory://")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.execute('PRAGMA journal_mode=WAL;')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    try:
        conn = get_db_connection()
        conn.execute('''
            CREATE TABLE IF NOT EXISTS url_cache (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                url               TEXT UNIQUE NOT NULL,
                domain            TEXT,
                tier              TEXT,
                malicious_count   INTEGER,
                raw_data          TEXT,
                scanned_timestamp REAL,
                scan_count        INTEGER DEFAULT 1
            )
        ''')
        cursor = conn.execute("PRAGMA table_info(url_cache)")
        columns = [row['name'] for row in cursor.fetchall()]
        if 'scan_count' not in columns:
            conn.execute('ALTER TABLE url_cache ADD COLUMN scan_count INTEGER DEFAULT 1')
        conn.commit()
    except Exception as e:
        logging.error(f"❌ ไม่สามารถเริ่มต้น Database: {e}")
    finally:
        if 'conn' in locals(): conn.close()

init_db()

def get_domain(url):
    try: return urlparse(url).netloc or urlparse(url).path
    except Exception: return "N/A"

def get_vt_url_id(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip('=')

def parse_vt_stats(stats, results, url):
    malicious  = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    harmless   = stats.get('harmless', 0)
    undetected = stats.get('undetected', 0)
    
    total = malicious + suspicious + harmless + undetected
    malicious_pct = (malicious / total * 100) if total > 0 else 0
    
    if malicious >= 3 or malicious_pct >= 20: tier = "High"
    elif malicious >= 1 or suspicious >= 2: tier = "Medium"
    else: tier = "Low"

    return {
        "url": url, "domain": get_domain(url), "ip_address": "Scan via API",
        "tier": tier, "malicious": malicious, "suspicious": suspicious,
        "harmless": stats.get('harmless', 0), "undetected": stats.get('undetected', 0),
        "engine_results": results
    }

def search_db(url):
    conn = get_db_connection()
    try:
        row = conn.execute('SELECT * FROM url_cache WHERE url = ?', (url,)).fetchone()
        if row:
            if (time.time() - row['scanned_timestamp']) > 604800: return None
            try:
                cached_data = json.loads(row['raw_data'])
                if not isinstance(cached_data, dict): cached_data = {}
                cached_data['tier'] = row['tier']
                cached_data['url'] = row['url']
                cached_data['domain'] = row['domain']
                cached_data['malicious'] = row['malicious_count']
                return cached_data
            except: return None
        return None
    except: return None
    finally: conn.close()

def scan_with_virustotal(url):
    if not VT_API_KEY: raise ValueError("ไม่พบ VT_API_KEY ในไฟล์ .env")
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    url_id = get_vt_url_id(url)

    try:
        cached_response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=15)
        if cached_response.status_code == 200:
            attr = cached_response.json().get('data', {}).get('attributes', {})
            stats = attr.get('last_analysis_stats', {})
            if sum(stats.values()) > 0:
                return parse_vt_stats(stats, attr.get('last_analysis_results', {}), url)
    except: pass

    submit_headers = {**headers, "content-type": "application/x-www-form-urlencoded"}
    submit_response = requests.post("https://www.virustotal.com/api/v3/urls", data={"url": url}, headers=submit_headers, timeout=15)
    submit_response.raise_for_status()

    analysis_id = submit_response.json().get('data', {}).get('id')
    for _ in range(8):
        time.sleep(3)
        try:
            report_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=15)
            report_data = report_response.json()
            if report_data.get('data', {}).get('attributes', {}).get('status', '') == 'completed':
                attr = report_data.get('data', {}).get('attributes', {})
                return parse_vt_stats(attr.get('stats', {}), attr.get('results', {}), url)
        except: continue

    return parse_vt_stats({}, {}, url)

def save_to_db(data):
    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT INTO url_cache (url, domain, tier, malicious_count, raw_data, scanned_timestamp, scan_count)
            VALUES (?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(url) DO UPDATE SET
                domain=excluded.domain, tier=excluded.tier, malicious_count=excluded.malicious_count,
                raw_data=excluded.raw_data, scanned_timestamp=excluded.scanned_timestamp, scan_count=url_cache.scan_count + 1
        ''', (data['url'], data['domain'], data['tier'], data['malicious'], json.dumps(data), time.time()))
        conn.commit()
    except: conn.rollback()
    finally: conn.close()

def classify_threat(result_name, category):
    r = result_name.lower()
    if any(kw in r for kw in ['phish', 'scam', 'fraud', 'credential', 'fake']): return 'Phishing'
    if 'trojan' in r: return 'Trojan'
    if 'ransom' in r: return 'Ransomware'
    if 'adware' in r: return 'Adware'
    if any(kw in r for kw in ['spam', 'pup', 'risk']): return 'Spam / PUP'
    if 'spyware' in r: return 'Spyware'
    if 'worm' in r: return 'Worm'
    if any(kw in r for kw in ['bot', 'backdoor', 'exploit']): return 'Botnet / Backdoor'
    if any(kw in r for kw in ['malware', 'virus', 'downloader']): return 'Malware'
    if 'suspicious' in r or category == 'suspicious': return 'Suspicious'
    return 'Malicious'

def aggregate_analytics():
    conn = get_db_connection()
    try:
        table_check = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='url_cache'").fetchone()
        if not table_check: return {'total_scans': 0, 'tier_counts': {}, 'top_domains': [], 'top_sites': [], 'top_threats': []}

        total_scans = conn.execute('SELECT SUM(scan_count) AS total FROM url_cache').fetchone()['total'] or 0
        tier_rows = conn.execute('SELECT tier, COUNT(*) AS count FROM url_cache GROUP BY tier').fetchall()
        tier_counts = {row['tier']: row['count'] for row in tier_rows}

        top_domains = conn.execute("SELECT domain, SUM(scan_count) AS count FROM url_cache WHERE domain != 'N/A' AND domain != '' GROUP BY domain ORDER BY count DESC LIMIT 8").fetchall()
        top_sites = conn.execute('SELECT url, scan_count AS scanned_count FROM url_cache ORDER BY scan_count DESC LIMIT 8').fetchall()

        threat_counts = {}
        threat_rows = conn.execute('SELECT raw_data FROM url_cache WHERE tier IN ("High", "Medium") AND raw_data != ""').fetchall()

        for row in threat_rows:
            try: data = json.loads(row['raw_data'])
            except: continue
            
            engine_results = data.get('engine_results')
            found_threats = set() 
            if engine_results and isinstance(engine_results, dict):
                for res in engine_results.values():
                    if isinstance(res, dict) and res.get('category') in ('malicious', 'suspicious'):
                        found_threats.add(classify_threat(str(res.get('result', '')), res.get('category')))
            else:
                stats = data.get('stats', {})
                if isinstance(stats, dict):
                    if int(stats.get('malicious', 0)) > 0: found_threats.add('Malicious')
                    if int(stats.get('suspicious', 0)) > 0: found_threats.add('Suspicious')

            for t in found_threats: threat_counts[t] = threat_counts.get(t, 0) + 1

        return {
            'total_scans': total_scans, 'tier_counts': tier_counts,
            'top_domains': [{'domain': r['domain'], 'count': r['count']} for r in top_domains],
            'top_sites': [{'url': r['url'], 'scanned_count': r['scanned_count']} for r in top_sites],
            'top_threats': [{'threat': k, 'count': v} for k, v in sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)]
        }
    except: return {'total_scans': 0, 'tier_counts': {}, 'top_domains': [], 'top_sites': [], 'top_threats': []}
    finally: conn.close()

@app.route('/analytics')
def analytics(): return jsonify(aggregate_analytics())

@app.route('/')
def index(): return render_template('home.html')

@app.route('/history')
def history(): return render_template('history.html')

@app.route('/scan', methods=['POST'])
@limiter.limit("10 per minute")
def scan_url():
    url = request.form.get('url', '').strip()
    if not url: return render_template('home.html', error="กรุณากรอก URL ที่ต้องการสแกน")
    if not url.startswith(('http://', 'https://')): url = 'http://' + url

    try:
        cached = search_db(url)
        if cached:
            conn = get_db_connection()
            conn.execute('UPDATE url_cache SET scan_count = scan_count + 1 WHERE url = ?', (url,))
            conn.commit()
            conn.close()
            return render_template('dashboard.html', data=cached)

        data = scan_with_virustotal(url)
        save_to_db(data)
        return render_template('dashboard.html', data=data)
    except Exception as e:
        return render_template('home.html', error="ระบบไม่สามารถวิเคราะห์ URL ได้ในขณะนี้ กรุณาลองใหม่ภายหลัง")

@app.errorhandler(429)
def ratelimit_handler(e): return render_template('home.html', error="คุณตรวจสอบลิงก์ถี่เกินไป กรุณารอสักครู่")

if __name__ == '__main__':
    app.run(debug=True, port=5000)