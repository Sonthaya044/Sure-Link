import os
import json
import sqlite3
import time
import logging
import base64
import requests
from urllib.parse import urlparse
from flask import Blueprint, request, jsonify, render_template, current_app
from flask_limiter.util import get_remote_address

scan_bp = Blueprint('scan', __name__)

# Helper functions migrated from app.py
def get_db_connection():
    db_path = current_app.config['DB_PATH']
    conn = sqlite3.connect(db_path, timeout=20)
    conn.execute('PRAGMA journal_mode=WAL;')
    conn.row_factory = sqlite3.Row
    return conn

def get_domain(url):
    try:
        parsed = urlparse(url)
        return parsed.netloc or parsed.path
    except Exception:
        return "N/A"

def get_vt_url_id(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip('=')

def parse_vt_stats(stats, results, url):
    malicious  = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    harmless   = stats.get('harmless', 0)
    undetected = stats.get('undetected', 0)
    
    total = malicious + suspicious + harmless + undetected
    malicious_pct = (malicious / total * 100) if total > 0 else 0
    
    if malicious >= 3 or malicious_pct >= 20:
        tier = "High"
    elif malicious >= 1 or suspicious >= 2:
        tier = "Medium"
    else:
        tier = "Low"

    return {
        "url":            url,
        "domain":         get_domain(url),
        "ip_address":     "Scan via API",
        "tier":           tier,
        "malicious":      malicious,
        "suspicious":     suspicious,
        "harmless":       stats.get('harmless', 0),
        "undetected":     stats.get('undetected', 0),
        "engine_results": results
    }

def search_db(url):
    conn = get_db_connection()
    try:
        row = conn.execute(
            'SELECT * FROM url_cache WHERE url = ?',
            (url,)
        ).fetchone()
        
        if row:
            if (time.time() - row['scanned_timestamp']) > 604800:
                return None
            try:
                cached_data = json.loads(row['raw_data'])
                if not isinstance(cached_data, dict): cached_data = {}
                if 'tier' not in cached_data: cached_data['tier'] = row['tier']
                if 'url' not in cached_data: cached_data['url'] = row['url']
                if 'domain' not in cached_data: cached_data['domain'] = row['domain']
                if 'malicious' not in cached_data: cached_data['malicious'] = row['malicious_count']
                if 'suspicious' not in cached_data: cached_data['suspicious'] = 0
                if 'harmless' not in cached_data: cached_data['harmless'] = 0
                if 'undetected' not in cached_data: cached_data['undetected'] = 0
                if 'engine_results' not in cached_data: cached_data['engine_results'] = {}
                return cached_data
            except (json.JSONDecodeError, TypeError):
                logging.warning(f"  ⚠️ ไม่สามารถแปลง JSON จาก cache: {url}")
                return None
        return None
    except Exception as e:
        logging.error(f"  ❌ Database error in search_db: {e}")
        return None
    finally:
        conn.close()

def scan_with_virustotal(url):
    api_key = current_app.config['VT_API_KEY']
    if not api_key:
        raise ValueError("ไม่พบ VT_API_KEY — กรุณาตั้งค่าในไฟล์ .env")

    headers = { "accept": "application/json", "x-apikey": api_key }
    url_id = get_vt_url_id(url)

    try:
        cached_response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=15
        )
        if cached_response.status_code == 200:
            attr = cached_response.json().get('data', {}).get('attributes', {})
            stats = attr.get('last_analysis_stats', {})
            results = attr.get('last_analysis_results', {})
            if sum(stats.values()) > 0:
                return parse_vt_stats(stats, results, url)
    except Exception: pass

    submit_headers = {**headers, "content-type": "application/x-www-form-urlencoded"}
    submit_response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        data={"url": url}, headers=submit_headers, timeout=15
    )
    submit_response.raise_for_status()

    analysis_id = submit_response.json().get('data', {}).get('id')
    for _ in range(8):
        time.sleep(3)
        try:
            report_response = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers, timeout=15
            )
            report_data = report_response.json()
            status = report_data.get('data', {}).get('attributes', {}).get('status', '')
            if status == 'completed':
                attr = report_data.get('data', {}).get('attributes', {})
                return parse_vt_stats(attr.get('stats', {}), attr.get('results', {}), url)
        except Exception: continue
    return parse_vt_stats({}, {}, url)

def save_to_db(data):
    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT INTO url_cache
                (url, domain, tier, malicious_count, raw_data, scanned_timestamp, scan_count)
            VALUES (?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(url) DO UPDATE SET
                domain=excluded.domain,
                tier=excluded.tier,
                malicious_count=excluded.malicious_count,
                raw_data=excluded.raw_data,
                scanned_timestamp=excluded.scanned_timestamp,
                scan_count=url_cache.scan_count + 1
        ''', (
            data['url'], data['domain'], data['tier'], data['malicious'],
            json.dumps(data), time.time()
        ))
        conn.commit()
    except Exception as e:
        logging.error(f"  ❌ Database error in save_to_db: {e}")
        conn.rollback()
    finally:
        conn.close()

@scan_bp.route('/scan', methods=['POST'])
def scan_url():
    url = request.form.get('url', '').strip()
    if not url: return jsonify({"error": "ไม่พบ URL"}), 400
    if not url.startswith(('http://', 'https://')): url = 'http://' + url

    try:
        cached = search_db(url)
        if cached:
            conn = get_db_connection()
            conn.execute('UPDATE url_cache SET scan_count = scan_count + 1 WHERE url = ?', (url,))
            conn.commit()
            conn.close()
            return jsonify(cached)

        data = scan_with_virustotal(url)
        save_to_db(data)
        return jsonify(data)
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 429:
            logging.error(f"  ❌ VirusTotal API Rate Limit: {e}")
            return jsonify({"error": "โควต้า VirusTotal API ของคุณหมดแล้ว (429) กรุณาลองใหม่ภายหลัง"}), 429
        return jsonify({"error": f"เกิดข้อผิดพลาดจาก API: {str(e)}"}), 502
    except requests.exceptions.RequestException as e:
        logging.error(f"  ❌ Network error: {e}")
        return jsonify({"error": "การเชื่อมต่อ VirusTotal ล้มเหลว"}), 502
    except Exception as e:
        logging.error(f"  ❌ Unexpected error: {e}")
        return jsonify({"error": str(e)}), 500

@scan_bp.route('/result')
def result():
    url = request.args.get('url', '').strip()
    if not url: return render_template('home.html', error="ไม่พบ URL ที่ต้องการแสดงผล")
    
    data = search_db(url)
    if not data:
        return render_template('home.html', error="ไม่พบข้อมูลการสแกนสำหรับ URL นี้")
    
    return render_template('dashboard.html', data=data)
