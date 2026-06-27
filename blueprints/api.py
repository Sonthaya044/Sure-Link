import json
import sqlite3
import logging
from flask import Blueprint, jsonify, current_app

api_bp = Blueprint('api', __name__)

def get_db_connection():
    db_path = current_app.config['DB_PATH']
    conn = sqlite3.connect(db_path, timeout=20)
    conn.row_factory = sqlite3.Row
    return conn

def classify_threat(result_name, category):
    r = result_name.lower()
    if any(kw in r for kw in ['phish', 'scam', 'fraud', 'credential', 'fake']): return 'Phishing'
    if 'trojan'   in r: return 'Trojan'
    if 'ransom'   in r: return 'Ransomware'
    if 'adware'   in r: return 'Adware'
    if any(kw in r for kw in ['spam', 'pup', 'risk']): return 'Spam / PUP'
    if 'spyware'  in r: return 'Spyware'
    if 'worm'     in r: return 'Worm'
    if any(kw in r for kw in ['bot', 'backdoor', 'exploit']): return 'Botnet / Backdoor'
    if any(kw in r for kw in ['malware', 'virus', 'downloader']): return 'Malware'
    if 'suspicious' in r or category == 'suspicious': return 'Suspicious'
    return 'Malicious'

def aggregate_analytics():
    conn = get_db_connection()
    try:
        table_check = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='url_cache'"
        ).fetchone()
        if not table_check:
            return {'total_scans': 0, 'tier_counts': {}, 'top_domains': [], 'top_sites': [], 'top_threats': []}

        total_scans_row = conn.execute('SELECT SUM(scan_count) AS total FROM url_cache').fetchone()
        total_scans = int(total_scans_row['total']) if total_scans_row and total_scans_row['total'] else 0

        tier_rows = conn.execute('SELECT tier, COUNT(*) AS count FROM url_cache GROUP BY tier').fetchall()
        tier_counts = {}
        for row in tier_rows:
            tier_counts[row['tier']] = row['count']

        top_domains = conn.execute('''
            SELECT domain, SUM(scan_count) AS count
            FROM url_cache
            WHERE domain IS NOT NULL AND domain != 'N/A' AND domain != ''
            GROUP BY domain
            ORDER BY count DESC
            LIMIT 8
        ''').fetchall()

        top_sites = conn.execute('''
            SELECT url, scan_count AS scanned_count
            FROM url_cache
            ORDER BY scan_count DESC
            LIMIT 8
        ''').fetchall()

        threat_counts = {}
        threat_rows = conn.execute('''
            SELECT raw_data
            FROM url_cache
            WHERE tier IN ("High", "Medium")
              AND raw_data IS NOT NULL AND raw_data != ''
        ''').fetchall()

        for row in threat_rows:
            try:
                data = json.loads(row['raw_data'])
            except: continue
            engine_results = data.get('engine_results')
            found_threats_in_this_url = set()
            if engine_results and isinstance(engine_results, dict):
                for _engine, result in engine_results.items():
                    if not isinstance(result, dict): continue
                    category = result.get('category', '')
                    result_name = str(result.get('result', ''))
                    if category in ('malicious', 'suspicious'):
                        t = classify_threat(result_name, category)
                        found_threats_in_this_url.add(t)
            else:
                stats = data.get('stats', {})
                if isinstance(stats, dict):
                    if int(stats.get('malicious',  0)) > 0: found_threats_in_this_url.add('Malicious')
                    if int(stats.get('suspicious', 0)) > 0: found_threats_in_this_url.add('Suspicious')
            for t in found_threats_in_this_url:
                threat_counts[t] = threat_counts.get(t, 0) + 1

        return {
            'total_scans': total_scans,
            'tier_counts': tier_counts,
            'top_domains': [{'domain': row['domain'] or 'N/A', 'count': row['count']} for row in top_domains],
            'top_sites': [{'url': row['url'], 'scanned_count': row['scanned_count']} for row in top_sites],
            'top_threats': [{'threat': name, 'count': count} for name, count in sorted(threat_counts.items(), key=lambda x: x[1], reverse=True) if count > 0]
        }
    except Exception as e:
        logging.error(f"❌ Error in aggregate_analytics: {e}")
        return {'total_scans': 0, 'tier_counts': {}, 'top_domains': [], 'top_sites': [], 'top_threats': []}
    finally:
        conn.close()

@api_bp.route('/analytics')
def analytics():
    return jsonify(aggregate_analytics())
