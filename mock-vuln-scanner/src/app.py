from flask import Flask, jsonify
import requests
import random
from datetime import datetime
import os

app = Flask(__name__)
INTEGRATION_URL = os.getenv('INTEGRATION_URL', 'http://integration:8000')

# Simulate vulnerability findings
VULNERABILITIES = [
    {'cve': 'CVE-2024-1234', 'name': 'OpenSSL Buffer Overflow', 'cvss': 9.8},
    {'cve': 'CVE-2024-5678', 'name': 'Django SQL Injection', 'cvss': 9.1},
    {'cve': 'CVE-2024-9012', 'name': 'Apache RCE', 'cvss': 10.0},
    {'cve': 'CVE-2024-3456', 'name': 'Weak SSL Config', 'cvss': 7.5},
    {'cve': 'CVE-2024-7890', 'name': 'Unpatched PHP Version', 'cvss': 8.9},
]

@app.route('/trigger-scan', methods=['GET'])
def trigger_scan():
    """Vuln scanner finds vulnerability and sends alert"""
    
    vuln = random.choice(VULNERABILITIES)
    
    scanner_alert = {
        'source_system': 'VULN_SCANNER',
        'alert_id': f'VULN-{random.randint(100000, 999999)}',
        'timestamp': datetime.now().isoformat(),
        'cve_id': vuln['cve'],
        'vulnerability_name': vuln['name'],
        'cvss_score': vuln['cvss'],
        'affected_host': f'server-{random.randint(1,10)}.prod.umass.edu',
        'affected_service': random.choice(['Apache', 'OpenSSL', 'Django', 'PHP']),
        'remediation': f'Update to latest patch for {vuln["cve"]}',
        'severity': 'CRITICAL' if vuln['cvss'] >= 9.0 else 'HIGH' if vuln['cvss'] >= 7.0 else 'MEDIUM'
    }
    
    # Send to integration
    response = requests.post(
        f'{INTEGRATION_URL}/webhook/security-alert',
        json=scanner_alert
    )
    
    return jsonify({
        'status': 'alert_sent',
        'scanner_alert': scanner_alert,
        'integration_response': response.json()
    }), 200

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'service': 'vuln_scanner'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)