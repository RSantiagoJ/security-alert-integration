from flask import Flask, jsonify
import requests
import random
from datetime import datetime
import os

app = Flask(__name__)
INTEGRATION_URL = os.getenv('INTEGRATION_URL', 'http://integration:8000')

# Simulate different WAF detections
WAF_ALERTS = [
    {'type': 'SQL_INJECTION', 'severity': 'CRITICAL', 'payload': "admin' OR '1'='1"},
    {'type': 'XSS_ATTACK', 'severity': 'HIGH', 'payload': '<script>alert("xss")</script>'},
    {'type': 'PATH_TRAVERSAL', 'severity': 'HIGH', 'payload': '../../etc/passwd'},
    {'type': 'DDOS_DETECTION', 'severity': 'CRITICAL', 'requests_per_sec': 10000},
    {'type': 'BOT_DETECTED', 'severity': 'MEDIUM', 'bot_type': 'crawler'},
]

@app.route('/trigger-alert', methods=['GET'])
def trigger_alert():
    """WAF detects attack and sends to integration"""
    
    alert = random.choice(WAF_ALERTS)
    
    waf_alert = {
        'source_system': 'WAF',
        'alert_id': f'WAF-{random.randint(100000, 999999)}',
        'timestamp': datetime.now().isoformat(),
        'type': alert['type'],
        'severity': alert['severity'],
        'source_ip': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}',
        'target_url': '/api/login',
        'http_method': 'POST',
        'payload': alert.get('payload', ''),
        'action_taken': 'BLOCKED'
    }
    
    # Send to integration service
    response = requests.post(
        f'{INTEGRATION_URL}/webhook/security-alert',
        json=waf_alert
    )
    
    return jsonify({
        'status': 'alert_sent',
        'waf_alert': waf_alert,
        'integration_response': response.json()
    }), 200

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'service': 'waf'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)