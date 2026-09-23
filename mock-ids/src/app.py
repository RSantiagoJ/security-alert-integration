from flask import Flask, jsonify
import requests
import random
from datetime import datetime
import os

app = Flask(__name__)
INTEGRATION_URL = os.getenv('INTEGRATION_URL', 'http://integration:8000')

# Simulate IDS detections
IDS_SIGNATURES = [
    {'name': 'Suspicious Port Scan', 'protocol': 'TCP', 'action': 'ALERT'},
    {'name': 'Known Malware Traffic', 'protocol': 'TLS', 'action': 'DROP'},
    {'name': 'Reverse Shell Detected', 'protocol': 'TCP', 'action': 'DROP'},
    {'name': 'Lateral Movement Attempt', 'protocol': 'SMB', 'action': 'ALERT'},
    {'name': 'Exfiltration Pattern', 'protocol': 'HTTPS', 'action': 'ALERT'},
]

@app.route('/trigger-detection', methods=['GET'])
def trigger_detection():
    """IDS detects suspicious activity"""
    
    sig = random.choice(IDS_SIGNATURES)
    
    ids_alert = {
        'source_system': 'IDS',
        'alert_id': f'IDS-{random.randint(100000, 999999)}',
        'timestamp': datetime.now().isoformat(),
        'signature_name': sig['name'],
        'protocol': sig['protocol'],
        'src_ip': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}',
        'dst_ip': '10.0.1.50',  # Internal server
        'src_port': random.randint(10000, 65535),
        'dst_port': random.choice([22, 3306, 5432, 445]),
        'packets_count': random.randint(10, 1000),
        'bytes_transferred': random.randint(1000, 1000000),
        'action': sig['action'],
        'severity': 'CRITICAL' if sig['action'] == 'DROP' else 'HIGH'
    }
    
    # Send to integration
    response = requests.post(
        f'{INTEGRATION_URL}/webhook/security-alert',
        json=ids_alert
    )
    
    return jsonify({
        'status': 'alert_sent',
        'ids_alert': ids_alert,
        'integration_response': response.json()
    }), 200

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'service': 'ids'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002)