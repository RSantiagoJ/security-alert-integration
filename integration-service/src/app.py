from flask import Flask, request, jsonify
import logging
from datetime import datetime
import os
import requests

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SIEM_URL = os.getenv('SIEM_URL', 'http://siem:3000')

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'service': 'security-integration'}), 200

@app.route('/webhook/security-alert', methods=['POST'])
def security_alert():
    """
    Receives alerts from multiple security tools (WAF, IDS, Vuln Scanner).
    Normalizes them to unified format.
    Sends to SIEM for correlation and response.
    """
    try:
        alert_data = request.json
        logger.info(f"[SECURITY] Received alert from {alert_data.get('source_system')}: {alert_data}")
        
        # Normalize to common schema
        normalized_alert = normalize_alert(alert_data)
        logger.info(f"[SECURITY] Normalized alert: {normalized_alert}")
        
        # Enrich with context (could add threat intel, asset info, etc)
        enriched_alert = enrich_alert(normalized_alert)
        logger.info(f"[SECURITY] Enriched alert: {enriched_alert}")
        
        # Send to SIEM
        try:
            siem_response = requests.post(
                f'{SIEM_URL}/api/events/ingest',
                json=enriched_alert,
                timeout=10
            )
            siem_response.raise_for_status()
            
            return jsonify({
                'status': 'success',
                'message': 'Alert normalized and sent to SIEM',
                'event_id': enriched_alert.get('event_id'),
                'siem_reference': siem_response.json().get('reference_id')
            }), 200
        
        except requests.exceptions.RequestException as e:
            logger.error(f"[SECURITY] Failed to reach SIEM: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': 'Failed to send to SIEM',
                'error': str(e)
            }), 503
    
    except Exception as e:
        logger.error(f"[SECURITY] Error processing alert: {str(e)}")
        return jsonify({'error': str(e)}), 500

def normalize_alert(raw_alert):
    """Transform security alert to normalized schema"""
    
    source = raw_alert.get('source_system', 'UNKNOWN')
    
    # Common normalized schema
    normalized = {
        'event_id': f'EVENT-{int(datetime.now().timestamp() * 1000)}',
        'timestamp': raw_alert.get('timestamp', datetime.now().isoformat()),
        'source_system': source,
        'original_alert_id': raw_alert.get('alert_id'),
        'alert_type': get_alert_type(raw_alert),
        'severity': normalize_severity(raw_alert.get('severity', 'MEDIUM')),
        'description': generate_description(raw_alert),
        'affected_asset': get_affected_asset(raw_alert),
        'attacker_info': get_attacker_info(raw_alert),
        'remediation': raw_alert.get('remediation', 'See SIEM for details'),
        'raw_data': raw_alert
    }
    
    return normalized

def normalize_severity(severity):
    """Convert different severity scales to 0-10"""
    
    severity_map = {
        'CRITICAL': 9,
        'HIGH': 7,
        'MEDIUM': 5,
        'LOW': 3,
        'INFO': 1
    }
    
    return severity_map.get(severity, 5)

def get_alert_type(alert):
    """Classify alert type"""
    
    source = alert.get('source_system', '')
    
    if source == 'WAF':
        return alert.get('type', 'WEB_ATTACK')
    elif source == 'VULN_SCANNER':
        return 'VULNERABILITY'
    elif source == 'IDS':
        return 'NETWORK_INTRUSION'
    else:
        return 'SECURITY_EVENT'

def generate_description(alert):
    """Generate human-readable description"""
    
    source = alert.get('source_system', '')
    
    if source == 'WAF':
        return f"{alert.get('type')} detected from {alert.get('source_ip')} targeting {alert.get('target_url')}"
    elif source == 'VULN_SCANNER':
        return f"Vulnerability {alert.get('cve_id')} found on {alert.get('affected_host')}: {alert.get('vulnerability_name')}"
    elif source == 'IDS':
        return f"IDS signature '{alert.get('signature_name')}' triggered between {alert.get('src_ip')} and {alert.get('dst_ip')}"
    else:
        return "Security alert detected"

def get_affected_asset(alert):
    """Extract affected asset/host"""
    
    source = alert.get('source_system', '')
    
    if source == 'WAF':
        return {'type': 'web_service', 'value': alert.get('target_url')}
    elif source == 'VULN_SCANNER':
        return {'type': 'host', 'value': alert.get('affected_host')}
    elif source == 'IDS':
        return {'type': 'host', 'value': alert.get('dst_ip')}
    else:
        return {}

def get_attacker_info(alert):
    """Extract attacker/source information"""
    
    source = alert.get('source_system', '')
    
    if source == 'WAF':
        return {'type': 'ip', 'value': alert.get('source_ip')}
    elif source == 'IDS':
        return {'type': 'ip', 'value': alert.get('src_ip')}
    else:
        return {}

def enrich_alert(alert):
    """Add enrichment data (threat intel, asset context, etc)"""
    
    alert['enrichment'] = {
        'threat_level': 'CRITICAL' if alert['severity'] >= 8 else 'HIGH' if alert['severity'] >= 6 else 'MEDIUM',
        'requires_response': alert['severity'] >= 7,
        'response_priority': 1 if alert['severity'] >= 9 else 2 if alert['severity'] >= 7 else 3,
        'enriched_at': datetime.now().isoformat()
    }
    
    return alert

if __name__ == '__main__':
    port = int(os.getenv('PORT', 8000))
    app.run(host='0.0.0.0', port=port)