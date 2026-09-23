from flask import Flask, request, jsonify
from datetime import datetime
import uuid

app = Flask(__name__)

# Store security events
security_events = []
correlations = []

@app.route('/api/events/ingest', methods=['POST'])
def ingest_event():
    """Receive normalized security events from integration"""
    
    event = request.json
    reference_id = f'SIEM-{uuid.uuid4().hex[:8]}'
    
    # Store event
    security_events.append({
        'reference_id': reference_id,
        'event': event,
        'ingested_at': datetime.now().isoformat()
    })
    
    # Run correlations
    check_correlations(event)
    
    return jsonify({
        'status': 'recorded',
        'reference_id': reference_id,
        'message': f'Event ingested: {event.get("alert_type")}',
        'event_count': len(security_events)
    }), 200

def check_correlations(new_event):
    """Check if events correlate (attack chain detection)"""
    
    # Simple correlation: multiple events from same source IP
    attacker = new_event.get('attacker_info', {}).get('value')
    
    if attacker:
        related_events = [
            e for e in security_events 
            if e['event'].get('attacker_info', {}).get('value') == attacker
        ]
        
        if len(related_events) >= 3:
            correlation = {
                'correlation_id': f'CORR-{uuid.uuid4().hex[:8]}',
                'type': 'COORDINATED_ATTACK',
                'attacker': attacker,
                'event_count': len(related_events),
                'severity': 'CRITICAL',
                'timestamp': datetime.now().isoformat()
            }
            correlations.append(correlation)
            print(f"[SIEM] Correlation detected: {correlation}")

@app.route('/api/events', methods=['GET'])
def get_events():
    """View all security events"""
    return jsonify({
        'total_events': len(security_events),
        'events': security_events,
        'correlations': correlations
    }), 200

@app.route('/api/dashboard', methods=['GET'])
def dashboard():
    """Security dashboard summary"""
    
    critical_count = sum(1 for e in security_events if e['event'].get('severity', 0) >= 8)
    high_count = sum(1 for e in security_events if 6 <= e['event'].get('severity', 0) < 8)
    attack_chains = len(correlations)
    
    return jsonify({
        'dashboard': {
            'total_events': len(security_events),
            'critical_events': critical_count,
            'high_events': high_count,
            'attack_chains': attack_chains,
            'last_event': security_events[-1]['ingested_at'] if security_events else None,
            'requires_response': critical_count > 0 or attack_chains > 0
        }
    }), 200

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'service': 'siem'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000)