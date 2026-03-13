import json
import os
import random
from flask import Flask, render_template, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

DATASET_PATH = os.path.join(os.path.dirname(__file__), 'datasets', 'logs.json')

def load_logs():
    try:
        with open(DATASET_PATH, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading logs: {e}")
        return []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/logs')
def api_logs():
    logs = load_logs()
    
    # Simulate dynamic logs for realism
    if random.random() > 0.6:
        new_log = {
            "id": random.randint(1000, 9999),
            "timestamp": "2026-03-13T10:15:00Z", # just a sample timestamp
            "source_ip": f"192.168.1.{random.randint(2, 254)}",
            "destination_ip": "10.0.0.1",
            "event_type": "Connection Attempt",
            "severity": random.choice(["low", "medium", "high", "critical"]),
            "status": random.choice(["allowed", "blocked", "flagged"])
        }
        logs.insert(0, new_log)
    
    return jsonify(logs[:50])

@app.route('/api/stats')
def api_stats():
    logs = load_logs()
    total_events = len(logs) + random.randint(100, 1000)
    critical_alerts = sum(1 for log in logs if log.get('severity') in ['high', 'critical'])
    active_threats = random.randint(1, 15)
    resolved_threats = random.randint(50, 200)
    
    return jsonify({
        "total_events": total_events,
        "critical_alerts": critical_alerts,
        "active_threats": active_threats,
        "resolved_threats": resolved_threats
    })

@app.route('/api/alerts')
def api_alerts():
    logs = load_logs()
    alerts = [log for log in logs if log.get('severity') in ['high', 'critical']]
    return jsonify(alerts)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
