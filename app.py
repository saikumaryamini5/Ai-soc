import json
import os
import random
import datetime
from flask import Flask, render_template, jsonify, request, session, redirect, url_for, send_file
from flask_cors import CORS
from fpdf import FPDF
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# Crucial for session management:
app.secret_key = 'super_secret_cyber_soc_key_123' 
CORS(app)

DATASET_PATH = os.path.join(os.path.dirname(__file__), 'datasets', 'logs.json')
USERS_PATH = os.path.join(os.path.dirname(__file__), 'datasets', 'users.json')

# Global state to simulate 'blocked' IPs for the live session
BLOCKED_IPS = set()

def load_logs():
    try:
        with open(DATASET_PATH, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading logs: {e}")
        return []

def load_users():
    if not os.path.exists(USERS_PATH):
        return {}
    try:
        with open(USERS_PATH, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_users(users):
    os.makedirs(os.path.dirname(USERS_PATH), exist_ok=True)
    with open(USERS_PATH, 'w') as f:
        json.dump(users, f, indent=4)

# Custom decorator for login required
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --------------
# HTML ROUTES
# --------------

@app.route('/')
def index():
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        users = load_users()
        
        # Check against users.json database
        if username in users and check_password_hash(users[username]['password'], password):
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid username or password")
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not username or not password or not confirm_password:
            return render_template('register.html', error="All fields are required")
            
        if password != confirm_password:
            return render_template('register.html', error="Passwords do not match")
            
        users = load_users()
        if username in users:
            return render_template('register.html', error="Username already exists")
            
        users[username] = {
            "password": generate_password_hash(password)
        }
        save_users(users)
        
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('index.html')


# --------------
# API ROUTES
# --------------

@app.route('/api/logs', methods=['GET'])
@login_required
def api_logs():
    logs = load_logs()
    return jsonify(logs)

@app.route('/api/search', methods=['GET'])
@login_required
def api_search():
    ip = request.args.get('ip', '').strip()
    logs = load_logs()
    
    if not ip:
        return jsonify([])
        
    # Find logs where source_ip or destination_ip matches
    results = [log for log in logs if ip in log.get('source_ip', '') or ip in log.get('destination_ip', '')]
    return jsonify(results)

@app.route('/api/alerts', methods=['GET'])
@login_required
def api_alerts():
    logs = load_logs()
    alerts = [log for log in logs if log.get('severity') in ['high', 'critical']]
    return jsonify(alerts)

@app.route('/api/stats', methods=['GET'])
@login_required
def api_stats():
    logs = load_logs()
    
    alerts_count = sum(1 for log in logs if log.get('severity') in ['high', 'critical'])
    incidents_count = len(logs)
    blocked_count = len(BLOCKED_IPS)
    
    # Generate some fake chart data points (Network Traffic and Alerts over time)
    traffic_data = [random.randint(50, 250) for _ in range(12)]
    alert_trend = [random.randint(0, 15) for _ in range(12)]
    
    labels = []
    now = datetime.datetime.now()
    for i in range(11, -1, -1):
        t = now - datetime.timedelta(minutes=5 * i)
        labels.append(t.strftime("%H:%M"))
    
    return jsonify({
        "alerts": alerts_count,
        "incidents": incidents_count,
        "blocked_ips": blocked_count,
        "chart_data": {
            "labels": labels,
            "traffic": traffic_data,
            "alerts_trend": alert_trend
        }
    })

@app.route('/api/block-ip', methods=['POST'])
@login_required
def block_ip():
    data = request.json
    ip_to_block = data.get('ip')
    
    if not ip_to_block:
        return jsonify({"success": False, "message": "No IP provided"}), 400
        
    BLOCKED_IPS.add(ip_to_block)
    return jsonify({"success": True, "message": f"IP {ip_to_block} blocked successfully"})

@app.route('/api/analyze-log', methods=['POST'])
@login_required
def analyze_log():
    data = request.json
    raw_log = data.get('log', '').lower()
    
    if not raw_log:
        return jsonify({"success": False, "error": "No log provided"}), 400
        
    risk_factor = "Low"
    score = 10
    findings = []
    
    if "failed login" in raw_log or "incorrect password" in raw_log or "invalid user" in raw_log:
        risk_factor = "Medium"
        score += 30
        findings.append("Detected authentication failure pattern.")
        
    if "sql" in raw_log or "select * from" in raw_log or "union" in raw_log or "1=1" in raw_log:
        risk_factor = "Critical"
        score += 80
        findings.append("Possible SQL Injection attempt detected.")
        
    if "exe" in raw_log or "malware" in raw_log or "virus" in raw_log or "payload" in raw_log:
        risk_factor = "High"
        score += 60
        findings.append("Suspicious payload or executable file signature mentioned.")
        
    if score > 80: risk_factor = "Critical"
    elif score > 50: risk_factor = "High"
    elif score > 20: risk_factor = "Medium"
        
    return jsonify({
        "success": True,
        "risk_factor": risk_factor,
        "risk_score": min(score, 100),
        "findings": findings,
        "analysis_time": datetime.datetime.now().isoformat()
    })

# --------------
# EXPORT PDF
# --------------
@app.route('/export/pdf', methods=['GET'])
@login_required
def export_pdf():
    logs = load_logs()
    
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=10)
    
    pdf.cell(200, 10, txt="SOC Analyst Dashboard - Event Logs Report", ln=1, align='C')
    pdf.cell(200, 10, txt=f"Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=1, align='C')
    pdf.ln(10)
    
    # Header
    pdf.set_font("Arial", 'B', 9)
    # Col widths: 30, 25, 25, 60, 25, 25 = 190
    pdf.cell(35, 8, "Timestamp", border=1)
    pdf.cell(30, 8, "Source IP", border=1)
    pdf.cell(30, 8, "Destination IP", border=1)
    pdf.cell(50, 8, "Event Type", border=1)
    pdf.cell(20, 8, "Severity", border=1)
    pdf.cell(25, 8, "Status", border=1)
    pdf.ln()
    
    pdf.set_font("Arial", size=8)
    
    for log in logs:
        # Format time nicely
        try:
            dt = datetime.datetime.strptime(log.get('timestamp', ''), "%Y-%m-%dT%H:%M:%SZ")
            time_str = dt.strftime("%Y-%m-%d %H:%M")
        except:
            time_str = log.get('timestamp', '')[:16]
            
        pdf.cell(35, 6, time_str, border=1)
        pdf.cell(30, 6, log.get('source_ip', ''), border=1)
        pdf.cell(30, 6, log.get('destination_ip', ''), border=1)
        pdf.cell(50, 6, log.get('event_type', ''), border=1)
        pdf.cell(20, 6, log.get('severity', ''), border=1)
        pdf.cell(25, 6, log.get('status', ''), border=1)
        pdf.ln()

    # Save to temp file
    pdf_filename = "SOC_Logs_Report.pdf"
    pdf_path = os.path.join(os.path.dirname(__file__), pdf_filename)
    pdf.output(pdf_path)
    
    return send_file(pdf_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
