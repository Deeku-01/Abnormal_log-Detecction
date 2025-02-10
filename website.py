from flask import Flask, request, jsonify, render_template, session, redirect, url_for
import logging
import json
from datetime import datetime
import random
import time
from functools import wraps

app = Flask(__name__)

# Setup logging
# Remove the basicConfig setup since we'll use our own handler
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Initialize the log file with proper JSON structure
with open('website_logs.json', 'w') as f:
    json.dump({"logs": []}, f, indent=2)

# Create a custom handler to maintain JSON structure
class JSONFileHandler(logging.FileHandler):
    def __init__(self, filename):
        super().__init__(filename, mode='r+')
    
    def emit(self, record):
        try:
            with open(self.baseFilename, 'r+') as f:
                data = json.load(f)
                data['logs'].append(json.loads(record.getMessage()))
                f.seek(0)
                json.dump(data, f, indent=2)
                f.truncate()
        except Exception:
            self.handleError(record)

# Set up the logger with only our custom handler
logger.handlers = []
logger.addHandler(JSONFileHandler('website_logs.json'))
logger.propagate = False  # Prevent logging propagation to parent handlers

# Simulated user database
users = {
    "user1": "password123",
    "user2": "password456",
    "admin": "adminpass"
}

# Track login attempts
login_attempts = {}

# Add session configuration
app.secret_key = 'your-secret-key-here'  # Change this to a secure secret key
active_sessions = {}

# Add this global variable at the top with other imports
test_traffic_enabled = True

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = session.get('user')
        if user is None:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return render_template('index.html')

def get_client_ip():
    """Get the real IP address of the client"""
    if request.headers.get('X-Test-Traffic'):
        # This is test traffic, use the X-Forwarded-For header
        return request.headers.get('X-Forwarded-For', 'unknown')
    # This is real traffic, use the actual remote address
    return request.remote_addr

def log_event(event_type, user, status, details=None):
    """
    Centralized logging function for the website
    """
    try:
        with open('website_logs.json', 'r+') as f:
            data = json.load(f)
            
            # Get the appropriate IP address and mark the traffic source
            ip_address = get_client_ip()
            is_test_traffic = bool(request.headers.get('X-Test-Traffic'))
            
            log_entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "event_type": event_type,
                "user": user,
                "source_ip": ip_address,
                "traffic_type": "test" if is_test_traffic else "real",
                "status": status,
                "response_time": random.uniform(0.1, 0.5),
                "attempts": login_attempts.get(ip_address, {}).get('count', 1)
            }
            
            if details:
                log_entry.update(details)
            
            data['logs'].append(log_entry)
            
            # Reset file pointer and write updated data
            f.seek(0)
            json.dump(data, f, indent=2)
            f.truncate()
            
    except Exception as e:
        print(f"Error logging event: {e}")

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # Track login attempts
    if request.remote_addr not in login_attempts:
        login_attempts[request.remote_addr] = {'count': 0, 'last_attempt': datetime.now()}
    
    login_attempts[request.remote_addr]['count'] += 1
    login_attempts[request.remote_addr]['last_attempt'] = datetime.now()
    
    # Check credentials
    if username in users and users[username] == password:
        status = "success"
        session['user'] = username
    else:
        status = "failed"
    
    log_event(
        event_type="login",
        user=username,
        status=status,
        details={
            "attempts": login_attempts[request.remote_addr]['count'],
            "is_known_user": username in users
        }
    )
    
    if status == "success":
        return jsonify({"status": "success"})
    else:
        return jsonify({"status": "failed"}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('user', None)
    return jsonify({"status": "success"})

@app.route('/api/data', methods=['GET'])
@login_required
def get_data():
    # Simulate different response times
    if random.random() < 0.1:  # 10% chance of slow response
        time.sleep(2)
    
    log_event(
        event_type="data_access",
        user=session['user'],
        status="success",
        details={
            "response_time": random.uniform(0.1, 0.5)
        }
    )
    return jsonify({"data": "Some data"})

@app.route('/api/admin', methods=['POST'])
@login_required
def admin_action():
    if session['user'] != "admin":
        log_event(
            event_type="admin_action",
            user=session['user'],
            status="unauthorized"
        )
        return jsonify({"status": "unauthorized"}), 403
        
    data = request.get_json()
    action = data.get('action')
    
    log_event(
        event_type="admin_action",
        user=session['user'],
        status="success",
        details={"action": action}
    )
    return jsonify({"status": "success"})

@app.route('/api/stop_test_traffic', methods=['POST'])
def stop_test_traffic():
    global test_traffic_enabled
    test_traffic_enabled = False
    print("\n" + "="*50)
    print("Stopping test traffic generator...")
    print("="*50 + "\n")
    return jsonify({"status": "success", "message": "Test traffic generator stopped"})

@app.route('/api/test_traffic_status')
def test_traffic_status():
    global test_traffic_enabled
    return jsonify({"enabled": test_traffic_enabled})

if __name__ == '__main__':
    # Initialize the log file with proper JSON structure
    with open('website_logs.json', 'w') as f:
        json.dump({"logs": []}, f, indent=2)
    app.run(host='127.0.0.1', port=5000, debug=False) 