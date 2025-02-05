from flask import Flask, jsonify, render_template, request, session
import random
import time
from datetime import datetime
import queue
import threading
from request_simulator import RequestSimulator
import signal
import sys
from werkzeug.serving import make_server
import os
import atexit

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Required for sessions

# Queue to store recent requests for display
request_log = queue.Queue(maxsize=100)

# Create a shared request simulator instance
request_simulator = RequestSimulator()

# HTML template with improved UI
DASHBOARD_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>API Monitor Dashboard</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        .header {
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .nav-links {
            margin-bottom: 20px;
        }
        .nav-links a {
            color: #2c3e50;
            text-decoration: none;
            margin-right: 20px;
            padding: 5px 10px;
            border-radius: 4px;
            background-color: #ecf0f1;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .endpoint-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .endpoint-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .logs-container {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .log-entry {
            padding: 10px;
            border-bottom: 1px solid #eee;
            font-family: monospace;
        }
        .status-200 { color: #27ae60; }
        .status-300 { color: #2980b9; }
        .status-400 { color: #f39c12; }
        .status-500 { color: #c0392b; }
        .method-GET { background-color: #2ecc71; }
        .method-POST { background-color: #3498db; }
        .method-DELETE { background-color: #e74c3c; }
        .method-tag {
            padding: 2px 6px;
            border-radius: 4px;
            color: white;
            font-size: 12px;
            margin-right: 5px;
        }
        .payload-data {
            background-color: #f8f9fa;
            padding: 8px;
            border-radius: 4px;
            margin-top: 5px;
            font-size: 12px;
        }
        .refresh-button {
            background-color: #2c3e50;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
            margin-bottom: 20px;
        }
        .refresh-button:hover {
            background-color: #34495e;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>API Monitor Dashboard</h1>
            <p>Real-time monitoring of API endpoints and traffic</p>
        </div>

        <div class="nav-links">
            <a href="/">Main Dashboard</a>
            <a href="/security">Security Monitor</a>
        </div>

        <button class="refresh-button" onclick="location.reload()">Refresh Dashboard</button>

        <div class="stats-grid">
            <div class="stat-card">
                <h3>Active Sessions</h3>
                <p>{{ active_sessions }} current sessions</p>
            </div>
            <div class="stat-card">
                <h3>Total Requests</h3>
                <p>{{ total_requests }} requests processed</p>
            </div>
            <div class="stat-card">
                <h3>Error Rate</h3>
                <p>{{ error_rate }}% error rate</p>
            </div>
        </div>

        <h2>Endpoint Status</h2>
        <div class="endpoint-grid">
            {% for endpoint in endpoints %}
            <div class="endpoint-card">
                <h3>{{ endpoint['path'] }}</h3>
                <p>Methods: {{ endpoint['methods']|join(', ') }}</p>
                <p>Status: <span class="status-{{ endpoint['last_status'] }}">{{ endpoint['last_status'] }}</span></p>
                <p>Response Time: {{ endpoint['last_response_time'] }}ms</p>
                <p>Success Rate: {{ endpoint['success_rate'] }}%</p>
            </div>
            {% endfor %}
        </div>

        <h2>Recent Requests</h2>
        <div class="logs-container">
            {% for log in logs %}
            <div class="log-entry">
                <span class="method-tag method-{{ log['method'] }}">{{ log['method'] }}</span>
                <span class="status-{{ log['status_code'] }}">
                    [{{ log['timestamp'] }}] {{ log['endpoint'] }} - Status: {{ log['status_code'] }}
                    ({{ log['response_time'] }}ms)
                </span>
                {% if log['payload'] %}
                <div class="payload-data">
                    Payload: {{ log['payload']|tojson }}
                </div>
                {% endif %}
            </div>
            {% endfor %}
        </div>
    </div>

    <script>
        // Auto-refresh every 5 seconds
        setTimeout(function() {
            location.reload();
        }, 5000);
    </script>
</body>
</html>
'''

# Store endpoint states
endpoints = [
    {'path': '/api/users', 'methods': ['GET', 'POST'], 'last_status': 200, 'last_response_time': 0},
    {'path': '/api/products', 'methods': ['GET', 'POST'], 'last_status': 200, 'last_response_time': 0},
    {'path': '/api/orders', 'methods': ['GET', 'POST'], 'last_status': 200, 'last_response_time': 0},
    {'path': '/api/auth', 'methods': ['GET', 'POST'], 'last_status': 200, 'last_response_time': 0},
    {'path': '/api/cart', 'methods': ['GET', 'POST'], 'last_status': 200, 'last_response_time': 0}
]

# Simulate a simple database
db = {
    'users': {},
    'products': {
        1: {'name': 'Laptop', 'price': 999.99, 'stock': 10},
        2: {'name': 'Phone', 'price': 599.99, 'stock': 5}
    },
    'carts': {},
    'orders': {}
}

# Track endpoint statistics
endpoint_stats = {
    '/api/users': {'requests': 0, 'errors': 0},
    '/api/products': {'requests': 0, 'errors': 0},
    '/api/orders': {'requests': 0, 'errors': 0},
    '/api/auth': {'requests': 0, 'errors': 0},
    '/api/cart': {'requests': 0, 'errors': 0}
}

class SessionManager:
    def __init__(self):
        self._sessions = {}
        self._lock = threading.Lock()

    def add_session(self, session_id, data):
        with self._lock:
            self._sessions[session_id] = {
                'data': data,
                'last_activity': datetime.now()
            }

    def remove_session(self, session_id):
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]

    def get_active_count(self):
        with self._lock:
            return len(self._sessions)

    def cleanup_old_sessions(self):
        with self._lock:
            current_time = datetime.now()
            to_remove = []
            for session_id, session_data in self._sessions.items():
                if (current_time - session_data['last_activity']).total_seconds() > 1800:  # 30 minutes
                    to_remove.append(session_id)
            
            for session_id in to_remove:
                del self._sessions[session_id]

session_manager = SessionManager()

def update_endpoint_stats(endpoint, status_code):
    if endpoint in endpoint_stats:
        endpoint_stats[endpoint]['requests'] += 1
        if status_code >= 400:
            endpoint_stats[endpoint]['errors'] += 1

def calculate_success_rate(endpoint):
    stats = endpoint_stats[endpoint]
    if stats['requests'] == 0:
        return 100
    return round(((stats['requests'] - stats['errors']) / stats['requests']) * 100, 1)

def update_endpoint_status(endpoint_path, status_code, response_time):
    for endpoint in endpoints:
        if endpoint['path'] == endpoint_path:
            endpoint['last_status'] = status_code
            endpoint['last_response_time'] = round(response_time, 2)
            break

def log_request(endpoint, method, status_code, response_time, payload=None):
    # Get IP from request headers or use simulated IP
    ip = request.headers.get('X-Simulated-IP', request.remote_addr)
    
    log_entry = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'endpoint': endpoint,
        'method': method,
        'status_code': status_code,
        'response_time': round(response_time, 2),
        'payload': payload,
        'ip_address': ip
    }
    
    if request_log.full():
        request_log.get()
    request_log.put(log_entry)
    
    update_endpoint_stats(endpoint, status_code)

@app.route('/')
def dashboard():
    # Calculate statistics
    total_requests = sum(stats['requests'] for stats in endpoint_stats.values())
    total_errors = sum(stats['errors'] for stats in endpoint_stats.values())
    error_rate = round((total_errors / total_requests * 100) if total_requests > 0 else 0, 1)
    
    # Update success rates in endpoints list
    for endpoint in endpoints:
        endpoint['success_rate'] = calculate_success_rate(endpoint['path'])

    # Convert queue to list for template rendering
    logs = list(request_log.queue)
    logs.reverse()

    # Get active sessions count
    active_sessions = session_manager.get_active_count()

    return render_template('dashboard.html',
        endpoints=endpoints,
        logs=logs,
        active_sessions=active_sessions,
        total_requests=total_requests,
        error_rate=error_rate
    )

@app.route('/api/users', methods=['GET', 'POST'])
def users():
    start_time = time.time()
    time.sleep(random.uniform(0.1, 0.5))
    
    # Increase error probability
    status_code = random.choice([200, 200, 200, 400, 401, 403, 500, 503])
    response_time = (time.time() - start_time) * 1000
    
    # Occasionally generate very slow responses
    if random.random() < 0.1:  # 10% chance
        time.sleep(random.uniform(1, 3))
    
    update_endpoint_status('/api/users', status_code, response_time)
    log_request('/api/users', request.method, status_code, response_time)
    
    return jsonify({"message": "Users endpoint"}), status_code

class SystemLoadSimulator:
    def __init__(self):
        self.base_load = 0.3  # 30% base load
        self.peak_hours = range(9, 18)  # 9 AM to 5 PM
        self.peak_load_factor = 2.5
        self.current_load = self.base_load

    def get_current_load(self):
        hour = datetime.now().hour
        is_peak = hour in self.peak_hours
        day_load = self.base_load * (self.peak_load_factor if is_peak else 1.0)
        
        # Add random fluctuation
        noise = random.uniform(-0.1, 0.1)
        self.current_load = min(1.0, max(0.1, day_load + noise))
        return self.current_load

system_load = SystemLoadSimulator()

@app.route('/api/products', methods=['GET', 'POST'])
def products():
    start_time = time.time()
    
    # Apply system load to response time
    load_factor = system_load.get_current_load()
    time.sleep(random.uniform(0.1, 0.5) * load_factor)
    
    if request.method == 'POST':
        if not session.get('authenticated'):
            status_code = 401
        else:
            data = request.get_json()
            if not data or 'name' not in data or 'price' not in data or 'stock' not in data:
                status_code = 400
            elif data['price'] < 0 or data['stock'] < 0:
                status_code = 400
            else:
                status_code = 201
    else:
        status_code = 200
    
    response_time = (time.time() - start_time) * 1000
    
    update_endpoint_status('/api/products', status_code, response_time)
    log_request('/api/products', request.method, status_code, response_time)
    
    return jsonify({'products': list(db['products'].values())}), status_code

@app.route('/api/orders', methods=['GET', 'POST'])
def orders():
    start_time = time.time()
    time.sleep(random.uniform(0.1, 0.5))
    status_code = random.choice([200, 200, 200, 401, 500])
    response_time = (time.time() - start_time) * 1000
    
    update_endpoint_status('/api/orders', status_code, response_time)
    log_request('/api/orders', request.method, status_code, response_time)
    
    return jsonify({"message": "Orders endpoint"}), status_code

@app.route('/api/auth', methods=['POST'])
def auth():
    start_time = time.time()
    data = request.get_json()
    
    if not data or 'username' not in data or 'password' not in data:
        time.sleep(random.uniform(0.1, 0.3))
        return jsonify({'error': 'Invalid request'}), 400
    
    # Simulate authentication
    if data['username'] == 'user1' and data['password'] == 'pass123':
        session_id = str(random.randint(1000, 9999))  # Simple session ID
        session_manager.add_session(session_id, {
            'username': data['username'],
            'authenticated': True
        })
        status_code = 200
    else:
        status_code = 401
    
    response_time = (time.time() - start_time) * 1000
    update_endpoint_status('/api/auth', status_code, response_time)
    log_request('/api/auth', request.method, status_code, response_time, data)
    
    return jsonify({'status': 'success' if status_code == 200 else 'failed'}), status_code

@app.route('/api/cart', methods=['GET', 'POST'])
def cart():
    start_time = time.time()
    time.sleep(random.uniform(0.1, 0.5))
    status_code = random.choice([200, 200, 200, 404, 500])
    response_time = (time.time() - start_time) * 1000
    
    update_endpoint_status('/api/cart', status_code, response_time)
    log_request('/api/cart', request.method, status_code, response_time)
    
    return jsonify({"message": "Cart endpoint"}), status_code

# Add a cleanup function to remove expired sessions
def cleanup_sessions():
    cleanup_thread.running = True  # Add this flag
    while cleanup_thread.running:  # Use the flag instead of True
        try:
            time.sleep(60)  # Check every minute
            session_manager.cleanup_old_sessions()
        except:
            break

# Start the cleanup thread
cleanup_thread = threading.Thread(target=cleanup_sessions, daemon=True)
cleanup_thread.running = True  # Add this flag
cleanup_thread.start()

class AutomatedResponse:
    def __init__(self, simulator):
        self.blocked_ips = {}
        self.rate_limits = {}
        self.suspicious_sessions = {}
        self.lock = threading.Lock()
        self.simulator = simulator  # Store reference to simulator

    def check_and_block(self, ip, endpoint, method, status_code):
        with self.lock:
            current_time = datetime.now()
            
            # Get IP activity from simulator
            ip_activity = self.simulator.ip_activity.get(ip, {})
            
            # Initialize rate limiting
            if ip not in self.rate_limits:
                self.rate_limits[ip] = {
                    'count': 0,
                    'first_request': current_time,
                    'warnings': 0,
                    'last_activity': current_time,
                    'pattern_type': ip_activity.get('pattern_type', 'unknown')
                }
            
            # Update request count and last activity
            self.rate_limits[ip]['count'] += 1
            self.rate_limits[ip]['last_activity'] = current_time
            
            time_window = (current_time - self.rate_limits[ip]['first_request']).total_seconds()
            request_rate = self.rate_limits[ip]['count'] / time_window if time_window > 0 else 0
            
            is_blocked = False
            response_headers = {}
            
            # Rate limiting
            if request_rate > 100:
                self.blocked_ips[ip] = {
                    'timestamp': current_time,
                    'reason': 'Rate limit exceeded',
                    'request_rate': request_rate
                }
                is_blocked = True
                response_headers['X-RateLimit-Exceeded'] = 'True'
            
            # Suspicious auth attempts
            if endpoint == '/api/auth' and status_code == 401:
                self.rate_limits[ip]['warnings'] += 1
                if self.rate_limits[ip]['warnings'] >= 5:
                    self.blocked_ips[ip] = {
                        'timestamp': current_time,
                        'reason': 'Multiple failed auth attempts',
                        'warning_count': self.rate_limits[ip]['warnings']
                    }
                    is_blocked = True
                    response_headers['X-Auth-Blocked'] = 'True'
            
            return is_blocked, response_headers

# Initialize automated response with simulator
automated_response = AutomatedResponse(request_simulator)

@app.before_request
def check_automated_response():
    # Get IP from request headers or use simulated IP
    ip = request.headers.get('X-Simulated-IP', request.remote_addr)
    is_blocked, headers = automated_response.check_and_block(
        ip, 
        request.path, 
        request.method, 
        200
    )
    
    if is_blocked:
        return jsonify({
            'error': 'Request blocked due to suspicious activity'
        }), 429, headers

# Add this after the existing DASHBOARD_HTML template
SECURITY_DASHBOARD_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Security Monitor</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        .header {
            background-color: #c0392b;
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .nav-links {
            margin-bottom: 20px;
        }
        .nav-links a {
            color: #2c3e50;
            text-decoration: none;
            margin-right: 20px;
            padding: 5px 10px;
            border-radius: 4px;
            background-color: #ecf0f1;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .blocked-ips {
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .ip-entry {
            padding: 10px;
            border-bottom: 1px solid #eee;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .warning {
            color: #e74c3c;
        }
        .refresh-button {
            background-color: #c0392b;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
            margin-bottom: 20px;
        }
        .rate-limits {
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Monitor Dashboard</h1>
            <p>Real-time security monitoring and automated responses</p>
        </div>

        <div class="nav-links">
            <a href="/">Main Dashboard</a>
            <a href="/security">Security Monitor</a>
        </div>

        <button class="refresh-button" onclick="location.reload()">Refresh Dashboard</button>

        <div class="stats-grid">
            <div class="stat-card">
                <h3>Blocked IPs</h3>
                <p>{{ blocked_ips|length }} IPs currently blocked</p>
            </div>
            <div class="stat-card">
                <h3>Rate Limited Requests</h3>
                <p>{{ rate_limited_count }} requests rate limited</p>
            </div>
            <div class="stat-card">
                <h3>Suspicious Auth Attempts</h3>
                <p>{{ suspicious_auth_count }} suspicious attempts detected</p>
            </div>
        </div>

        <h2>Currently Blocked IPs</h2>
        <div class="blocked-ips">
            {% for ip, details in blocked_ips.items() %}
            <div class="ip-entry">
                <div>
                    <strong>{{ ip }}</strong>
                    <span class="warning">(Blocked at: {{ details.blocked_at }})</span>
                </div>
                <div>
                    Reason: {{ details.reason }}
                </div>
            </div>
            {% endfor %}
        </div>

        <h2>Active Rate Limits</h2>
        <div class="rate-limits">
            {% for ip, limits in rate_limits.items() %}
            <div class="ip-entry">
                <div>
                    <strong>{{ ip }}</strong>
                    <span>(Requests: {{ limits.count }})</span>
                </div>
                <div>
                    Warnings: {{ limits.warnings }}
                </div>
            </div>
            {% endfor %}
        </div>
    </div>

    <script>
        // Auto-refresh every 5 seconds
        setTimeout(function() {
            location.reload();
        }, 5000);
    </script>
</body>
</html>
'''

# Add this new route
@app.route('/security')
def security_dashboard():
    # Get security statistics
    blocked_ips_details = {}
    for ip, block_info in automated_response.blocked_ips.items():
        # Calculate risk level based on activity
        ip_activity = request_simulator.ip_activity.get(ip, {})
        error_rate = (ip_activity.get('error_count', 0) / ip_activity.get('request_count', 1)) * 100
        
        risk_level = 'high' if error_rate > 50 else 'medium' if error_rate > 20 else 'low'
        
        blocked_ips_details[ip] = {
            'blocked_at': block_info['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
            'reason': block_info['reason'],
            'risk_level': risk_level,
            'request_count': ip_activity.get('request_count', 0),
            'error_rate': round(error_rate, 1),
            'pattern_type': ip_activity.get('pattern_type', 'unknown')
        }
    
    # Count risk levels
    high_risk_count = sum(1 for details in blocked_ips_details.values() if details['risk_level'] == 'high')
    medium_risk_count = sum(1 for details in blocked_ips_details.values() if details['risk_level'] == 'medium')
    
    # Process rate limits
    current_time = datetime.now()
    rate_limits_processed = {}
    for ip, data in automated_response.rate_limits.items():
        time_window = (current_time - data['first_request']).total_seconds()
        request_rate = data['count'] / time_window if time_window > 0 else 0
        last_activity_ago = (current_time - data['last_activity']).total_seconds()
        
        rate_limits_processed[ip] = {
            'count': data['count'],
            'warnings': data['warnings'],
            'request_rate': request_rate,
            'last_activity_ago': f"{int(last_activity_ago)}s ago"
        }
    
    # Get recent security events
    security_events = []
    # Add your security events processing here
    
    return render_template('security.html',
        blocked_ips=blocked_ips_details,
        rate_limits=rate_limits_processed,
        high_risk_count=high_risk_count,
        medium_risk_count=medium_risk_count,
        rate_limited_count=len(rate_limits_processed),
        recent_rate_limits=sum(1 for data in rate_limits_processed.values() if float(data['last_activity_ago'].split('s')[0]) < 300),
        suspicious_auth_count=sum(data['warnings'] for data in automated_response.rate_limits.values()),
        failed_login_count=sum(1 for ip, data in automated_response.rate_limits.items() if data['warnings'] > 0),
        security_events=security_events
    )

# Replace the @app.before_first_request decorator with a new function
def init_app(app):
    with app.app_context():
        # Start the request simulator
        request_simulator.start(lambda x: None)

class FlaskServer:
    def __init__(self, app, host='localhost', port=5000):
        self.server = make_server(host, port, app)
        self.ctx = app.app_context()
        self.ctx.push()
        self.server_thread = threading.Thread(target=self.server.serve_forever)
    
    def start(self):
        self.server_thread.start()
    
    def stop(self):
        self.server.shutdown()
        self.server_thread.join()
        self.ctx.pop()

def shutdown_server():
    print("\nInitiating shutdown sequence...")
    try:
        # Stop the request simulator first
        if request_simulator:
            print("Stopping request simulator...")
            request_simulator.stop()
        
        # Stop the cleanup thread
        if cleanup_thread and cleanup_thread.is_alive():
            print("Stopping cleanup thread...")
            cleanup_thread.running = False
            cleanup_thread.join(timeout=3)
        
        # Stop the Flask server
        if flask_server:
            print("Stopping Flask server...")
            flask_server.stop()
        
        print("Shutdown completed successfully")
    except Exception as e:
        print(f"Error during shutdown: {e}")
    finally:
        # Force exit if something is stuck
        os._exit(0)

if __name__ == '__main__':
    try:
        # Initialize components
        flask_server = FlaskServer(app)
        
        # Register signal handlers
        signal.signal(signal.SIGINT, lambda s, f: shutdown_server())
        signal.signal(signal.SIGTERM, lambda s, f: shutdown_server())
        
        # Register cleanup
        atexit.register(shutdown_server)
        
        # Initialize the app
        init_app(app)
        
        # Start the server
        print("Starting server...")
        flask_server.start()
        
        # Keep the main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        shutdown_server()
    except Exception as e:
        print(f"Error: {e}")
        shutdown_server() 