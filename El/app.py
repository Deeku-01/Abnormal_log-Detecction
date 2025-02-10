from flask import Flask, jsonify, render_template, request, session
import random
import time
from datetime import datetime
import queue
import threading
from request_simulator import RequestSimulator
import atexit

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Required for sessions

# Global variables
request_log = queue.Queue(maxsize=1000)
request_simulator = None  # Initialize as None
simulator_thread = None

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
    log_entry = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'endpoint': endpoint,
        'method': method,
        'status_code': status_code,
        'response_time': round(response_time, 2),
        'payload': payload
    }
    
    try:
        if request_log.full():
            request_log.get_nowait()  # Remove oldest entry if full
        request_log.put_nowait(log_entry)
    except queue.Full:
        pass  # Skip logging if queue is full
    
    # Update endpoint statistics
    update_endpoint_stats(endpoint, status_code)

def start_request_simulator():
    global request_simulator, simulator_thread
    
    if request_simulator is None:
        request_simulator = RequestSimulator()
        
    def process_log(log_entry):
        if log_entry:
            try:
                log_request(
                    log_entry['endpoint'],
                    log_entry['method'],
                    log_entry['status_code'],
                    log_entry['response_time'],
                    log_entry.get('payload')
                )
            except Exception as e:
                print(f"Error processing log: {e}")
    
    if not simulator_thread or not simulator_thread.is_alive():
        simulator_thread = threading.Thread(
            target=lambda: request_simulator.start(process_log),
            daemon=True
        )
        simulator_thread.start()

def stop_request_simulator():
    global request_simulator, simulator_thread
    if request_simulator:
        request_simulator.stop()
    if simulator_thread and simulator_thread.is_alive():
        simulator_thread.join(timeout=1)

@app.route('/')
def dashboard():
    global request_simulator
    
    # Start simulator if not running
    if request_simulator is None or not simulator_thread.is_alive():
        start_request_simulator()
    
    # Calculate statistics
    total_requests = sum(stats['requests'] for stats in endpoint_stats.values())
    total_errors = sum(stats['errors'] for stats in endpoint_stats.values())
    error_rate = round((total_errors / total_requests * 100) if total_requests > 0 else 0, 1)
    
    # Update success rates in endpoints list
    for endpoint in endpoints:
        endpoint['success_rate'] = calculate_success_rate(endpoint['path'])

    # Convert queue to list for template rendering
    try:
        logs = list(request_log.queue)
        logs.reverse()  # Show newest first
    except:
        logs = []

    # Get active sessions count
    active_sessions = len(request_simulator.active_sessions) if request_simulator else 0

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
    while True:
        time.sleep(60)  # Check every minute
        session_manager.cleanup_old_sessions()

# Start the cleanup thread
cleanup_thread = threading.Thread(target=cleanup_sessions, daemon=True)
cleanup_thread.start()

class AutomatedResponse:
    def __init__(self):
        self.blocked_ips = {}  # Changed to dict to store more info
        self.rate_limits = {}
        self.suspicious_sessions = {}
        self.lock = threading.Lock()

    def check_and_block(self, ip, endpoint, method, status_code):
        with self.lock:
            current_time = datetime.now()
            
            # Initialize rate limiting
            if ip not in self.rate_limits:
                self.rate_limits[ip] = {
                    'count': 0,
                    'first_request': current_time,
                    'warnings': 0,
                    'last_activity': current_time
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

automated_response = AutomatedResponse()

# Add to each route handler:
@app.before_request
def check_automated_response():
    ip = request.remote_addr
    is_blocked, headers = automated_response.check_and_block(
        ip, 
        request.path, 
        request.method, 
        200  # Default status code
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
    blocked_ips_details = {
        ip: {
            'blocked_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'reason': 'Rate limit exceeded' if automated_response.rate_limits.get(ip, {}).get('count', 0) > 100 
                     else 'Suspicious auth attempts'
        }
        for ip in automated_response.blocked_ips
    }
    
    rate_limited_count = sum(
        1 for ip, data in automated_response.rate_limits.items()
        if data['count'] / ((datetime.now() - data['first_request']).total_seconds()) > 50
    )
    
    suspicious_auth_count = sum(
        data['warnings'] for data in automated_response.rate_limits.values()
    )

    return render_template('security.html',
        blocked_ips=blocked_ips_details,
        rate_limits=automated_response.rate_limits,
        rate_limited_count=rate_limited_count,
        suspicious_auth_count=suspicious_auth_count
    )

# Add cleanup on shutdown
@atexit.register
def cleanup():
    stop_request_simulator()

if __name__ == '__main__':
    try:
        start_request_simulator()
        app.run(port=5000, debug=False)  # Set debug=False to avoid duplicate simulators
    finally:
        stop_request_simulator() 