import requests
import random
import time
import threading
from datetime import datetime
import json
import uuid

class RequestSimulator:
    def __init__(self):
        self.base_url = "http://localhost:5000"
        self.endpoints = {
            '/api/auth': {
                'methods': ['POST'],
                'payloads': [
                    {'username': 'user1', 'password': 'pass123'},
                    {'username': 'admin', 'password': 'wrong_pass'},
                    {'username': 'nonexistent', 'password': 'test123'}
                ]
            },
            '/api/users': {
                'methods': ['GET', 'POST'],
                'payloads': [
                    {'name': 'John Doe', 'email': 'john@example.com'},
                    {'name': 'Jane Smith', 'email': 'jane@example.com'},
                    {'name': 'Invalid Name', 'email': 'not_an_email'}
                ]
            },
            '/api/products': {
                'methods': ['GET', 'POST'],
                'payloads': [
                    {'name': 'Laptop', 'price': 999.99, 'stock': 10},
                    {'name': 'Phone', 'price': 599.99, 'stock': 0},
                    {'name': 'Invalid', 'price': -100, 'stock': -5}
                ]
            },
            '/api/orders': {
                'methods': ['GET', 'POST'],
                'payloads': [
                    {'product_id': 1, 'quantity': 2},
                    {'product_id': 2, 'quantity': 100},  # Out of stock
                    {'product_id': 999, 'quantity': 1}   # Non-existent product
                ]
            },
            '/api/cart': {
                'methods': ['GET', 'POST', 'DELETE'],
                'payloads': [
                    {'product_id': 1, 'quantity': 1},
                    {'product_id': 2, 'quantity': 0},    # Invalid quantity
                    {'product_id': 999, 'quantity': 1}   # Non-existent product
                ]
            }
        }
        
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1'
        ]
        
        self.running = False
        self.active_sessions = {}  # Store active user sessions
        
        # Add user behavior patterns
        self.user_patterns = {
            'normal_user': {
                'session_length': (10, 30),  # minutes
                'request_interval': (2, 10),  # seconds
                'error_tolerance': 0.3,  # probability to continue after error
                'typical_actions': ['browse_products', 'view_cart', 'add_to_cart']
            },
            'bot': {
                'session_length': (1, 5),
                'request_interval': (0.1, 0.5),
                'error_tolerance': 0.9,
                'typical_actions': ['browse_products'] * 10  # Repetitive behavior
            },
            'attacker': {
                'session_length': (5, 15),
                'request_interval': (0.1, 1),
                'error_tolerance': 0.8,
                'typical_actions': ['auth', 'auth', 'auth']  # Brute force attempts
            }
        }

    def create_session(self):
        session = requests.Session()
        session_id = str(uuid.uuid4())
        
        # Assign a random user pattern
        pattern_type = random.choices(
            list(self.user_patterns.keys()),
            weights=[0.8, 0.1, 0.1]  # 80% normal, 10% bot, 10% attacker
        )[0]
        
        pattern = self.user_patterns[pattern_type]
        session_length = random.uniform(*pattern['session_length']) * 60  # Convert to seconds
        
        self.active_sessions[session_id] = {
            'session': session,
            'pattern': pattern_type,
            'start_time': datetime.now(),
            'session_length': session_length,
            'last_activity': datetime.now(),
            'error_count': 0
        }
        
        return session_id

    def simulate_user_behavior(self, session_id):
        """Simulate realistic user behavior within a session"""
        if session_id not in self.active_sessions:
            return None
        
        session_data = self.active_sessions[session_id]
        session = session_data['session']
        pattern_type = session_data['pattern']
        
        # Get actions from user pattern
        pattern = self.user_patterns[pattern_type]
        actions = []
        
        if pattern_type == 'normal_user':
            actions = [
                self.browse_products,
                self.add_to_cart,
                self.view_cart,
                self.place_order
            ]
        elif pattern_type == 'bot':
            actions = [self.browse_products] * 10  # Repetitive behavior
        else:  # attacker
            actions = [self.retry_login] * 5  # Brute force attempts
        
        action = random.choice(actions)
        return action(session)

    def browse_products(self, session):
        return self.send_request('/api/products', 'GET', session=session)

    def add_to_cart(self, session):
        payload = random.choice(self.endpoints['/api/cart']['payloads'])
        return self.send_request('/api/cart', 'POST', session=session, payload=payload)

    def view_cart(self, session):
        return self.send_request('/api/cart', 'GET', session=session)

    def place_order(self, session):
        payload = random.choice(self.endpoints['/api/orders']['payloads'])
        return self.send_request('/api/orders', 'POST', session=session, payload=payload)

    def failed_cart_addition(self, session):
        payload = random.choice(self.endpoints['/api/cart']['payloads'])
        return self.send_request('/api/cart', 'POST', session=session, payload=payload)

    def retry_login(self, session):
        payload = random.choice(self.endpoints['/api/auth']['payloads'])
        return self.send_request('/api/auth', 'POST', session=session, payload=payload)

    def send_request(self, endpoint, method='GET', session=None, payload=None):
        headers = {'User-Agent': random.choice(self.user_agents)}
        start_time = time.time()
        
        try:
            if session is None:
                session = requests.Session()

            # Enhanced anomaly patterns
            anomaly_type = random.random()
            if anomaly_type < 0.15:  # Network issues
                time.sleep(random.uniform(2, 5))  # Slow response
            elif anomaly_type < 0.20:  # Burst of rapid requests
                for _ in range(random.randint(5, 10)):
                    session.get(f"{self.base_url}{endpoint}", headers=headers)
                    time.sleep(0.1)
            elif anomaly_type < 0.25:  # Connection drops
                raise requests.exceptions.ConnectionError("Simulated connection drop")
            
            # Add load-based response times
            base_response_time = random.uniform(0.1, 0.5)
            current_hour = datetime.now().hour
            
            # Simulate peak hours (9AM-5PM)
            if 9 <= current_hour <= 17:
                base_response_time *= random.uniform(1.5, 3.0)
            
            if method == 'GET':
                response = session.get(f"{self.base_url}{endpoint}", headers=headers)
            else:
                response = session.post(f"{self.base_url}{endpoint}", 
                                     json=payload,
                                     headers=headers)
            
            response_time = (time.time() - start_time) * 1000
            
            return {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'endpoint': endpoint,
                'method': method,
                'status_code': response.status_code,
                'response_time': round(response_time, 2),
                'user_agent': headers['User-Agent'],
                'ip_address': '127.0.0.1',
                'payload': payload
            }
        
        except requests.exceptions.RequestException as e:
            print(f"Error sending request: {e}")
            return None

    def cleanup_old_sessions(self):
        """Remove inactive sessions older than 30 minutes"""
        current_time = datetime.now()
        sessions_to_remove = []
        
        for session_id, session_data in self.active_sessions.items():
            if (current_time - session_data['last_activity']).total_seconds() > 1800:  # 30 minutes
                sessions_to_remove.append(session_id)
        
        for session_id in sessions_to_remove:
            del self.active_sessions[session_id]

    def simulate_traffic(self, callback):
        while self.running:
            try:
                # Increase frequency of new sessions
                if not self.active_sessions or random.random() < 0.4:
                    session_id = self.create_session()
                else:
                    try:
                        session_id = random.choice(list(self.active_sessions.keys()))
                    except IndexError:
                        continue  # Skip if no active sessions

                # Generate requests more frequently
                for _ in range(random.randint(1, 3)):
                    try:
                        log_entry = self.simulate_user_behavior(session_id)
                        if log_entry:
                            callback(log_entry)
                    except Exception as e:
                        print(f"Error generating request: {e}")
                    time.sleep(random.uniform(0.1, 0.5))

                # Cleanup old sessions periodically
                if random.random() < 0.1:
                    self.cleanup_old_sessions()

            except Exception as e:
                print(f"Error in simulate_traffic: {e}")
                time.sleep(1)

    def start(self, callback):
        self.running = True
        self.thread = threading.Thread(target=self.simulate_traffic, args=(callback,))
        self.thread.start()

    def stop(self):
        self.running = False
        if hasattr(self, 'thread'):
            try:
                self.thread.join(timeout=2)
            except Exception as e:
                print(f"Error stopping thread: {e}")

    def simulate_correlated_errors(self):
        """Simulate cascading failures across endpoints"""
        if random.random() < 0.05:  # 5% chance of cascading failure
            self.system_degradation = {
                'start_time': datetime.now(),
                'duration': random.uniform(60, 180),  # 1-3 minutes
                'affected_endpoints': random.sample(list(self.endpoints.keys()), 
                                                 k=random.randint(2, 4))
            } 