import requests
import random
import time
from datetime import datetime
import sys

def check_test_traffic_status(base_url):
    try:
        status_response = requests.get(f"{base_url}/api/test_traffic_status")
        return status_response.json().get('enabled', True)
    except:
        return True  # Continue if status check fails

def send_requests():
    base_url = "http://localhost:5000"
    
    # List of test users
    users = [
        {"username": "user1", "password": "password123"},
        {"username": "user2", "password": "password456"},
        {"username": "admin", "password": "adminpass"},
        {"username": "unknown_user", "password": "wrongpass"}
    ]

    # Add custom headers to identify test traffic
    headers = {
        'X-Forwarded-For': f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
        'X-Test-Traffic': 'true'
    }

    print("\n" + "="*50)
    print("Starting Test Traffic Generator")
    print("="*50 + "\n")

    try:
        while True:
            # Check if we should stop
            if not check_test_traffic_status(base_url):
                print("\n" + "="*50)
                print("[TEST] Test traffic generator stopped by user request")
                print("="*50 + "\n")
                sys.exit(0)

            try:
                print("\n--- Test Traffic Generator ---")
                # Random user login attempts
                user = random.choice(users)
                response = requests.post(
                    f"{base_url}/api/login",
                    json=user,
                    headers=headers
                )
                print(f"[TEST] Login attempt for {user['username']}: {response.status_code}")

                # Random data access only if login was successful
                if response.status_code == 200:
                    response = requests.get(
                        f"{base_url}/api/data",
                        params={"user": user['username']},
                        headers=headers
                    )
                    print(f"[TEST] Data access for {user['username']}: {response.status_code}")

                    # Random admin actions only after successful login
                    if user['username'] == "admin":
                        response = requests.post(
                            f"{base_url}/api/admin",
                            json={"username": user['username'], "action": "update_settings"},
                            headers=headers
                        )
                        print(f"[TEST] Admin action: {response.status_code}")
                print("-"*30)

                time.sleep(random.uniform(2, 4))

            except requests.exceptions.RequestException as e:
                print(f"[TEST] Error sending request: {e}")
                time.sleep(5)
                
    except KeyboardInterrupt:
        print("\n[TEST] Test traffic generator stopped by user")
        sys.exit(0)

if __name__ == "__main__":
    send_requests() 