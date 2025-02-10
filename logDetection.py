import pandas as pd
import numpy as np
import random
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest
from datetime import datetime
import json
import logging
from typing import List, Dict, Any
import time
import threading
import os

class LogAnalyzer:
    def __init__(self):
        self.scaler = StandardScaler()
        self.model = IsolationForest(contamination=0.2, random_state=42, n_estimators=100)
        self.logger = self._setup_logger()

    def _setup_logger(self) -> logging.Logger:
        """Set up logging configuration"""
        logger = logging.getLogger('LogAnalyzer')
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('\n%(asctime)s - %(name)s - %(levelname)s\n%(message)s\n')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def preprocess_logs(self, raw_logs: List[Dict[str, Any]]) -> pd.DataFrame:
        """
        Preprocess raw log data into structured format with numerical features
        """
        try:
            # Convert list of dictionaries to DataFrame
            df = pd.DataFrame(raw_logs)
            
            # Convert timestamp strings to datetime objects
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            # Extract time-based features
            df['hour'] = df['timestamp'].dt.hour
            df['minute'] = df['timestamp'].dt.minute
            df['day_of_week'] = df['timestamp'].dt.dayofweek
            
            # Convert categorical variables to numerical using one-hot encoding
            if 'event_type' in df.columns:
                event_type_dummies = pd.get_dummies(df['event_type'], prefix='event')
                df = pd.concat([df, event_type_dummies], axis=1)
            
            if 'status' in df.columns:
                status_dummies = pd.get_dummies(df['status'], prefix='status')
                df = pd.concat([df, status_dummies], axis=1)
            
            # Convert IP addresses to numerical values
            if 'source_ip' in df.columns:
                df['ip_last_octet'] = df['source_ip'].apply(
                    lambda x: int(x.split('.')[-1]) if isinstance(x, str) else 0
                    )
            
            # Create user-based numerical features
            if 'user' in df.columns:
                user_dummies = pd.get_dummies(df['user'], prefix='user')
                df = pd.concat([df, user_dummies], axis=1)
            
            # Drop non-numerical columns
            columns_to_drop = ['timestamp', 'event_type', 'user', 'source_ip', 'status']
            df = df.drop([col for col in columns_to_drop if col in df.columns], axis=1)
            
            # Handle missing values
            df = df.fillna(0)
            
            self.logger.info(f"Preprocessed {len(df)} log entries with {len(df.columns)} features")
            self.logger.info(f"Features available: {', '.join(df.columns)}")
            
            return df
            
        except Exception as e:
            self.logger.error(f"Error in preprocessing: {str(e)}")
            raise

    def train_model(self, df: pd.DataFrame) -> None:
        """
        Train the anomaly detection model
        """
        try:
            # Select numerical features for training
            numerical_features = df.select_dtypes(include=['int64', 'float64']).columns
            X = df[numerical_features]
            
            # Scale the features
            X_scaled = self.scaler.fit_transform(X)
            
            # Train the model
            self.model.fit(X_scaled)
            
            self.logger.info("Model training completed successfully")
            
        except Exception as e:
            self.logger.error(f"Error in model training: {str(e)}")
            raise

    def detect_anomalies(self, df: pd.DataFrame) -> np.ndarray:
        """
        Detect anomalies in new log data
        """
        try:
            numerical_features = df.select_dtypes(include=['int64', 'float64']).columns
            X = df[numerical_features]
            X_scaled = self.scaler.transform(X)
            
            # Predict anomalies (-1 for anomalies, 1 for normal)
            predictions = self.model.predict(X_scaled)
            
            # Convert predictions to boolean (True for anomalies)
            anomalies = predictions == -1
            
            self.logger.info(f"Detected {sum(anomalies)} anomalies in {len(df)} logs")
            return anomalies
            
        except Exception as e:
            self.logger.error(f"Error in anomaly detection: {str(e)}")
            raise

    def real_time_monitoring(self, log_source: str, interval: int = 5):
        """
        Continuous monitoring of logs in real-time
        """
        last_processed = 0
        
        try:
            while True:
                # Collect new logs
                all_logs = self._collect_new_logs(log_source)
                
                if len(all_logs) > last_processed:
                    # Process only new logs
                    new_logs = all_logs[last_processed:]
                    
                    if new_logs:
                        # Preprocess new logs
                        df = self.preprocess_logs(new_logs)
                        
                        # Detect anomalies
                        anomalies = self.detect_anomalies(df)
                        
                        # Handle detected anomalies
                        if any(anomalies):
                            anomalous_df = pd.DataFrame(new_logs)[anomalies]
                            self._handle_anomalies(anomalous_df)
                        
                        last_processed = len(all_logs)
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            self.logger.info("Real-time monitoring stopped")
        except Exception as e:
            self.logger.error(f"Error in real-time monitoring: {str(e)}")
            raise

    def _collect_new_logs(self, log_source: str) -> List[Dict[str, Any]]:
        """
        Collect new logs from the specified source
        """
        try:
            with open(log_source, 'r') as file:
                log_data = json.load(file)
                return log_data.get('logs', [])
        except Exception as e:
            self.logger.error(f"Error reading logs from {log_source}: {str(e)}")
            return []

    def _handle_anomalies(self, anomalous_logs: pd.DataFrame) -> None:
        """
        Enhanced anomaly handling with detailed classification
        """
        if not anomalous_logs.empty:
            for _, log in anomalous_logs.iterrows():
                reasons = []
                
                # Classify the type of anomaly
                if log.get('is_failed_login', 0) == 1:
                    if log.get('user_attempts', 0) > self.suspicious_patterns['login_attempts']:
                        reasons.append("Multiple failed login attempts")
                
                if log.get('response_time', 0) > self.suspicious_patterns['response_time_threshold']:
                    reasons.append("Unusual response time")
                
                if log.get('is_admin_action', 0) == 1 and log.get('status_success', 0) == 0:
                    reasons.append("Unauthorized admin action attempt")
                
                if 'unknown_user' in str(log.get('user', '')):
                    reasons.append("Unknown user attempt")
                
                if not reasons:
                    reasons.append("Statistical anomaly detected")
                
                self.logger.warning(
                    "\n" + "!"*50 + "\n" +
                    "ANOMALY DETECTED:\n" +
                    f"Reasons: {', '.join(reasons)}\n" +
                    f"Traffic Type: {log.get('traffic_type', 'unknown')}\n" +
                    f"Details: {log.to_dict()}\n" +
                    "!"*50
                )

class WebsiteLogAnalyzer(LogAnalyzer):
    def __init__(self):
        super().__init__()
        # Make model less sensitive initially
        self.model = IsolationForest(
            contamination=0.1,  # Start with 10% contamination
            random_state=42,
            n_estimators=100,
            max_samples=100
        )
        self.suspicious_patterns = {
            'login_attempts': 3,
            'response_time_threshold': 1.0,
            'admin_action_unauthorized': 2
        }

    def preprocess_logs(self, raw_logs: List[Dict[str, Any]]) -> pd.DataFrame:
        """
        Enhanced preprocessing with consistent feature names
        """
        try:
            df = pd.DataFrame(raw_logs)
            
            # Basic features
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df['hour'] = df['timestamp'].dt.hour
            df['minute'] = df['timestamp'].dt.minute
            
            # IP-based features
            df['ip_attempts'] = df.groupby('source_ip')['source_ip'].transform('count')
            df['ip_failed_attempts'] = df[df['status'] == 'failed'].groupby('source_ip')['source_ip'].transform('count').fillna(0)
            
            # User-based features
            df['user_attempts'] = df.groupby('user')['user'].transform('count')
            df['user_failed_attempts'] = df[df['status'] == 'failed'].groupby('user')['user'].transform('count').fillna(0)
            
            # Response time features
            df['response_time'] = df['response_time'].fillna(0).astype(float)
            df['high_response_time'] = (df['response_time'] > self.suspicious_patterns['response_time_threshold']).astype(int)
            
            # Security features
            df['is_admin_action'] = (df['event_type'] == 'admin_action').astype(int)
            df['is_failed_login'] = ((df['event_type'] == 'login') & (df['status'] == 'failed')).astype(int)
            df['is_unknown_user'] = (~df['user'].isin(['user1', 'user2', 'admin', 'system'])).astype(int)
            df['rapid_requests'] = (df.groupby('source_ip')['timestamp'].diff().dt.total_seconds() < 1).astype(int)
            
            # Status features
            df['status_failed'] = (df['status'] == 'failed').astype(int)
            df['status_unauthorized'] = (df['status'] == 'unauthorized').astype(int)
            
            # Select final features in consistent order
            feature_columns = [
                'hour', 'minute',
                'ip_attempts', 'ip_failed_attempts',
                'user_attempts', 'user_failed_attempts',
                'response_time', 'high_response_time',
                'is_admin_action', 'is_failed_login',
                'is_unknown_user', 'rapid_requests',
                'status_failed', 'status_unauthorized'
            ]
            
            return df[feature_columns]
            
        except Exception as e:
            self.logger.error(f"Error in preprocessing: {str(e)}")
            raise

    def detect_anomalies(self, df: pd.DataFrame) -> np.ndarray:
        """
        Enhanced anomaly detection with multiple criteria
        """
        try:
            # Get features for isolation forest
            X = df.copy()
            X_scaled = self.scaler.transform(X)
            
            # Get isolation forest predictions
            predictions = self.model.predict(X_scaled)
            
            # Additional rule-based anomaly detection
            anomalies = predictions == -1  # Start with isolation forest predictions
            
            # Add rule-based anomalies
            anomalies = anomalies | (df['ip_failed_attempts'] >= self.suspicious_patterns['login_attempts'])
            anomalies = anomalies | (df['user_failed_attempts'] >= self.suspicious_patterns['login_attempts'])
            anomalies = anomalies | (df['high_response_time'] == 1)
            anomalies = anomalies | ((df['is_admin_action'] == 1) & (df['status_unauthorized'] == 1))
            anomalies = anomalies | (df['is_unknown_user'] == 1)
            anomalies = anomalies | (df['rapid_requests'] == 1)
            
            self.logger.info(f"Detected {sum(anomalies)} anomalies in {len(df)} logs")
            return anomalies
            
        except Exception as e:
            self.logger.error(f"Error in anomaly detection: {str(e)}")
            raise

    def _collect_new_logs(self, log_file: str) -> List[Dict[str, Any]]:
        """
        Collect new logs from the website log file
        """
        try:
            with open(log_file, 'r') as file:
                data = json.load(file)
                return data.get('logs', [])
        except Exception as e:
            self.logger.error(f"Error reading logs: {str(e)}")
            return []

    def _handle_anomalies(self, anomalous_logs: pd.DataFrame) -> None:
        """
        Enhanced anomaly handling with detailed classification
        """
        if not anomalous_logs.empty:
            for _, log in anomalous_logs.iterrows():
                reasons = []
                
                # Classify the type of anomaly
                if log.get('is_failed_login', 0) == 1:
                    if log.get('user_attempts', 0) > self.suspicious_patterns['login_attempts']:
                        reasons.append("Multiple failed login attempts")
                
                if log.get('response_time', 0) > self.suspicious_patterns['response_time_threshold']:
                    reasons.append("Unusual response time")
                
                if log.get('is_admin_action', 0) == 1 and log.get('status_success', 0) == 0:
                    reasons.append("Unauthorized admin action attempt")
                
                if 'unknown_user' in str(log.get('user', '')):
                    reasons.append("Unknown user attempt")
                
                if not reasons:
                    reasons.append("Statistical anomaly detected")
                
                self.logger.warning(
                    "\n" + "!"*50 + "\n" +
                    "ANOMALY DETECTED:\n" +
                    f"Reasons: {', '.join(reasons)}\n" +
                    f"Traffic Type: {log.get('traffic_type', 'unknown')}\n" +
                    f"Details: {log.to_dict()}\n" +
                    "!"*50
                )

def simulate_new_logs(log_file: str):
    """
    Simulate new log entries by appending to the log file
    """
    # Initialize the log file if it doesn't exist
    if not os.path.exists(log_file):
        with open(log_file, 'w') as file:
            json.dump({"logs": []}, file, indent=2)
    
    while True:
        try:
            # Read existing logs
            with open(log_file, 'r') as file:
                data = json.load(file)
            
            # Occasionally generate suspicious patterns (20% chance)
            is_suspicious = random.random() < 0.2
            
            if is_suspicious:
                # Generate suspicious log entry
                new_log = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "event_type": random.choice(["login", "admin_action"]),
                    "user": random.choice(["unknown_user", "admin"]),
                    "source_ip": f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
                    "status": "failed",
                    "response_time": random.uniform(2.0, 5.0),
                    "attempts": random.randint(5, 10)
                }
            else:
                # Generate normal log entry
                new_log = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "event_type": random.choice(["login", "file_access", "system_update"]),
                    "user": random.choice(["user1", "user2", "admin", "system"]),
                    "source_ip": f"192.168.1.{random.randint(1, 255)}",
                    "status": random.choice(["success", "failed", "running"]),
                    "response_time": random.uniform(0.1, 0.5),
                    "attempts": random.randint(1, 3)
                }
            
            # Append new log
            data['logs'].append(new_log)
            
            # Write back to file
            with open(log_file, 'w') as file:
                json.dump(data, file, indent=2)
            
            print(f"Generated {'suspicious' if is_suspicious else 'normal'} log entry")
            time.sleep(5)  # Wait for 5 seconds before adding new log
            
        except Exception as e:
            print(f"Error simulating new logs: {str(e)}")
            time.sleep(5)

def main():
    try:
        # Initialize the website log analyzer
        analyzer = WebsiteLogAnalyzer()
        log_file = 'website_logs.json'
        
        print("\nStarting Log Detection System...")
        print("="*50)
        
        # Initialize model with dummy data for training
        initial_df = pd.DataFrame({
            'hour': [0, 1],
            'minute': [0, 30],
            'ip_attempts': [1, 2],
            'ip_failed_attempts': [0, 1],
            'user_attempts': [1, 2],
            'user_failed_attempts': [0, 1],
            'response_time': [0.1, 0.2],
            'high_response_time': [0, 1],
            'is_admin_action': [0, 1],
            'is_failed_login': [0, 1],
            'is_unknown_user': [0, 1],
            'rapid_requests': [0, 1],
            'status_failed': [0, 1],
            'status_unauthorized': [0, 1]
        })
        
        # Train initial model
        analyzer.train_model(initial_df)
        print("Model initialized with baseline data")
        
        # Start monitoring
        print("Starting real-time monitoring...")
        analyzer.real_time_monitoring(log_file, interval=2)
            
    except KeyboardInterrupt:
        print("\nLog Detection System stopped by user")
    except Exception as e:
        print(f"\nError in log detection: {str(e)}")
        raise

if __name__ == "__main__":
    main()