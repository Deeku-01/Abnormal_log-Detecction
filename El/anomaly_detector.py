import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pandas as pd
import pickle
import os
from datetime import datetime
import colorama
from colorama import Fore, Style
from request_simulator import RequestSimulator
import time

# Initialize colorama for colored console output
colorama.init()

class DetailedAnalytics:
    def __init__(self):
        self.endpoint_stats = {}
        self.hourly_stats = {}
        self.anomaly_patterns = {}
        
    def update_stats(self, logs, predictions, scores):
        df = pd.DataFrame(logs)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['is_anomaly'] = predictions == -1
        df['anomaly_score'] = scores
        
        # Endpoint analysis
        endpoint_analysis = df.groupby('endpoint').agg({
            'response_time': ['mean', 'std', 'max'],
            'status_code': lambda x: (x >= 400).mean(),
            'is_anomaly': 'mean'
        })
        
        # Hourly patterns
        hourly = df.groupby(df['timestamp'].dt.hour).agg({
            'response_time': 'mean',
            'is_anomaly': 'mean',
            'status_code': lambda x: (x >= 400).mean()
        })
        
        # Anomaly patterns
        anomaly_df = df[df['is_anomaly']]
        patterns = {
            'slow_response': len(anomaly_df[anomaly_df['response_time'] > 1000]),
            'error_burst': len(anomaly_df[anomaly_df['status_code'] >= 400]),
            'auth_failures': len(anomaly_df[
                (anomaly_df['endpoint'] == '/api/auth') & 
                (anomaly_df['status_code'] == 401)
            ])
        }
        
        self.endpoint_stats = endpoint_analysis.to_dict()
        self.hourly_stats = hourly.to_dict()
        self.anomaly_patterns = patterns
        
        return {
            'endpoint_analysis': endpoint_analysis,
            'hourly_patterns': hourly,
            'anomaly_patterns': patterns
        }

class AnomalyDetector:
    def __init__(self):
        # More sensitive anomaly detection
        self.model = IsolationForest(
            contamination=0.15,  # Increased to 15%
            random_state=42,
            n_estimators=100,
            max_samples='auto'
        )
        self.scaler = StandardScaler()
        self.model_file = 'anomaly_model.pkl'
        self.scaler_file = 'scaler.pkl'
        self.logs_buffer = []
        self.buffer_size = 30  # Reduced buffer size for more frequent analysis
        self.history = []
        self.analytics = DetailedAnalytics()
        self.load_model()

    def load_model(self):
        if os.path.exists(self.model_file) and os.path.exists(self.scaler_file):
            with open(self.model_file, 'rb') as f:
                self.model = pickle.load(f)
            with open(self.scaler_file, 'rb') as f:
                self.scaler = pickle.load(f)

    def save_model(self):
        with open(self.model_file, 'wb') as f:
            pickle.dump(self.model, f)
        with open(self.scaler_file, 'wb') as f:
            pickle.dump(self.scaler, f)

    def prepare_data(self, logs):
        df = pd.DataFrame(logs)
        
        # Convert timestamp to datetime
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Basic features
        features = pd.DataFrame()
        features['response_time'] = df['response_time']
        features['status_code'] = pd.to_numeric(df['status_code'])
        
        # Time-based features
        features['hour'] = df['timestamp'].dt.hour
        features['minute'] = df['timestamp'].dt.minute
        features['is_peak_hour'] = ((features['hour'] >= 9) & (features['hour'] <= 17)).astype(int)
        features['is_weekend'] = df['timestamp'].dt.weekday.isin([5, 6]).astype(int)
        
        # Request patterns
        features['request_rate'] = df.groupby(df['timestamp'].dt.minute).size()
        features['error_rate'] = df.groupby(df['timestamp'].dt.minute)['status_code'].apply(
            lambda x: (x >= 400).mean()
        )
        
        # Response time patterns
        if len(self.history) > 0:
            hist_df = pd.DataFrame(self.history)
            hist_df['timestamp'] = pd.to_datetime(hist_df['timestamp'])
            
            # Calculate rolling statistics
            features['rt_moving_avg'] = df['response_time'].rolling(window=10).mean()
            features['rt_moving_std'] = df['response_time'].rolling(window=10).std()
            features['rt_zscore'] = (df['response_time'] - features['rt_moving_avg']) / features['rt_moving_std']
            
            # Calculate endpoint-specific baselines
            endpoint_baselines = hist_df.groupby('endpoint')['response_time'].agg(['mean', 'std'])
            for endpoint in df['endpoint'].unique():
                if endpoint in endpoint_baselines.index:
                    mask = df['endpoint'] == endpoint
                    baseline_mean = endpoint_baselines.loc[endpoint, 'mean']
                    baseline_std = endpoint_baselines.loc[endpoint, 'std']
                    features.loc[mask, 'endpoint_rt_zscore'] = (
                        (df.loc[mask, 'response_time'] - baseline_mean) / baseline_std
                    )
        
        # Request sequence patterns
        features['consecutive_errors'] = (
            (df['status_code'] >= 400).rolling(window=3).sum()
        )
        
        return features.fillna(0)

    def train_and_detect(self, logs):
        # Add to history
        self.history.extend(logs)
        # Keep last 1000 requests in history
        self.history = self.history[-1000:]
        
        features = self.prepare_data(logs)
        
        # Scale the features
        scaled_features = self.scaler.fit_transform(features)
        
        # Train the model and predict
        predictions = self.model.fit_predict(scaled_features)
        
        # Calculate anomaly scores
        scores = self.model.score_samples(scaled_features)
        
        # Save the updated model
        self.save_model()
        
        # Add analytics
        analytics_results = self.analytics.update_stats(logs, predictions, scores)
        
        # Enhanced logging
        print("\nDetailed Analytics:")
        print("=" * 80)
        print(f"Endpoint Analysis:\n{analytics_results['endpoint_analysis']}\n")
        print(f"Hourly Patterns:\n{analytics_results['hourly_patterns']}\n")
        print(f"Anomaly Patterns:\n{analytics_results['anomaly_patterns']}")
        print("=" * 80)
        
        return predictions, scores

    def detect_anomalies(self, logs):
        features = self.prepare_data(logs)
        scaled_features = self.scaler.transform(features)
        predictions = self.model.predict(scaled_features)
        return predictions

def print_log_entry(log, is_anomaly):
    timestamp = log['timestamp']
    method = log['method']
    endpoint = log['endpoint']
    status_code = log['status_code']
    response_time = log['response_time']
    
    color = Fore.RED if is_anomaly else Fore.GREEN
    print(f"{color}[{timestamp}] {method} {endpoint} - Status: {status_code}, "
          f"Response Time: {response_time}ms{Style.RESET_ALL}")

def main():
    anomaly_detector = AnomalyDetector()
    simulator = RequestSimulator()
    
    def process_log(log_entry):
        anomaly_detector.logs_buffer.append(log_entry)
        
        if len(anomaly_detector.logs_buffer) >= anomaly_detector.buffer_size:
            predictions, scores = anomaly_detector.train_and_detect(anomaly_detector.logs_buffer)
            
            print("\nProcessing batch of logs:")
            print("=" * 80)
            
            # Print logs without individual anomaly scores
            for log, prediction in zip(anomaly_detector.logs_buffer, predictions):
                is_anomaly = prediction == -1
                print_log_entry(log, is_anomaly)
            
            # Summary with overall statistics
            anomaly_count = sum(1 for p in predictions if p == -1)
            print("\nSummary:")
            print(f"Total logs processed: {len(predictions)}")
            print(f"Anomalies detected: {anomaly_count}")
            print(f"Normal logs: {len(predictions) - anomaly_count}")
            print(f"Average anomaly score: {scores.mean():.3f}")
            print(f"Min anomaly score: {scores.min():.3f}")
            print(f"Max anomaly score: {scores.max():.3f}")
            print("=" * 80)
            
            anomaly_detector.logs_buffer = []

    try:
        print("Starting request simulation... Press Ctrl+C to stop")
        simulator.start(process_log)
        
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping simulation...")
        simulator.stop()
        print("Simulation stopped")

if __name__ == "__main__":
    main() 