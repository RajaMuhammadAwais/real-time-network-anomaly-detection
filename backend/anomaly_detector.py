"""
Anomaly Detection Module
Implements machine learning-based anomaly detection for network traffic
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib
import logging
from datetime import datetime
import os

logger = logging.getLogger(__name__)

class AnomalyDetector:
    def __init__(self, contamination=0.1, model_path='anomaly_model.pkl'):
        """
        Initialize anomaly detector
        
        Args:
            contamination (float): Expected proportion of anomalies in the data
            model_path (str): Path to save/load the trained model
        """
        self.contamination = contamination
        self.model_path = model_path
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names = []
        
    def generate_synthetic_data(self, n_samples=1000):
        """Generate synthetic network traffic data for initial training"""
        np.random.seed(42)
        
        # Normal traffic patterns
        normal_data = {
            'packet_count': np.random.normal(100, 20, int(n_samples * 0.9)),
            'unique_src_ips': np.random.normal(10, 3, int(n_samples * 0.9)),
            'unique_dst_ips': np.random.normal(15, 4, int(n_samples * 0.9)),
            'avg_packet_size': np.random.normal(500, 100, int(n_samples * 0.9)),
            'std_packet_size': np.random.normal(150, 30, int(n_samples * 0.9)),
            'total_bytes': np.random.normal(50000, 10000, int(n_samples * 0.9)),
            'tcp_ratio': np.random.normal(0.7, 0.1, int(n_samples * 0.9)),
            'udp_ratio': np.random.normal(0.25, 0.08, int(n_samples * 0.9)),
            'icmp_ratio': np.random.normal(0.05, 0.02, int(n_samples * 0.9)),
            'avg_inter_arrival_time': np.random.normal(0.1, 0.05, int(n_samples * 0.9)),
            'std_inter_arrival_time': np.random.normal(0.05, 0.02, int(n_samples * 0.9)),
            'unique_connections': np.random.normal(20, 5, int(n_samples * 0.9)),
            'avg_packets_per_connection': np.random.normal(5, 2, int(n_samples * 0.9))
        }
        
        # Anomalous traffic patterns (DoS, Port Scan, etc.)
        anomaly_data = {
            'packet_count': np.random.normal(500, 100, int(n_samples * 0.1)),  # High packet count
            'unique_src_ips': np.random.normal(2, 1, int(n_samples * 0.1)),    # Few source IPs
            'unique_dst_ips': np.random.normal(50, 10, int(n_samples * 0.1)),  # Many destination IPs
            'avg_packet_size': np.random.normal(100, 50, int(n_samples * 0.1)), # Small packets
            'std_packet_size': np.random.normal(50, 20, int(n_samples * 0.1)),
            'total_bytes': np.random.normal(25000, 5000, int(n_samples * 0.1)),
            'tcp_ratio': np.random.normal(0.9, 0.05, int(n_samples * 0.1)),    # Mostly TCP
            'udp_ratio': np.random.normal(0.08, 0.03, int(n_samples * 0.1)),
            'icmp_ratio': np.random.normal(0.02, 0.01, int(n_samples * 0.1)),
            'avg_inter_arrival_time': np.random.normal(0.01, 0.005, int(n_samples * 0.1)), # Fast packets
            'std_inter_arrival_time': np.random.normal(0.005, 0.002, int(n_samples * 0.1)),
            'unique_connections': np.random.normal(100, 20, int(n_samples * 0.1)), # Many connections
            'avg_packets_per_connection': np.random.normal(2, 1, int(n_samples * 0.1)) # Few packets per connection
        }
        
        # Combine normal and anomalous data
        combined_data = {}
        for feature in normal_data.keys():
            combined_data[feature] = np.concatenate([normal_data[feature], anomaly_data[feature]])
        
        # Create labels (1 for normal, -1 for anomaly)
        labels = np.concatenate([
            np.ones(int(n_samples * 0.9)),   # Normal
            np.full(int(n_samples * 0.1), -1) # Anomaly
        ])
        
        df = pd.DataFrame(combined_data)
        return df, labels
    
    def train_model(self, training_data=None):
        """Train the anomaly detection model"""
        if training_data is None:
            logger.info("Generating synthetic training data...")
            training_data, _ = self.generate_synthetic_data()
        
        logger.info("Training anomaly detection model...")
        
        # Store feature names
        self.feature_names = training_data.columns.tolist()
        
        # Scale the features
        scaled_data = self.scaler.fit_transform(training_data)
        
        # Train Isolation Forest
        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100
        )
        
        self.model.fit(scaled_data)
        self.is_trained = True
        
        logger.info("Model training completed")
        
        # Save the model
        self.save_model()
        
        return self.model
    
    def predict(self, feature_vector):
        """
        Predict if the given feature vector is anomalous
        
        Args:
            feature_vector (np.array): Feature vector to classify
            
        Returns:
            dict: Prediction result with score and classification
        """
        if not self.is_trained:
            logger.warning("Model not trained. Loading or training model...")
            if not self.load_model():
                self.train_model()
        
        # Ensure feature vector is 2D
        if feature_vector.ndim == 1:
            feature_vector = feature_vector.reshape(1, -1)
        
        # Scale the features
        scaled_features = self.scaler.transform(feature_vector)
        
        # Predict
        prediction = self.model.predict(scaled_features)[0]
        anomaly_score = self.model.decision_function(scaled_features)[0]
        
        # Convert prediction to human-readable format
        is_anomaly = prediction == -1
        confidence = abs(anomaly_score)
        
        result = {
            'is_anomaly': is_anomaly,
            'anomaly_score': float(anomaly_score),
            'confidence': float(confidence),
            'prediction': 'Anomaly' if is_anomaly else 'Normal',
            'timestamp': datetime.now()
        }
        
        return result
    
    def analyze_features(self, features_dict):
        """
        Analyze features and detect specific attack types
        
        Args:
            features_dict (dict): Dictionary of extracted features
            
        Returns:
            dict: Analysis results including attack type detection
        """
        analysis = {
            'attack_types': [],
            'severity': 'Low',
            'recommendations': []
        }
        
        # Check for DoS indicators
        if features_dict.get('packet_count', 0) > 300:
            analysis['attack_types'].append('Potential DoS Attack')
            analysis['severity'] = 'High'
            analysis['recommendations'].append('Monitor source IPs and consider rate limiting')
        
        # Check for port scan indicators
        if 'port_scan_indicators' in features_dict and features_dict['port_scan_indicators']:
            analysis['attack_types'].append('Port Scanning Detected')
            analysis['severity'] = 'Medium' if analysis['severity'] == 'Low' else 'High'
            analysis['recommendations'].append('Block suspicious source IPs')
        
        # Check for unusual traffic patterns
        tcp_ratio = features_dict.get('tcp_ratio', 0)
        if tcp_ratio > 0.95:
            analysis['attack_types'].append('Unusual TCP Traffic Pattern')
            analysis['recommendations'].append('Investigate TCP connections')
        
        # Check for connection flooding
        unique_connections = features_dict.get('unique_connections', 0)
        if unique_connections > 100:
            analysis['attack_types'].append('Connection Flooding')
            analysis['severity'] = 'High'
            analysis['recommendations'].append('Implement connection limits')
        
        return analysis
    
    def save_model(self):
        """Save the trained model and scaler"""
        if self.model is not None:
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'feature_names': self.feature_names,
                'contamination': self.contamination
            }
            joblib.dump(model_data, self.model_path)
            logger.info(f"Model saved to {self.model_path}")
    
    def load_model(self):
        """Load a previously trained model"""
        if os.path.exists(self.model_path):
            try:
                model_data = joblib.load(self.model_path)
                self.model = model_data['model']
                self.scaler = model_data['scaler']
                self.feature_names = model_data['feature_names']
                self.contamination = model_data['contamination']
                self.is_trained = True
                logger.info(f"Model loaded from {self.model_path}")
                return True
            except Exception as e:
                logger.error(f"Error loading model: {e}")
                return False
        return False

# Test function
if __name__ == "__main__":
    # Create and test the anomaly detector
    detector = AnomalyDetector()
    
    # Train the model
    detector.train_model()
    
    # Test with normal traffic
    normal_features = np.array([100, 10, 15, 500, 150, 50000, 0.7, 0.25, 0.05, 0.1, 0.05, 20, 5])
    result = detector.predict(normal_features)
    print("Normal traffic prediction:", result)
    
    # Test with anomalous traffic
    anomaly_features = np.array([500, 2, 50, 100, 50, 25000, 0.9, 0.08, 0.02, 0.01, 0.005, 100, 2])
    result = detector.predict(anomaly_features)
    print("Anomalous traffic prediction:", result)
# End of file

