"""
Deep Learning Attack Detection Module
Implements LSTM-based temporal analysis for advanced attack detection
"""

import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import logging
import pickle
import os
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class LSTMAttackDetector:
    def __init__(self, sequence_length=50, model_path='lstm_model.h5'):
        """
        Initialize LSTM-based attack detector
        
        Args:
            sequence_length (int): Length of sequence for temporal analysis
            model_path (str): Path to save/load the trained model
        """
        self.sequence_length = sequence_length
        self.model_path = model_path
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.model = None
        self.is_trained = False
        self.feature_names = []
        
    def create_lstm_model(self, input_shape, num_classes):
        """Create LSTM model architecture"""
        model = keras.Sequential([
            layers.LSTM(128, return_sequences=True, input_shape=input_shape),
            layers.Dropout(0.3),
            layers.LSTM(64, return_sequences=True),
            layers.Dropout(0.3),
            layers.LSTM(32),
            layers.Dropout(0.3),
            layers.Dense(64, activation='relu'),
            layers.Dropout(0.2),
            layers.Dense(32, activation='relu'),
            layers.Dense(num_classes, activation='softmax')
        ])
        
        model.compile(
            optimizer='adam',
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def generate_advanced_training_data(self, n_samples=5000):
        """Generate synthetic training data for various attack types"""
        np.random.seed(42)
        
        # Define attack types
        attack_types = ['normal', 'dos', 'port_scan', 'apt', 'sql_injection', 'xss', 'botnet']
        
        all_sequences = []
        all_labels = []
        
        for attack_type in attack_types:
            for _ in range(n_samples // len(attack_types)):
                sequence = self._generate_attack_sequence(attack_type)
                all_sequences.append(sequence)
                all_labels.append(attack_type)
        
        return np.array(all_sequences), np.array(all_labels)
    
    def _generate_attack_sequence(self, attack_type):
        """Generate a sequence of network features for specific attack type"""
        sequence = []
        
        for i in range(self.sequence_length):
            if attack_type == 'normal':
                features = self._generate_normal_features()
            elif attack_type == 'dos':
                features = self._generate_dos_features(i)
            elif attack_type == 'port_scan':
                features = self._generate_port_scan_features(i)
            elif attack_type == 'apt':
                features = self._generate_apt_features(i)
            elif attack_type == 'sql_injection':
                features = self._generate_sql_injection_features(i)
            elif attack_type == 'xss':
                features = self._generate_xss_features(i)
            elif attack_type == 'botnet':
                features = self._generate_botnet_features(i)
            
            sequence.append(features)
        
        return np.array(sequence)
    
    def _generate_normal_features(self):
        """Generate normal traffic features"""
        return [
            np.random.normal(100, 20),      # packet_count
            np.random.normal(10, 3),        # unique_src_ips
            np.random.normal(15, 4),        # unique_dst_ips
            np.random.normal(500, 100),     # avg_packet_size
            np.random.normal(0.7, 0.1),     # tcp_ratio
            np.random.normal(0.25, 0.08),   # udp_ratio
            np.random.normal(0.1, 0.05),    # avg_inter_arrival_time
            np.random.normal(20, 5),        # unique_connections
            np.random.normal(80, 10),       # avg_dst_port
            np.random.normal(0, 0.1),       # syn_flag_ratio
            np.random.normal(0, 0.1),       # rst_flag_ratio
            np.random.normal(50000, 10000), # total_bytes
        ]
    
    def _generate_dos_features(self, time_step):
        """Generate DoS attack features with temporal progression"""
        intensity = min(1.0, time_step / (self.sequence_length * 0.3))
        
        return [
            np.random.normal(500 * (1 + intensity), 100),  # High packet count
            np.random.normal(2, 1),                        # Few source IPs
            np.random.normal(1, 0.5),                      # Single target
            np.random.normal(64, 20),                      # Small packets
            np.random.normal(0.95, 0.02),                  # Mostly TCP
            np.random.normal(0.05, 0.02),                  # Little UDP
            np.random.normal(0.001, 0.0005),               # Very fast packets
            np.random.normal(1, 0.5),                      # Few connections
            np.random.normal(80, 5),                       # Target port
            np.random.normal(0.8 * intensity, 0.1),        # High SYN ratio
            np.random.normal(0.1, 0.05),                   # Some RST
            np.random.normal(32000 * (1 + intensity), 5000), # High traffic
        ]
    
    def _generate_port_scan_features(self, time_step):
        """Generate port scan features"""
        return [
            np.random.normal(200, 50),                     # Moderate packet count
            np.random.normal(1, 0.2),                      # Single source
            np.random.normal(1, 0.2),                      # Single target
            np.random.normal(40, 10),                      # Small packets
            np.random.normal(0.9, 0.05),                   # Mostly TCP
            np.random.normal(0.1, 0.05),                   # Some UDP
            np.random.normal(0.01, 0.005),                 # Fast scanning
            np.random.normal(100 + time_step * 2, 20),     # Many connections
            np.random.normal(1024 + time_step * 50, 100),  # Sequential ports
            np.random.normal(0.7, 0.1),                    # High SYN ratio
            np.random.normal(0.3, 0.1),                    # High RST ratio
            np.random.normal(8000, 2000),                  # Low traffic volume
        ]
    
    def _generate_apt_features(self, time_step):
        """Generate APT (Advanced Persistent Threat) features"""
        # APT is stealthy and low-volume
        return [
            np.random.normal(50, 15),                      # Low packet count
            np.random.normal(5, 2),                        # Few sources
            np.random.normal(10, 3),                       # Multiple targets
            np.random.normal(800, 200),                    # Larger packets
            np.random.normal(0.6, 0.1),                    # Mixed protocols
            np.random.normal(0.3, 0.1),                    # Some UDP
            np.random.normal(5, 2),                        # Slow, patient
            np.random.normal(15, 5),                       # Few connections
            np.random.normal(443, 50),                     # HTTPS/encrypted
            np.random.normal(0.2, 0.1),                    # Low SYN ratio
            np.random.normal(0.1, 0.05),                   # Low RST ratio
            np.random.normal(40000, 10000),                # Moderate traffic
        ]
    
    def _generate_sql_injection_features(self, time_step):
        """Generate SQL injection attack features"""
        return [
            np.random.normal(80, 20),                      # Moderate packets
            np.random.normal(3, 1),                        # Few sources
            np.random.normal(2, 1),                        # Few targets
            np.random.normal(1200, 300),                   # Large packets (SQL)
            np.random.normal(0.8, 0.1),                    # Mostly TCP
            np.random.normal(0.2, 0.1),                    # Some UDP
            np.random.normal(0.5, 0.2),                    # Moderate timing
            np.random.normal(5, 2),                        # Few connections
            np.random.normal(80, 10),                      # HTTP port
            np.random.normal(0.3, 0.1),                    # Moderate SYN
            np.random.normal(0.1, 0.05),                   # Low RST
            np.random.normal(96000, 20000),                # High payload
        ]
    
    def _generate_xss_features(self, time_step):
        """Generate XSS attack features"""
        return [
            np.random.normal(60, 15),                      # Low-moderate packets
            np.random.normal(2, 1),                        # Few sources
            np.random.normal(1, 0.5),                      # Single target
            np.random.normal(900, 200),                    # Medium packets
            np.random.normal(0.85, 0.05),                  # Mostly TCP
            np.random.normal(0.15, 0.05),                  # Little UDP
            np.random.normal(0.3, 0.1),                    # Quick bursts
            np.random.normal(3, 1),                        # Few connections
            np.random.normal(80, 5),                       # HTTP port
            np.random.normal(0.4, 0.1),                    # Moderate SYN
            np.random.normal(0.1, 0.05),                   # Low RST
            np.random.normal(54000, 15000),                # Moderate traffic
        ]
    
    def _generate_botnet_features(self, time_step):
        """Generate botnet communication features"""
        return [
            np.random.normal(30, 10),                      # Low packet count
            np.random.normal(20, 5),                       # Many sources (bots)
            np.random.normal(2, 1),                        # Few C&C servers
            np.random.normal(200, 50),                     # Small packets
            np.random.normal(0.7, 0.1),                    # Mixed protocols
            np.random.normal(0.3, 0.1),                    # Some UDP
            np.random.normal(30, 10),                      # Periodic beacons
            np.random.normal(25, 5),                       # Many connections
            np.random.normal(8080, 100),                   # Non-standard ports
            np.random.normal(0.3, 0.1),                    # Low SYN ratio
            np.random.normal(0.1, 0.05),                   # Low RST ratio
            np.random.normal(6000, 2000),                  # Low traffic volume
        ]
    
    def prepare_sequences(self, data, labels):
        """Prepare data sequences for LSTM training"""
        # Encode labels
        encoded_labels = self.label_encoder.fit_transform(labels)
        
        # Scale features
        n_samples, seq_len, n_features = data.shape
        data_reshaped = data.reshape(-1, n_features)
        data_scaled = self.scaler.fit_transform(data_reshaped)
        data_scaled = data_scaled.reshape(n_samples, seq_len, n_features)
        
        return data_scaled, encoded_labels
    
    def train_model(self, epochs=50, batch_size=32):
        """Train the LSTM model"""
        logger.info("Generating training data for LSTM model...")
        
        # Generate training data
        X, y = self.generate_advanced_training_data()
        
        # Prepare sequences
        X_scaled, y_encoded = self.prepare_sequences(X, y)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y_encoded, test_size=0.2, random_state=42
        )
        
        # Create model
        input_shape = (X_train.shape[1], X_train.shape[2])
        num_classes = len(np.unique(y_encoded))
        
        self.model = self.create_lstm_model(input_shape, num_classes)
        
        logger.info(f"Training LSTM model with {len(X_train)} samples...")
        
        # Train model
        history = self.model.fit(
            X_train, y_train,
            epochs=epochs,
            batch_size=batch_size,
            validation_data=(X_test, y_test),
            verbose=1
        )
        
        # Evaluate model
        test_loss, test_accuracy = self.model.evaluate(X_test, y_test, verbose=0)
        logger.info(f"Test accuracy: {test_accuracy:.4f}")
        
        self.is_trained = True
        self.save_model()
        
        return history
    
    def predict_sequence(self, sequence):
        """Predict attack type for a sequence of network features"""
        if not self.is_trained:
            logger.warning("Model not trained. Loading or training model...")
            if not self.load_model():
                self.train_model()
        
        # Ensure sequence has correct shape
        if len(sequence.shape) == 2:
            sequence = sequence.reshape(1, sequence.shape[0], sequence.shape[1])
        
        # Scale the sequence
        n_samples, seq_len, n_features = sequence.shape
        sequence_reshaped = sequence.reshape(-1, n_features)
        sequence_scaled = self.scaler.transform(sequence_reshaped)
        sequence_scaled = sequence_scaled.reshape(n_samples, seq_len, n_features)
        
        # Make prediction
        predictions = self.model.predict(sequence_scaled, verbose=0)
        predicted_class = np.argmax(predictions[0])
        confidence = np.max(predictions[0])
        
        # Decode prediction
        attack_type = self.label_encoder.inverse_transform([predicted_class])[0]
        
        result = {
            'attack_type': attack_type,
            'confidence': float(confidence),
            'is_attack': attack_type != 'normal',
            'probabilities': {
                self.label_encoder.inverse_transform([i])[0]: float(prob)
                for i, prob in enumerate(predictions[0])
            },
            'timestamp': datetime.now()
        }
        
        return result
    
    def save_model(self):
        """Save the trained model and preprocessing objects"""
        if self.model is not None:
            # Save model
            self.model.save(self.model_path)
            
            # Save preprocessing objects
            preprocessing_path = self.model_path.replace('.h5', '_preprocessing.pkl')
            with open(preprocessing_path, 'wb') as f:
                pickle.dump({
                    'scaler': self.scaler,
                    'label_encoder': self.label_encoder,
                    'sequence_length': self.sequence_length
                }, f)
            
            logger.info(f"LSTM model saved to {self.model_path}")
    
    def load_model(self):
        """Load a previously trained model"""
        if os.path.exists(self.model_path):
            try:
                # Load model
                self.model = keras.models.load_model(self.model_path)
                
                # Load preprocessing objects
                preprocessing_path = self.model_path.replace('.h5', '_preprocessing.pkl')
                with open(preprocessing_path, 'rb') as f:
                    preprocessing = pickle.load(f)
                    self.scaler = preprocessing['scaler']
                    self.label_encoder = preprocessing['label_encoder']
                    self.sequence_length = preprocessing['sequence_length']
                
                self.is_trained = True
                logger.info(f"LSTM model loaded from {self.model_path}")
                return True
            except Exception as e:
                logger.error(f"Error loading LSTM model: {e}")
                return False
        return False

# Test function
if __name__ == "__main__":
    # Create and test the LSTM detector
    detector = LSTMAttackDetector()
    
    # Train the model (this will take some time)
    print("Training LSTM model...")
    detector.train_model(epochs=10)  # Reduced epochs for testing
    
    # Test with a sample sequence
    print("Testing prediction...")
    test_sequence = detector._generate_attack_sequence('dos')
    result = detector.predict_sequence(test_sequence)
    print("Prediction result:", result)
# End of file

