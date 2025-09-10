"""
Unit Tests for Network Anomaly Detection Backend Components
"""

import unittest
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import sys
import os

# Ensure repository root on path to import backend package
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from backend.feature_extraction import FeatureExtractor
from backend.anomaly_detector import AnomalyDetector


class TestFeatureExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = FeatureExtractor()

        # Create sample data
        self.sample_data = {
            'timestamp': [datetime.now() - timedelta(seconds=i) for i in range(10, 0, -1)],
            'src_ip': ['192.168.1.1'] * 5 + ['192.168.1.2'] * 5,
            'dst_ip': ['192.168.1.100'] * 10,
            'protocol': [6] * 8 + [17] * 2,  # TCP and UDP
            'packet_size': [500, 600, 450, 700, 550, 400, 650, 500, 300, 800],
            'src_port': [1024, 1025, 1026, 1027, 1028, 2048, 2049, 2050, 2051, 2052],
            'dst_port': [80] * 5 + [443] * 5,
            'flags': ['S'] * 10,
        }
        self.df = pd.DataFrame(self.sample_data)

    def test_extract_basic_features(self):
        """Test basic feature extraction"""
        features = self.extractor.extract_basic_features(self.df)

        self.assertIn('packet_count', features)
        self.assertIn('unique_src_ips', features)
        self.assertIn('avg_packet_size', features)
        self.assertEqual(features['packet_count'], 10)
        self.assertEqual(features['unique_src_ips'], 2)
        self.assertAlmostEqual(features['avg_packet_size'], 555.0)

    def test_extract_temporal_features(self):
        """Test temporal feature extraction"""
        features = self.extractor.extract_temporal_features(self.df)

        self.assertIn('avg_inter_arrival_time', features)
        self.assertIn('std_inter_arrival_time', features)
        self.assertGreater(features['avg_inter_arrival_time'], 0)

    def test_extract_connection_features(self):
        """Test connection-based feature extraction"""
        features = self.extractor.extract_connection_features(self.df)

        self.assertIn('unique_connections', features)
        self.assertIn('avg_packets_per_connection', features)
        self.assertGreater(features['unique_connections'], 0)

    def test_create_feature_vector(self):
        """Test feature vector creation"""
        features = self.extractor.extract_all_features(self.df)
        feature_vector = self.extractor.create_feature_vector(features)

        self.assertIsInstance(feature_vector, np.ndarray)
        self.assertEqual(len(feature_vector), 13)  # Expected number of features
        self.assertTrue(np.all(np.isfinite(feature_vector)))  # No NaN or inf values

    def test_empty_dataframe(self):
        """Test handling of empty dataframe"""
        empty_df = pd.DataFrame()
        features = self.extractor.extract_basic_features(empty_df)

        self.assertEqual(features, {})


class TestAnomalyDetector(unittest.TestCase):
    def setUp(self):
        self.detector = AnomalyDetector(contamination=0.1)

    def test_generate_synthetic_data(self):
        """Test synthetic data generation"""
        data, labels = self.detector.generate_synthetic_data(n_samples=100)

        self.assertIsInstance(data, pd.DataFrame)
        self.assertEqual(len(data), 100)
        self.assertEqual(len(labels), 100)
        self.assertTrue(np.all(np.isin(labels, [1, -1])))  # Only 1 and -1 labels

    def test_model_training(self):
        """Test model training"""
        self.detector.train_model()

        self.assertTrue(self.detector.is_trained)
        self.assertIsNotNone(self.detector.model)
        self.assertIsNotNone(self.detector.scaler)

    def test_prediction(self):
        """Test anomaly prediction"""
        # Train the model first
        self.detector.train_model()

        # Test with normal-looking features
        normal_features = np.array(
            [100, 10, 15, 500, 150, 50000, 0.7, 0.25, 0.05, 0.1, 0.05, 20, 5]
        )
        result = self.detector.predict(normal_features)

        self.assertIn('is_anomaly', result)
        self.assertIn('anomaly_score', result)
        self.assertIn('confidence', result)
        self.assertIn('prediction', result)
        self.assertIsInstance(result['is_anomaly'], bool)
        self.assertIsInstance(result['anomaly_score'], float)

    def test_analyze_features(self):
        """Test feature analysis for attack detection"""
        # Features indicating potential DoS
        dos_features = {
            'packet_count': 500,  # High packet count
            'unique_src_ips': 2,
            'unique_connections': 150,
            'tcp_ratio': 0.95,
        }

        analysis = self.detector.analyze_features(dos_features)

        self.assertIn('attack_types', analysis)
        self.assertIn('severity', analysis)
        self.assertIn('recommendations', analysis)
        self.assertIsInstance(analysis['attack_types'], list)

    def test_model_save_load(self):
        """Test model saving and loading"""
        # Train and save model
        self.detector.train_model()
        original_feature_names = self.detector.feature_names.copy()

        # Create new detector and load model
        new_detector = AnomalyDetector(model_path=self.detector.model_path)
        success = new_detector.load_model()

        self.assertTrue(success)
        self.assertTrue(new_detector.is_trained)
        self.assertEqual(new_detector.feature_names, original_feature_names)


class TestIntegration(unittest.TestCase):
    def setUp(self):
        self.extractor = FeatureExtractor()
        self.detector = AnomalyDetector()
        self.detector.train_model()

    def test_end_to_end_processing(self):
        """Test complete pipeline from data to prediction"""
        # Create sample traffic data
        sample_data = {
            'timestamp': [datetime.now() - timedelta(seconds=i) for i in range(50, 0, -1)],
            'src_ip': ['192.168.1.1'] * 25 + ['192.168.1.2'] * 25,
            'dst_ip': ['192.168.1.100'] * 50,
            'protocol': [6] * 40 + [17] * 10,
            'packet_size': np.random.normal(500, 100, 50),
            'src_port': np.random.randint(1024, 65535, 50),
            'dst_port': [80] * 25 + [443] * 25,
            'flags': ['S'] * 50,
        }
        df = pd.DataFrame(sample_data)

        # Extract features
        features = self.extractor.extract_all_features(df)
        self.assertIsInstance(features, dict)
        self.assertGreater(len(features), 0)

        # Create feature vector
        feature_vector = self.extractor.create_feature_vector(features)
        self.assertIsInstance(feature_vector, np.ndarray)

        # Make prediction
        prediction = self.detector.predict(feature_vector)
        self.assertIn('is_anomaly', prediction)
        self.assertIn('prediction', prediction)

        # Analyze features
        analysis = self.detector.analyze_features(features)
        self.assertIn('attack_types', analysis)
        self.assertIn('severity', analysis)


if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()

    # Add test cases
    test_suite.addTest(unittest.makeSuite(TestFeatureExtractor))
    test_suite.addTest(unittest.makeSuite(TestAnomalyDetector))
    test_suite.addTest(unittest.makeSuite(TestIntegration))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)

    # Print summary
    print(f"\n{'=' * 50}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
  cosine/fix/flake8-warnings-u5qs06
    total_passed = result.testsRun - len(result.failures) - len(result.errors)
    success_pct = (total_passed / result.testsRun * 100) if result.testsRun else 0.0
    print(f"Success rate: {success_pct:.1f}%")
    print(f"{'=' * 50}")

