"""
SENTINEL Test Configuration

This module contains pytest fixtures and configuration for testing the SENTINEL platform.
"""
import pytest
import os
import sys
from unittest.mock import MagicMock, patch

# Add the project root to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


@pytest.fixture(scope='session')
def app_config():
    """Return test configuration."""
    return {
        'TESTING': True,
        'DEBUG': False,
        'SECRET_KEY': 'test-secret-key-do-not-use-in-production',
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'REDIS_URL': 'redis://localhost:6379/1',
        'JWT_SECRET_KEY': 'test-jwt-secret-key',
    }


@pytest.fixture
def mock_redis():
    """Create a mock Redis client for testing."""
    with patch('redis.from_url') as mock:
        mock_client = MagicMock()
        mock.return_value = mock_client
        
        # Configure common Redis methods
        mock_client.get.return_value = None
        mock_client.set.return_value = True
        mock_client.setex.return_value = True
        mock_client.incr.return_value = 1
        mock_client.expire.return_value = True
        mock_client.keys.return_value = []
        mock_client.hgetall.return_value = {}
        mock_client.hmset.return_value = True
        mock_client.hset.return_value = True
        mock_client.sadd.return_value = 1
        mock_client.smembers.return_value = set()
        mock_client.sinter.return_value = set()
        mock_client.scard.return_value = 0
        mock_client.srem.return_value = 1
        
        yield mock_client


@pytest.fixture
def mock_kafka_producer():
    """Create a mock Kafka producer for testing."""
    with patch('kafka.KafkaProducer') as mock:
        mock_producer = MagicMock()
        mock.return_value = mock_producer
        mock_producer.send.return_value = MagicMock()
        yield mock_producer


@pytest.fixture
def sample_user_data():
    """Return sample user data for testing."""
    return {
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'SecurePassword123!',
        'role': 'security_analyst'
    }


@pytest.fixture
def sample_alert_data():
    """Return sample alert data for testing."""
    return {
        'type': 'network_anomaly',
        'severity': 'high',
        'description': 'Test alert description',
        'details': {
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'port': 443
        }
    }


@pytest.fixture
def sample_threat_data():
    """Return sample threat data for testing."""
    return {
        'type': 'brute_force',
        'severity': 'critical',
        'timestamp': '2024-01-15T10:30:00Z',
        'details': {
            'source_ip': '192.168.1.200',
            'attempts': 50,
            'target': 'auth-service'
        }
    }


@pytest.fixture
def auth_headers():
    """Return authentication headers for testing."""
    return {
        'Authorization': 'Bearer test-jwt-token',
        'Content-Type': 'application/json'
    }


@pytest.fixture(autouse=True)
def reset_environment():
    """Reset environment variables before each test."""
    original_env = os.environ.copy()
    
    # Set test environment variables
    os.environ['FLASK_DEBUG'] = 'false'
    os.environ['JWT_SECRET_KEY'] = 'test-secret-key'
    
    yield
    
    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)


class MockResponse:
    """Mock HTTP response for testing requests."""
    
    def __init__(self, json_data, status_code=200):
        self.json_data = json_data
        self.status_code = status_code
    
    def json(self):
        return self.json_data


@pytest.fixture
def mock_requests():
    """Create mock requests module for testing HTTP calls."""
    with patch('requests.get') as mock_get, \
         patch('requests.post') as mock_post, \
         patch('requests.put') as mock_put, \
         patch('requests.delete') as mock_delete:
        
        mocks = {
            'get': mock_get,
            'post': mock_post,
            'put': mock_put,
            'delete': mock_delete
        }
        
        yield mocks
