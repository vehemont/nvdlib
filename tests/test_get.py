import pytest
import requests
import time
from unittest import mock
from unittest.mock import Mock, patch, MagicMock
from json.decoder import JSONDecodeError

from nvdlib.get import __get, __get_with_generator


# Test fixtures
@pytest.fixture
def sample_headers():
    return {'content-type': 'application/json'}


@pytest.fixture
def sample_parameters():
    return {'cveId': 'CVE-2021-12345'}


@pytest.fixture
def sample_response_data():
    return {
        'totalResults': 1,
        'vulnerabilities': [
            {'cve': {'id': 'CVE-2021-12345', 'descriptions': []}}
        ]
    }


@pytest.fixture
def sample_generator_response_data():
    return {
        'totalResults': 1,
        'startIndex': 0,
        'vulnerabilities': [
            {'cve': {'id': 'CVE-2021-12345', 'descriptions': []}}
        ]
    }


# Tests for __get function
@patch('nvdlib.get.time.sleep')
@patch('nvdlib.get.requests.get')
def test_get_successful_request(mock_requests_get, mock_sleep, sample_headers, sample_parameters, sample_response_data):
    """Test successful __get request with valid response."""
    mock_response = Mock()
    mock_response.json.return_value = sample_response_data
    mock_response.raise_for_status.return_value = None
    mock_response.encoding = 'utf-8'
    mock_requests_get.return_value = mock_response

    result = __get('cve', sample_headers, sample_parameters)

    assert result == sample_response_data
    mock_requests_get.assert_called_once()
    mock_response.raise_for_status.assert_called_once()
    mock_sleep.assert_called_once_with(6)  # Default delay


@patch('nvdlib.get.time.sleep')
@patch('nvdlib.get.requests.get')
def test_get_handles_json_decode_error(mock_requests_get, mock_sleep, sample_headers, sample_parameters):
    """Test that __get handles JSONDecodeError from Response.json() cleanly."""
    mock_response = Mock()
    mock_response.json.side_effect = JSONDecodeError("Invalid JSON", "doc", 0)
    mock_response.raise_for_status.return_value = None
    mock_response.encoding = 'utf-8'
    mock_requests_get.return_value = mock_response

    with patch('nvdlib.get.logger.error') as mock_logger:
        result = __get('cve', sample_headers, sample_parameters)

    assert result is None  # Should return None on JSONDecodeError
    mock_logger.assert_called()  # Should log the error
    mock_sleep.assert_not_called()  # Should not sleep if JSON parsing fails


@patch('nvdlib.get.time.sleep')
@patch('nvdlib.get.requests.get')
def test_get_handles_http_errors(mock_requests_get, mock_sleep, sample_headers, sample_parameters):
    """Test that __get handles HTTP errors properly."""
    mock_response = Mock()
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("404 Not Found")
    mock_response.encoding = 'utf-8'
    mock_requests_get.return_value = mock_response

    with pytest.raises(requests.exceptions.HTTPError):
        __get('cve', sample_headers, sample_parameters)

    mock_requests_get.assert_called_once()
    mock_response.raise_for_status.assert_called_once()


@patch('nvdlib.get.time.sleep')
@patch('nvdlib.get.requests.get')
def test_get_handles_api_error_message(mock_requests_get, mock_sleep, sample_headers, sample_parameters):
    """Test that __get handles API error messages by raising LookupError."""
    error_response = {'message': 'Invalid request parameters'}
    mock_response = Mock()
    mock_response.json.return_value = error_response
    mock_response.raise_for_status.return_value = None
    mock_response.encoding = 'utf-8'
    mock_requests_get.return_value = mock_response

    with pytest.raises(LookupError, match="Invalid request parameters"):
        __get('cve', sample_headers, sample_parameters)


@patch('nvdlib.get.time.sleep')
@patch('nvdlib.get.requests.get')
def test_get_different_product_types(mock_requests_get, mock_sleep, sample_headers, sample_parameters, sample_response_data):
    """Test __get with different product types (cve, cpe, cpeMatch)."""
    mock_response = Mock()
    mock_response.json.return_value = sample_response_data
    mock_response.raise_for_status.return_value = None
    mock_response.encoding = 'utf-8'
    mock_requests_get.return_value = mock_response

    # Test CVE
    __get('cve', sample_headers, sample_parameters)
    call_args = mock_requests_get.call_args[0]
    assert 'cves/2.0' in call_args[0]

    # Test CPE
    __get('cpe', sample_headers, sample_parameters)
    call_args = mock_requests_get.call_args[0]
    assert 'cpes/2.0' in call_args[0]

    # Test CPE Match
    __get('cpeMatch', sample_headers, sample_parameters)
    call_args = mock_requests_get.call_args[0]
    assert 'cpematch/2.0' in call_args[0]


@patch('nvdlib.get.time.sleep')
@patch('nvdlib.get.requests.get')
def test_get_with_limit_parameter(mock_requests_get, mock_sleep, sample_headers, sample_parameters, sample_response_data):
    """Test __get with limit parameter."""
    mock_response = Mock()
    mock_response.json.return_value = sample_response_data
    mock_response.raise_for_status.return_value = None
    mock_response.encoding = 'utf-8'
    mock_requests_get.return_value = mock_response

    result = __get('cve', sample_headers, sample_parameters, limit=100)

    assert result == sample_response_data
    mock_requests_get.assert_called_once()


@patch('nvdlib.get.time.sleep')
@patch('nvdlib.get.requests.get')
def test_get_with_custom_delay(mock_requests_get, mock_sleep, sample_headers, sample_parameters, sample_response_data):
    """Test __get with custom delay parameter."""
    mock_response = Mock()
    mock_response.json.return_value = sample_response_data
    mock_response.raise_for_status.return_value = None
    mock_response.encoding = 'utf-8'
    mock_requests_get.return_value = mock_response

    __get('cve', sample_headers, sample_parameters, delay=3.0)

    mock_sleep.assert_called_once_with(3.0)


@patch('nvdlib.get.time.sleep')
@patch('nvdlib.get.requests.get')
def test_get_with_proxies(mock_requests_get, mock_sleep, sample_headers, sample_parameters, sample_response_data):
    """Test __get with proxies parameter."""
    mock_response = Mock()
    mock_response.json.return_value = sample_response_data
    mock_response.raise_for_status.return_value = None
    mock_response.encoding = 'utf-8'
    mock_requests_get.return_value = mock_response

    proxies = {'http': 'http://proxy.example.com:8080'}
    __get('cve', sample_headers, sample_parameters, proxies=proxies)

    mock_requests_get.assert_called_once()
    call_kwargs = mock_requests_get.call_args[1]
    assert call_kwargs['proxies'] == proxies


@patch('nvdlib.get.time.sleep')
@patch('nvdlib.get.requests.get')
def test_get_pagination_logic(mock_requests_get, mock_sleep, sample_headers, sample_parameters):
    """Test __get pagination when totalResults > 2000."""
    # First response with totalResults > 2000
    first_response_data = {
        'totalResults': 3000,
        'vulnerabilities': [{'cve': {'id': f'CVE-2021-{i}'}} for i in range(2000)]
    }
    
    # Second response for pagination
    second_response_data = {
        'vulnerabilities': [{'cve': {'id': f'CVE-2021-{i}'}} for i in range(2000, 3000)]
    }

    mock_first_response = Mock()
    mock_first_response.json.return_value = first_response_data
    mock_first_response.raise_for_status.return_value = None
    mock_first_response.encoding = 'utf-8'

    mock_second_response = Mock()
    mock_second_response.json.return_value = second_response_data
    mock_second_response.raise_for_status.return_value = None
    mock_second_response.encoding = 'utf-8'

    mock_requests_get.side_effect = [mock_first_response, mock_second_response]

    result = __get('cve', sample_headers, sample_parameters)

    assert len(result['vulnerabilities']) == 3000  # Combined results
    assert mock_requests_get.call_count == 2  # Two requests for pagination
    assert mock_sleep.call_count == 2  # Sleep after each request


# Tests for __get_with_generator function
@patch('nvdlib.get.time.sleep')
@patch('nvdlib.get.requests.get')
def test_get_with_generator_successful(mock_requests_get, mock_sleep, sample_headers, sample_parameters, sample_generator_response_data):
    """Test successful __get_with_generator request."""
    mock_response = Mock()
    mock_response.json.return_value = sample_generator_response_data
    mock_response.status_code = 200
    mock_response.raise_for_status.return_value = None
    mock_response.encoding = 'utf-8'
    mock_requests_get.return_value = mock_response

    generator = __get_with_generator('cve', sample_headers, sample_parameters, limit=1)
    results = list(generator)

    assert len(results) == 1
    assert results[0] == sample_generator_response_data
    mock_requests_get.assert_called_once()


@patch('nvdlib.get.time.sleep')
@patch('nvdlib.get.requests.get')
def test_get_with_generator_handles_json_decode_error(mock_requests_get, mock_sleep, sample_headers, sample_parameters):
    """Test that __get_with_generator handles JSONDecodeError cleanly."""
    # Create a mock that is an instance of requests.Response
    mock_response = Mock(spec=requests.Response)
    mock_response.json.side_effect = JSONDecodeError("Invalid JSON", "doc", 0)
    mock_response.status_code = 200
    mock_response.raise_for_status.return_value = None
    mock_response.encoding = 'utf-8'
    mock_requests_get.return_value = mock_response

    with patch('nvdlib.get.logger.error') as mock_logger:
        generator = __get_with_generator('cve', sample_headers, sample_parameters, limit=1)
        results = list(generator)

    assert len(results) == 0  # Should not yield anything on JSONDecodeError
    mock_logger.assert_called()  # Should log the error


@patch('nvdlib.get.time.sleep')
@patch('nvdlib.get.requests.get')
def test_get_with_generator_handles_rate_limiting(mock_requests_get, mock_sleep, sample_headers, sample_parameters, sample_generator_response_data):
    """Test that __get_with_generator handles 403 rate limiting with exponential backoff."""
    # First response: 403 rate limit
    mock_rate_limit_response = Mock()
    mock_rate_limit_response.status_code = 403
    mock_rate_limit_response.raise_for_status.return_value = None
    mock_rate_limit_response.encoding = 'utf-8'

    # Second response: Success
    mock_success_response = Mock()
    mock_success_response.status_code = 200
    mock_success_response.json.return_value = sample_generator_response_data
    mock_success_response.raise_for_status.return_value = None
    mock_success_response.encoding = 'utf-8'

    mock_requests_get.side_effect = [mock_rate_limit_response, mock_success_response]

    with patch('nvdlib.get.logger.error') as mock_logger:
        generator = __get_with_generator('cve', sample_headers, sample_parameters, limit=1)
        results = list(generator)

    assert len(results) == 1
    assert mock_requests_get.call_count == 2  # Retry after 403
    mock_logger.assert_called()  # Should log rate limit error
    mock_sleep.assert_called()  # Should sleep during retry


@patch('nvdlib.get.time.sleep')
@patch('nvdlib.get.requests.get')
def test_get_with_generator_pagination(mock_requests_get, mock_sleep, sample_headers, sample_parameters):
    """Test __get_with_generator pagination logic."""
    # First batch
    first_batch = {
        'totalResults': 3000,
        'startIndex': 0,
        'vulnerabilities': [{'cve': {'id': f'CVE-2021-{i}'}} for i in range(2000)]
    }
    
    # Second batch
    second_batch = {
        'totalResults': 3000,
        'startIndex': 2000,
        'vulnerabilities': [{'cve': {'id': f'CVE-2021-{i}'}} for i in range(2000, 3000)]
    }

    mock_first_response = Mock()
    mock_first_response.status_code = 200
    mock_first_response.json.return_value = first_batch
    mock_first_response.raise_for_status.return_value = None
    mock_first_response.encoding = 'utf-8'

    mock_second_response = Mock()
    mock_second_response.status_code = 200
    mock_second_response.json.return_value = second_batch
    mock_second_response.raise_for_status.return_value = None
    mock_second_response.encoding = 'utf-8'

    mock_requests_get.side_effect = [mock_first_response, mock_second_response]

    generator = __get_with_generator('cve', sample_headers, sample_parameters, limit=None)
    results = list(generator)

    assert len(results) == 2  # Two batches
    assert mock_requests_get.call_count == 2
    assert mock_sleep.call_count == 1  # Sleep between batches


@patch('nvdlib.get.time.sleep')
@patch('nvdlib.get.requests.get')
def test_get_with_generator_with_proxies(mock_requests_get, mock_sleep, sample_headers, sample_parameters, sample_generator_response_data):
    """Test __get_with_generator with proxies parameter."""
    mock_response = Mock()
    mock_response.json.return_value = sample_generator_response_data
    mock_response.status_code = 200
    mock_response.raise_for_status.return_value = None
    mock_response.encoding = 'utf-8'
    mock_requests_get.return_value = mock_response

    proxies = {'http': 'http://proxy.example.com:8080'}
    generator = __get_with_generator('cve', sample_headers, sample_parameters, 
                                   limit=1, proxies=proxies)
    list(generator)  # Consume generator

    mock_requests_get.assert_called_once()
    call_kwargs = mock_requests_get.call_args[1]
    assert call_kwargs['proxies'] == proxies


@patch('nvdlib.get.time.sleep')
@patch('nvdlib.get.requests.get')
def test_get_with_generator_different_products(mock_requests_get, mock_sleep, sample_headers, sample_parameters, sample_generator_response_data):
    """Test __get_with_generator with different product types."""
    mock_response = Mock()
    mock_response.json.return_value = sample_generator_response_data  
    mock_response.status_code = 200
    mock_response.raise_for_status.return_value = None
    mock_response.encoding = 'utf-8'
    mock_requests_get.return_value = mock_response

    # Test CPE product type
    generator = __get_with_generator('cpe', sample_headers, sample_parameters, limit=1)
    list(generator)

    call_args = mock_requests_get.call_args[0]
    assert 'cpes/2.0' in call_args[0]