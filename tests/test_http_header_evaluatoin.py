import unittest
import requests
from unittest.mock import patch
from src.http_header_evaluation import http_header_evaluation

class TestHttpHeaderEvaluation(unittest.TestCase):

    @patch('src.http_header_evaluation.requests.head')
    def test_https_success_with_headers(self, mock_head):
        # Mock successful HTTPS response with Server and X-Powered-By headers
        mock_head.return_value.status_code = 200
        mock_head.return_value.headers = {
            'Server': 'nginx',
            'X-Powered-By': 'PHP/7.4'
        }
        expected = {
            'server_header': 'nginx',
            'powered_by_header': 'PHP/7.4'
        }
        result = http_header_evaluation('example.com')
        self.assertEqual(result, expected)

    @patch('src.http_header_evaluation.requests.head')
    def test_http_fallback_with_no_server_header(self, mock_head):
        # Mock SSL error to test HTTP fallback, without Server header
        mock_head.side_effect = [requests.exceptions.SSLError(), 
                                 unittest.mock.Mock(status_code=200, headers={'X-Powered-By': 'PHP/7.4'})]
        expected = {
            'server_header': 'No Server header found',
            'powered_by_header': 'PHP/7.4'
        }
        result = http_header_evaluation('example.com')
        self.assertEqual(result, expected)

    @patch('src.http_header_evaluation.requests.head')
    def test_connection_timeout_error(self, mock_head):
        # Mock connection timeout error
        mock_head.side_effect = requests.exceptions.Timeout()
        expected = "Error connecting to target"
        result = http_header_evaluation('example.com')
        self.assertEqual(result, expected)

    @patch('src.http_header_evaluation.requests.head')
    def test_non_200_status_code(self, mock_head):
        # Mock receiving non-200 status code
        mock_head.return_value.status_code = 404
        mock_head.return_value.headers = {}
        expected = "Received non-200 status code: 404"
        result = http_header_evaluation('example.com')
        self.assertEqual(result, expected)

if __name__ == '__main__':
    unittest.main()
