import unittest
import requests
from unittest.mock import patch, MagicMock
from src.banner_grabbing import banner_grabbing

class TestBannerGrabbing(unittest.TestCase):

    @patch('src.banner_grabbing.ssl.create_default_context')
    @patch('socket.socket')
    @patch('src.banner_grabbing.requests.get')
    def test_https_banner_grabbing_success(self, mock_requests_get, mock_socket, mock_create_default_context):
        # Mocking SSL context and socket
        mock_context = MagicMock()
        mock_create_default_context.return_value = mock_context
        mock_socket.return_value = mock_socket

        # Mocking successful SSL connection
        mock_ssl_socket = MagicMock()
        mock_context.wrap_socket.return_value = mock_ssl_socket

        # Mocking successful requests.get
        mock_response = MagicMock()
        mock_response.headers.get.return_value = "Apache"
        mock_requests_get.return_value = mock_response

        result = banner_grabbing("example.com", 443)

        mock_create_default_context.assert_called_once()
        mock_socket.assert_called_once()
        mock_context.wrap_socket.assert_called_once_with(mock_socket, server_hostname="example.com")
        mock_response.headers.get.assert_called_once_with("Server")

        # Check whether wrap_socket was called without specifying do_handshake_on_connect
        mock_context.wrap_socket.assert_called_once_with(mock_socket, server_hostname="example.com", **{})

        self.assertEqual(result, "Apache")


    @patch('src.banner_grabbing.requests.get')
    def test_http_banner_grabbing_success(self, mock_requests_get):
        # Mocking successful HTTP requests.get
        mock_response = MagicMock()
        mock_response.headers.get.return_value = "Nginx"
        mock_requests_get.return_value = mock_response

        result = banner_grabbing("example.com", 80)

        mock_requests_get.assert_called_once_with("http://example.com", timeout=5, cert=None)
        mock_response.headers.get.assert_called_once_with("Server")

        self.assertEqual(result, "Nginx")

    @patch('src.banner_grabbing.requests.get')
    def test_banner_grabbing_no_server_header(self, mock_requests_get):
        # Mocking HTTP requests.get with no Server header
        mock_response = MagicMock()
        mock_response.headers.get.return_value = None
        mock_requests_get.return_value = mock_response

        result = banner_grabbing("example.com", 80)

        mock_requests_get.assert_called_once_with("http://example.com", timeout=5, cert=None)
        mock_response.headers.get.assert_called_once_with("Server")

        self.assertEqual(result, "No Server header found")

    @patch('src.banner_grabbing.requests.get', side_effect=requests.RequestException("Connection error"))
    def test_banner_grabbing_connection_error(self, mock_requests_get):
        # Mocking requests.get with a connection error
        result = banner_grabbing("example.com", 80)

        mock_requests_get.assert_called_once_with("http://example.com", timeout=5, cert=None)

        self.assertEqual(result, "Error connecting to target: Connection error")

    @patch('src.banner_grabbing.ssl.create_default_context', side_effect=Exception("SSL error"))
    def test_banner_grabbing_ssl_error(self, mock_create_default_context):
        # Mocking SSL context creation with an error
        result = banner_grabbing("example.com", 443)

        mock_create_default_context.assert_called_once()

        self.assertEqual(result, "Unexpected error: SSL error")


if __name__ == '__main__':
    unittest.main()
