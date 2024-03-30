import unittest
from unittest.mock import patch
from src.enumerate import syn_scan, tcp_connect_scan

class TestPortScanning(unittest.TestCase):

    @patch('src.enumerate.sr1')
    def test_syn_scan_open_port(self, mock_sr1):
        mock_response = unittest.mock.Mock()
        mock_response.haslayer.return_value = True
        mock_response.getlayer.return_value.flags = 0x12  # SYN-ACK flags
        mock_sr1.return_value = mock_response

        ip = "192.168.1.1"
        ports = [22]
        result = syn_scan(ip, ports)
        self.assertIn(22, result)

    @patch('src.enumerate.sr1')
    def test_syn_scan_closed_port(self, mock_sr1):
        mock_sr1.return_value = None

        ip = "192.168.1.1"
        ports = [23]
        result = syn_scan(ip, ports)
        self.assertNotIn(23, result)

    @patch('socket.socket')
    def test_tcp_connect_scan_open_port(self, mock_socket):
        mock_sock_instance = mock_socket.return_value
        mock_sock_instance.connect_ex.return_value = 0  # No error

        ip = "192.168.1.1"
        ports = [80]
        result = tcp_connect_scan(ip, ports)
        self.assertIn(80, result)

    @patch('socket.socket')
    def test_tcp_connect_scan_closed_port(self, mock_socket):
        mock_sock_instance = mock_socket.return_value
        mock_sock_instance.connect_ex.return_value = 1  # Simulate a closed port

        ip = "192.168.1.1"
        ports = [81]
        result = tcp_connect_scan(ip, ports)
        self.assertNotIn(81, result)

if __name__ == '__main__':
    unittest.main()
