import unittest
from unittest.mock import patch, MagicMock
from src.os_detection import os_detection

class TestOSDetection(unittest.TestCase):

    def setUp(self):
        self.ping_output_linux = MagicMock()
        self.ping_output_linux.communicate.return_value = (b'64 bytes from 192.168.1.1: icmp_seq=1 ttl=64', b'')

        self.ping_output_windows = MagicMock()
        self.ping_output_windows.communicate.return_value = (b'64 bytes from 192.168.1.2: icmp_seq=1 ttl=128', b'')

        self.ping_output_unknown = MagicMock()
        self.ping_output_unknown.communicate.return_value = (b'', b'Error')

    @patch('subprocess.Popen')
    def test_linux_os_detection(self, mock_popen):
        mock_popen.return_value = self.ping_output_linux
        result = os_detection('192.168.1.1')
        self.assertEqual(result, 'Linux/Unix')

    @patch('subprocess.Popen')
    def test_windows_os_detection(self, mock_popen):
        mock_popen.return_value = self.ping_output_windows
        result = os_detection('192.168.1.2')
        self.assertEqual(result, 'Windows')

    @patch('subprocess.Popen')
    def test_unknown_os_detection(self, mock_popen):
        mock_popen.return_value = self.ping_output_unknown
        result = os_detection('192.168.1.3')
        self.assertEqual(result, 'Unknown')

if __name__ == '__main__':
    unittest.main()
