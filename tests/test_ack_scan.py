import unittest
from unittest.mock import patch, MagicMock
from scapy.layers.inet import TCP
from scapy.packet import Raw
from src.ack_scan import ack_scan

class TestAckScan(unittest.TestCase):

    @patch('src.ack_scan.sr1')
    def test_ack_scan_open_port(self, mock_sr1):
        # Mocking the response for an open port
        mock_response = MagicMock()
        mock_response.haslayer.return_value = True
        mock_response.getlayer.return_value.flags = 0x4  # RST flag
        mock_sr1.return_value = mock_response

        # Call ack_scan
        result = ack_scan("192.168.0.1", [80])

        # Assertions
        self.assertEqual(result, [80])

    @patch('src.ack_scan.sr1')
    def test_ack_scan_closed_port(self, mock_sr1):
        # Mocking the response for a closed port
        mock_sr1.return_value = None

        # Call ack_scan
        result = ack_scan("192.168.0.1", [81])

        # Assertions
        self.assertEqual(result, [])

    @patch('src.ack_scan.sr1')
    def test_ack_scan_with_exception(self, mock_sr1):
        # Mocking sr1 to raise an exception
        mock_sr1.side_effect = Exception("Test Exception")

        # Call ack_scan
        result = ack_scan("192.168.0.1", [82])

        # Assertions
        self.assertIsNone(result)

    @patch('src.ack_scan.sr1')
    def test_ack_scan_with_unfiltered_port(self, mock_sr1):
        """
        Test ACK scan identifies unfiltered (open) ports
        """
        # Mocking the response to simulate an unfiltered port
        mock_response = TCP(flags='R')
        mock_sr1.return_value = mock_response

        # Expecting the port to be identified as unfiltered
        open_ports = ack_scan('192.168.0.1', [80])
        self.assertIn(80, open_ports)

    @patch('src.ack_scan.sr1')
    def test_ack_scan_with_no_response(self, mock_sr1):
        """
        Test ACK scan with no response from the target
        """
        # Simulate no response
        mock_sr1.return_value = None

        # Expecting no open ports
        open_ports = ack_scan('192.168.0.1', [80])
        self.assertEqual(len(open_ports), 0)

    @patch('src.ack_scan.sr1')
    def test_ack_scan_with_exception(self, mock_sr1):
        """
        Test ACK scan handling of exceptions
        """
        # Simulating an exception during the scan
        mock_sr1.side_effect = Exception("Test Exception")

        # Expecting the function to return None
        result = ack_scan('192.168.0.1', [80])
        self.assertIsNone(result)

if __name__ == '__main__':
    unittest.main()
