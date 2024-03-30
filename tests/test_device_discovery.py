import unittest
from unittest.mock import patch, MagicMock
from src.device_discovery import discover_devices

class TestDeviceDiscovery(unittest.TestCase):
    @patch('src.device_discovery.srp')
    @patch('src.device_discovery.socket.socket')
    def test_discover_devices(self, mock_socket, mock_srp):
        # Mock ARP responses
        mock_arp_response = [
            (MagicMock(), MagicMock(psrc="192.168.0.2", hwsrc="aa:bb:cc:dd:ee:ff"))
        ]
        mock_srp.return_value = (mock_arp_response, None)

        # Mock TCP ping (connect_ex)
        mock_tcp_socket_instance = MagicMock()
        mock_tcp_socket_instance.connect_ex.return_value = 0
        mock_socket.return_value = mock_tcp_socket_instance

        # Mock UDP ping
        mock_udp_socket_instance = MagicMock()
        mock_udp_socket_instance.recvfrom.return_value = (b"PONG", "")
        # Differentiate between TCP and UDP socket
        mock_socket.side_effect = [mock_tcp_socket_instance, mock_udp_socket_instance, mock_tcp_socket_instance]

        # Mock ICMP ping
        with patch('src.device_discovery.sr1') as mock_sr1:
            mock_sr1.return_value = MagicMock()

            devices = discover_devices()

            # Validate ARP ping
            self.assertEqual(len(devices), 1)
            self.assertEqual(devices[0]['ip'], '192.168.0.2')
            self.assertEqual(devices[0]['mac'], 'aa:bb:cc:dd:ee:ff')

            # Validate TCP ping
            self.assertTrue(devices[0]['tcp_ping'])

            # Validate UDP ping
            self.assertTrue(devices[0]['udp_ping'])

            # Validate ICMP ping
            self.assertTrue(devices[0]['icmp_ping'])

            # Verify socket operations
            mock_tcp_socket_instance.connect_ex.assert_called_with(('192.168.0.2', 80))
            mock_udp_socket_instance.sendto.assert_called_with(b"PING", ('192.168.0.2', 80))

if __name__ == '__main__':
    unittest.main()
