import re
import pandas as pd
from datetime import datetime

class LogParser:
    """Utilities for parsing system and web logs into structured data."""
    
    @staticmethod
    def parse_auth_log(log_lines):
        """
        Parses SSH auth.log entries.
        Example: May  3 10:12:01 server sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 54321 ssh2
        """
        parsed_data = []
        pattern = r'(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<process>sshd)\[\d+\]:\s+(?P<message>.*)'
        
        for line in log_lines:
            match = re.search(pattern, line)
            if match:
                msg = match.group('message')
                ip_match = re.search(r'from\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', msg)
                user_match = re.search(r'for\s+(invalid user\s+)?(?P<user>\S+)', msg)
                
                parsed_data.append({
                    'timestamp': match.group('timestamp'),
                    'source': 'auth.log',
                    'ip': ip_match.group('ip') if ip_match else 'unknown',
                    'user': user_match.group('user') if user_match else 'unknown',
                    'event': 'Failed Login' if 'Failed password' in msg else 'Info',
                    'raw': line.strip()
                })
        return pd.DataFrame(parsed_data, columns=['timestamp', 'source', 'ip', 'user', 'event', 'raw'])

    @staticmethod
    def parse_access_log(log_lines):
        """
        Parses Apache/Nginx access.log entries.
        Example: 127.0.0.1 - - [03/May/2026:10:15:20 +0000] "GET /admin' OR '1'='1 HTTP/1.1" 404 154
        """
        parsed_data = []
        pattern = r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*\[(?P<timestamp>.*)\].*"(?P<request>.*)"\s+(?P<status>\d+)'
        
        for line in log_lines:
            match = re.search(pattern, line)
            if match:
                request = match.group('request')
                # Simple heuristic for common web attacks
                event = 'Potential SQLi' if "SELECT" in request.upper() or "'" in request else 'Web Request'
                if "../" in request: event = 'Path Traversal'
                
                parsed_data.append({
                    'timestamp': match.group('timestamp'),
                    'source': 'access.log',
                    'ip': match.group('ip'),
                    'request': request,
                    'status': match.group('status'),
                    'event': event,
                    'raw': line.strip()
                })
        return pd.DataFrame(parsed_data, columns=['timestamp', 'source', 'ip', 'request', 'status', 'event', 'raw'])
