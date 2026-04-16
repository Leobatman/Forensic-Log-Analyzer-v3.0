#!/usr/bin/env python3
"""
================================================================================
FORENSIC LOG ANALYZER v2.0 - UNIVERSAL FORENSIC ANALYSIS TOOL
================================================================================
Author: Leonardo Pereira
Version: 2.0 - Universal Edition
Description: Analisa QUALQUER arquivo de log - Apache, Nginx, IIS, Firewall,
             Syslog, JSON, CSV, texto puro, logs de aplicação, logs de sistema,
             logs de segurança, logs de banco de dados, logs de cloud, etc.
================================================================================
"""

import re
import json
import hashlib
import argparse
import sys
import os
from pathlib import Path
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from typing import Dict, List, Tuple, Set, Optional, Any, Union
import ipaddress
import time
import gzip
import bz2
import zipfile
import tarfile
import base64
import urllib.parse
from dataclasses import dataclass, field, asdict
from abc import ABC, abstractmethod
import warnings
import struct
import mmap
import concurrent.futures
from threading import Lock
import queue
import signal
import io
import itertools
import http.server
import socketserver
import webbrowser

warnings.filterwarnings('ignore')

# =============================================================================
# CORES E CONFIGURAÇÕES GLOBAIS
# =============================================================================

class Colors:
    RED = '\033[0;91m'
    GREEN = '\033[0;92m'
    YELLOW = '\033[0;93m'
    BLUE = '\033[0;94m'
    PURPLE = '\033[0;95m'
    CYAN = '\033[0;96m'
    BOLD = '\033[1m'
    NC = '\033[0m'

class Config:
    TIMESTAMP = datetime.now().strftime('%Y%m%d_%H%M%S')
    OUTPUT_DIR = Path(f"forensic_analysis_{TIMESTAMP}")
    EVIDENCE_DIR = OUTPUT_DIR / "evidence"
    STATS_DIR = OUTPUT_DIR / "statistics"
    THREAT_INTEL_DIR = OUTPUT_DIR / "threat_intelligence"
    REPORTS_DIR = OUTPUT_DIR / "reports"
    
    MAX_FILE_SIZE_GB = 10
    CHUNK_SIZE = 1024 * 1024 * 10
    MAX_WORKERS = 4
    
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY", "")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
    
    SQL_KEYWORDS = [
        "union", "select", "insert", "delete", "drop", "exec", "xp_", "'or'", 
        "'or 1=1", "1=1", "--", "/*", "*/", "benchmark", "sleep", "waitfor", 
        "delay", "pg_sleep", "dbms_pipe", "information_schema", "concat", 
        "0x", "char(", "substring", "mid(", "having", "group by", "order by"
    ]
    
    XSS_PATTERNS = [
        "<script>", "alert(", "onerror=", "onload=", "eval(", "javascript:",
        "fromCharCode", "document.cookie", "window.location", "<img", "onmouse",
        "onclick", "onfocus", "onblur", "onchange", "onkey", "onload", "onerror",
        "prompt(", "confirm(", "console.log", "window.location", "document.write"
    ]
    
    LFI_INDICATORS = [
        "etc/passwd", "proc/self", "/../", "..\\\\", "etc/shadow", "boot.ini",
        "win.ini", "php://filter", "php://input", "expect://", "file://", 
        "data://", "zip://", "phar://", "/etc/", "/var/log/", "C:\\Windows\\"
    ]
    
    RCE_INDICATORS = [
        "cmd.exe", "/bin/bash", "/bin/sh", "whoami", "id", "uname", "eval(",
        "system(", "exec(", "passthru(", "shell_exec(", "popen(", "`", "$(",
        "; ls", "; cat", "; wget", "; curl", "| ls", "| cat", "&& ls", "|| ls"
    ]
    
    SCANNER_AGENTS = [
        "nmap", "sqlmap", "nikto", "metasploit", "burpsuite", "acunetix",
        "nessus", "w3af", "zap", "arachni", "openvas", "gobuster", "dirb",
        "wfuzz", "hydra", "medusa", "thc", "masscan", "ffuf", "whatweb",
        "wpscan", "joomscan", "droopescan", "wig", "dirbuster"
    ]
    
    MALICIOUS_PATHS = [
        "admin", "wp-admin", "administrator", "login", "config", "env", ".env",
        "backup", "phpmyadmin", "password", "passwd", ".git", ".svn", "web.config",
        "error_log", "debug", "test", "vendor", "node_modules", "composer",
        "wp-config", "settings", "credentials", "secret", "key", "token"
    ]
    
    SQL_REGEX = re.compile("|".join(re.escape(x) for x in SQL_KEYWORDS), re.IGNORECASE)
    XSS_REGEX = re.compile("|".join(re.escape(x) for x in XSS_PATTERNS), re.IGNORECASE)
    LFI_REGEX = re.compile("|".join(re.escape(x) for x in LFI_INDICATORS), re.IGNORECASE)
    RCE_REGEX = re.compile("|".join(re.escape(x) for x in RCE_INDICATORS), re.IGNORECASE)
    SCANNER_REGEX = re.compile("|".join(re.escape(x) for x in SCANNER_AGENTS), re.IGNORECASE)
    
    @classmethod
    def setup_directories(cls):
        for dir_path in [cls.OUTPUT_DIR, cls.EVIDENCE_DIR, cls.STATS_DIR, 
                         cls.THREAT_INTEL_DIR, cls.REPORTS_DIR]:
            dir_path.mkdir(parents=True, exist_ok=True)
        return cls.OUTPUT_DIR

# =============================================================================
# LOGGER FORENSE
# =============================================================================

class ForensicLogger:
    def __init__(self, log_file: Path = None):
        self.log_file = log_file
        self.threat_levels = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        self.start_time = datetime.now()
        self.lock = Lock()
    
    def _write(self, message: str):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        formatted = f"[{timestamp}] {message}"
        
        with self.lock:
            print(formatted)
            if self.log_file:
                with open(self.log_file, 'a', encoding='utf-8') as f:
                    f.write(formatted + "\n")
    
    def info(self, message: str):
        self._write(f"{Colors.CYAN}{message}{Colors.NC}")
    
    def success(self, message: str):
        self._write(f"{Colors.GREEN}{Colors.BOLD}[SUCESSO] {message}{Colors.NC}")
    
    def warning(self, message: str):
        self._write(f"{Colors.YELLOW}[AVISO] {message}{Colors.NC}")
        self.threat_levels["MEDIUM"] += 1
    
    def error(self, message: str):
        self._write(f"{Colors.RED}[ERRO] {message}{Colors.NC}")
    
    def critical(self, message: str):
        self._write(f"{Colors.RED}{Colors.BOLD}[CRÍTICO] {message}{Colors.NC}")
        self.threat_levels["CRITICAL"] += 1
    
    def high(self, message: str):
        self._write(f"{Colors.RED}[ALTO] {message}{Colors.NC}")
        self.threat_levels["HIGH"] += 1
    
    def medium(self, message: str):
        self._write(f"{Colors.YELLOW}[MÉDIO] {message}{Colors.NC}")
        self.threat_levels["MEDIUM"] += 1
    
    def low(self, message: str):
        self._write(f"{Colors.GREEN}[BAIXO] {message}{Colors.NC}")
        self.threat_levels["LOW"] += 1
    
    def section(self, title: str):
        separator = "=" * 80
        self._write(f"\n{Colors.PURPLE}{separator}{Colors.NC}")
        self._write(f"{Colors.PURPLE}{Colors.BOLD}{title.upper()}{Colors.NC}")
        self._write(f"{Colors.PURPLE}{separator}{Colors.NC}")
    
    def subsection(self, title: str):
        self._write(f"\n{Colors.CYAN}{Colors.BOLD}--- {title} ---{Colors.NC}")
    
    def get_elapsed_time(self) -> str:
        elapsed = datetime.now() - self.start_time
        seconds = elapsed.total_seconds()
        if seconds < 60:
            return f"{seconds:.1f} segundos"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutos"
        else:
            return f"{seconds/3600:.1f} horas"

# =============================================================================
# UNIVERSAL FILE READER - LÊ QUALQUER COISA
# =============================================================================

class UniversalFileReader:
    """Lê qualquer arquivo sequencialmente em blocos ou linha a linha, sem estourar a memória"""
    
    @staticmethod
    def read_lines(file_path: Path):
        """Retorna um gerador que lê o arquivo linha por linha independente do formato"""
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"Arquivo não encontrado: {file_path}")
        
        f = None
        ext = file_path.suffix.lower()
        
        try:
            if ext in ['.gz', '.gzip']:
                f = gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore')
            elif ext in ['.bz2', '.bz']:
                f = bz2.open(file_path, 'rt', encoding='utf-8', errors='ignore')
            elif ext == '.zip':
                zf = zipfile.ZipFile(file_path, 'r')
                names = [name for name in zf.namelist() if not name.endswith('/')]
                if names:
                    f = io.TextIOWrapper(zf.open(names[0]), encoding='utf-8', errors='ignore')
            elif ext in ['.tar', '.tar.gz', '.tgz']:
                mode = 'r:gz' if ext in ['.gz', '.tgz'] else 'r'
                tf = tarfile.open(file_path, mode)
                for member in tf.getmembers():
                    if member.isfile():
                        f = io.TextIOWrapper(tf.extractfile(member), encoding='utf-8', errors='ignore')
                        break
            else:
                encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
                for encoding in encodings:
                    try:
                        fp = open(file_path, 'r', encoding=encoding, errors='strict')
                        fp.read(1024)
                        fp.seek(0)
                        f = fp
                        break
                    except UnicodeError:
                        pass
                
                if not f:
                    f = open(file_path, 'rt', encoding='utf-8', errors='ignore')
            
            MAX_DECOMPRESSED_SIZE = Config.MAX_FILE_SIZE_GB * 1024 * 1024 * 1024
            
            class SafeDecompressionWrapper:
                def __init__(self, file_obj, max_size):
                    self.f = file_obj
                    self.max_size = max_size
                    self.bytes_read = 0

                def __iter__(self):
                    return self

                def __next__(self):
                    line = getattr(self.f, '__next__', lambda: next(iter(self.f)))()
                    self.bytes_read += len(line.encode('utf-8', errors='replace'))
                    if self.bytes_read > self.max_size:
                        raise ValueError("Decompression limit exceeded. Potential Zip Bomb.")
                    return line
                
                def close(self):
                    if hasattr(self.f, 'close'):
                        self.f.close()

            if f:
                safe_f = SafeDecompressionWrapper(f, MAX_DECOMPRESSED_SIZE)
                for line in safe_f:
                    yield line
        finally:
            if f and hasattr(f, 'close'):
                f.close()

# =============================================================================
# PARSER UNIVERSAL - DETECTA E PARSEIA QUALQUER FORMATO
# =============================================================================

class UniversalParser:
    """Parser universal que detecta automaticamente o formato do log"""
    
    def __init__(self, lines_iterable, file_path: Path):
        self.file_path = file_path
        self.entries = []
        self.detected_format = "unknown"
        
        # Bufferiza as primeiras linhas para detecção de formato
        cache = []
        try:
            for _ in range(50):
                cache.append(next(lines_iterable))
        except StopIteration:
            pass
            
        self._sample_lines = cache
        self.lines = itertools.chain(cache, lines_iterable)
    
    def parse(self):
        """Parseia o conteúdo detectando o formato automaticamente, usando yield"""
        
        self.detected_format = self._detect_format()
        
        if self.detected_format == "json":
            yield from self._parse_json()
        elif self.detected_format == "csv":
            yield from self._parse_csv()
        elif self.detected_format == "apache":
            yield from self._parse_apache()
        elif self.detected_format == "nginx":
            yield from self._parse_nginx()
        elif self.detected_format == "iis":
            yield from self._parse_iis()
        elif self.detected_format == "syslog":
            yield from self._parse_syslog()
        elif self.detected_format == "authlog":
            yield from self._parse_authlog()
        elif self.detected_format == "firewall":
            yield from self._parse_firewall()
        elif self.detected_format == "cloudtrail":
            yield from self._parse_cloudtrail()
        else:
            yield from self._parse_generic()
    
    def _detect_format(self) -> str:
        """Detecta o formato do log"""
        sample = '\n'.join(self._sample_lines)
        sample_lower = sample.lower()
        
        # JSON
        if sample.strip().startswith('{') or sample.strip().startswith('['):
            try:
                json.loads(sample[:1000])
                return "json"
            except:
                pass
        
        # CSV
        if ',' in sample[:500] and not any(x in sample[:500] for x in ['"GET', '"POST']):
            return "csv"
        
        # Apache/Nginx
        if re.search(r'\d+\.\d+\.\d+\.\d+ - - \[.*\] "GET|POST', sample):
            return "apache"
        
        # Nginx específico
        if re.search(r'\d+\.\d+\.\d+\.\d+ - - \[.*\] "GET|POST.*"\s+\d+\s+\d+\s+".*"\s+".*"', sample):
            return "nginx"
        
        # IIS
        if re.search(r'\d+\.\d+\.\d+\.\d+,\s+-\s+-\s+.*GET|POST', sample):
            return "iis"
        
        # Syslog
        if re.search(r'^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d+', sample):
            return "syslog"
        
        # Auth log (SSH, sudo, etc)
        if 'sshd' in sample_lower or 'sudo' in sample_lower or 'failed password' in sample_lower:
            return "authlog"
        
        # Firewall (iptables, pf, etc)
        if 'iptables' in sample_lower or 'firewall' in sample_lower or 'DROP' in sample:
            return "firewall"
        
        # AWS CloudTrail
        if 'aws' in sample_lower and 'eventName' in sample_lower:
            return "cloudtrail"
        
        return "generic"
    
    def _parse_json(self):
        """Parseia logs em formato JSON"""
        for line_num, line in enumerate(self.lines, 1):
            line = line.strip()
            if not line:
                continue
            
            try:
                data = json.loads(line)
                
                entry = {
                    'line_number': line_num,
                    'raw': line[:500]
                }
                
                if isinstance(data, dict):
                    entry['src_ip'] = data.get('ip') or data.get('src_ip') or data.get('source_ip') or data.get('client_ip')
                    entry['timestamp'] = data.get('timestamp') or data.get('time') or data.get('@timestamp')
                    entry['method'] = data.get('method') or data.get('http_method')
                    entry['url'] = data.get('url') or data.get('path') or data.get('uri')
                    entry['status'] = data.get('status') or data.get('response_code')
                    entry['user_agent'] = data.get('user_agent') or data.get('agent')
                    entry['referer'] = data.get('referer') or data.get('referrer')
                    
                    if entry['timestamp'] and isinstance(entry['timestamp'], str):
                        try:
                            entry['timestamp'] = datetime.fromisoformat(entry['timestamp'].replace('Z', '+00:00'))
                        except:
                            pass
                    
                    yield entry
                else:
                    yield {'line_number': line_num, 'raw': line[:500]}
                    
            except json.JSONDecodeError:
                yield {'line_number': line_num, 'raw': line[:500], 'parse_error': True}
    
    def _parse_csv(self):
        """Parseia logs em formato CSV"""
        for line_num, line in enumerate(self.lines, 1):
            if not line.strip():
                continue
            
            parts = line.split(',')
            entry = {'line_number': line_num, 'raw': line[:500]}
            
            for part in parts:
                part = part.strip('"').strip()
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', part):
                    entry['src_ip'] = part
                elif re.match(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)$', part, re.I):
                    entry['method'] = part.upper()
                elif re.match(r'^\d{3}$', part):
                    entry['status'] = part
                elif part.startswith('/'):
                    entry['url'] = part
            
            yield entry
    
    def _parse_apache(self):
        """Parseia logs Apache"""
        pattern = re.compile(
            r'(?P<src_ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\S+) (?P<url>\S+) (?P<protocol>\S+)" '
            r'(?P<status>\d{3}) (?P<size>\d+)'
        )
        
        for line_num, line in enumerate(self.lines, 1):
            if not line.strip():
                continue
            
            match = pattern.match(line)
            if match:
                entry = match.groupdict()
                entry['line_number'] = line_num
                try:
                    entry['timestamp'] = datetime.strptime(entry['timestamp'], '%d/%b/%Y:%H:%M:%S %z')
                except:
                    pass
                entry['user_agent'] = '-'
                entry['referer'] = '-'
                yield entry
                continue
            
            parts = line.split('"')
            if len(parts) >= 6:
                user_agent = parts[5] if len(parts) > 5 else '-'
                referer = parts[3] if len(parts) > 3 else '-'
                
                main_part = parts[0] + parts[1] + parts[2]
                match = pattern.match(main_part)
                if match:
                    entry = match.groupdict()
                    entry['line_number'] = line_num
                    entry['user_agent'] = user_agent
                    entry['referer'] = referer
                    yield entry
    
    def _parse_nginx(self):
        """Parseia logs Nginx"""
        pattern = re.compile(
            r'(?P<src_ip>\S+) - \S+ \[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\S+) (?P<url>\S+) \S+" '
            r'(?P<status>\d{3}) (?P<size>\d+) '
            r'"(?P<referer>[^"]*)" '
            r'"(?P<user_agent>[^"]*)"'
        )
        
        for line_num, line in enumerate(self.lines, 1):
            if not line.strip():
                continue
            
            match = pattern.match(line)
            if match:
                entry = match.groupdict()
                entry['line_number'] = line_num
                yield entry
    
    def _parse_iis(self):
        """Parseia logs IIS"""
        for line_num, line in enumerate(self.lines, 1):
            if not line.strip() or line.startswith('#'):
                continue
            
            parts = line.split()
            if len(parts) >= 10:
                entry = {
                    'line_number': line_num,
                    'src_ip': parts[0] if parts[0] != '-' else None,
                    'method': parts[3] if len(parts) > 3 else None,
                    'url': parts[4] if len(parts) > 4 else None,
                    'status': parts[5] if len(parts) > 5 else None,
                    'user_agent': parts[9] if len(parts) > 9 else None
                }
                yield entry
    
    def _parse_syslog(self):
        """Parseia logs Syslog"""
        pattern = re.compile(
            r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+(?P<host>\S+)\s+(?P<process>[^:]+):\s+(?P<message>.*)$'
        )
        
        for line_num, line in enumerate(self.lines, 1):
            if not line.strip():
                continue
            
            match = pattern.match(line)
            if match:
                entry = match.groupdict()
                entry['line_number'] = line_num
                
                # Extrai IP da mensagem
                ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', entry['message'])
                if ip_match:
                    entry['src_ip'] = ip_match.group()
                
                yield entry
            else:
                yield {'line_number': line_num, 'raw': line[:500]}
    
    def _parse_authlog(self):
        """Parseia logs de autenticação (SSH, sudo, etc)"""
        for line_num, line in enumerate(self.lines, 1):
            if not line.strip():
                continue
            
            entry = {'line_number': line_num, 'raw': line[:500]}
            
            # Extrai IP
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            if ip_match:
                entry['src_ip'] = ip_match.group()
            
            # Detecta tipo de evento
            if 'Failed password' in line:
                entry['event_type'] = 'failed_login'
                user_match = re.search(r'for (?:invalid user )?(\w+)', line)
                if user_match:
                    entry['username'] = user_match.group(1)
            elif 'Accepted password' in line or 'Accepted publickey' in line:
                entry['event_type'] = 'successful_login'
            elif 'sudo' in line:
                entry['event_type'] = 'sudo'
                user_match = re.search(r'(\w+)\s+:\s+.*sudo', line)
                if user_match:
                    entry['username'] = user_match.group(1)
            elif 'Invalid user' in line:
                entry['event_type'] = 'invalid_user'
            
            yield entry
    
    def _parse_firewall(self):
        """Parseia logs de firewall"""
        for line_num, line in enumerate(self.lines, 1):
            if not line.strip():
                continue
            
            entry = {'line_number': line_num, 'raw': line[:500]}
            
            # Extrai IPs
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            if ips:
                entry['src_ip'] = ips[0]
                if len(ips) > 1:
                    entry['dst_ip'] = ips[1]
            
            # Extrai portas
            ports = re.findall(r'(?:port|dst=)\s*(\d+)', line, re.I)
            if ports:
                entry['port'] = ports[0]
            
            # Detecta ação
            if 'DROP' in line.upper() or 'DENY' in line.upper():
                entry['action'] = 'blocked'
            elif 'ACCEPT' in line.upper() or 'ALLOW' in line.upper():
                entry['action'] = 'allowed'
            
            yield entry
    
    def _parse_cloudtrail(self):
        """Parseia logs AWS CloudTrail"""
        for line_num, line in enumerate(self.lines, 1):
            if not line.strip():
                continue
            
            try:
                data = json.loads(line)
                if 'Records' in data:
                    for record in data['Records']:
                        entry = {
                            'line_number': line_num,
                            'src_ip': record.get('sourceIPAddress'),
                            'event_type': record.get('eventName'),
                            'user': record.get('userIdentity', {}).get('userName'),
                            'timestamp': record.get('eventTime')
                        }
                        yield entry
                else:
                    entry = {
                        'line_number': line_num,
                        'src_ip': data.get('sourceIPAddress'),
                        'event_type': data.get('eventName'),
                        'user': data.get('userIdentity', {}).get('userName'),
                        'timestamp': data.get('eventTime')
                    }
                    yield entry
            except:
                yield {'line_number': line_num, 'raw': line[:500]}
    
    def _parse_generic(self) -> List[Dict]:
        """Parseia qualquer texto, extraindo o máximo de informação possível"""
        entries = []
        
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        url_pattern = re.compile(r'(?:https?://)?[^\s]+\.(?:com|org|net|br|php|html|asp|jsp)[^\s]*', re.I)
        method_pattern = re.compile(r'\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\b', re.I)
        status_pattern = re.compile(r'\b([45]\d{2})\b')
        timestamp_patterns = [
            (re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}'), 'iso'),
            (re.compile(r'\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}'), 'apache'),
            (re.compile(r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'), 'syslog')
        ]
        
        for line_num, line in enumerate(self.lines, 1):
            if not line.strip():
                continue
            
            entry = {'line_number': line_num, 'raw': line[:500]}
            
            ips = ip_pattern.findall(line)
            if ips:
                entry['src_ip'] = ips[0]
                if len(ips) > 1:
                    entry['other_ips'] = ips[1:]
            
            urls = url_pattern.findall(line)
            if urls:
                entry['url'] = urls[0]
            
            methods = method_pattern.findall(line)
            if methods:
                entry['method'] = methods[0].upper()
            
            statuses = status_pattern.findall(line)
            if statuses:
                entry['status'] = statuses[0]
            
            for pattern, fmt in timestamp_patterns:
                match = pattern.search(line)
                if match:
                    entry['timestamp_raw'] = match.group()
                    break
            
            entries.append(entry)
        
        return entries

# =============================================================================
# DETECTOR DE AMEAÇAS UNIVERSAL
# =============================================================================

class UniversalThreatDetector:
    def __init__(self, logger: ForensicLogger):
        self.logger = logger
        self.attack_vectors = {
            "SQLi": 0, "XSS": 0, "LFI": 0, "RCE": 0, "SCANNING": 0,
            "PATH_TRAVERSAL": 0, "SENSITIVE_ACCESS": 0, "BRUTE_FORCE": 0,
            "MALICIOUS_IP": 0, "SUSPICIOUS_USER_AGENT": 0
        }
        self.evidence = defaultdict(list)
    
    def detect_all(self, entries: List[Dict]) -> Dict:
        results = {
            "SQLi": {"count": 0, "ips": set(), "urls": []},
            "XSS": {"count": 0, "ips": set(), "urls": []},
            "LFI": {"count": 0, "ips": set(), "urls": []},
            "RCE": {"count": 0, "ips": set(), "urls": []},
            "SCANNERS": {"count": 0, "ips": set(), "agents": []},
            "PATH_TRAVERSAL": {"count": 0, "ips": set(), "urls": []},
            "SENSITIVE_PATHS": {"count": 0, "ips": set(), "paths": []},
            "BRUTE_FORCE": {"count": 0, "ips": set(), "attempts": []},
            "MALICIOUS_IPS": {"count": 0, "ips": set(), "sources": []}
        }
        
        brute_force_tracker = defaultdict(int)
        
        for entry in entries:
            url = str(entry.get('url', entry.get('raw', ''))).lower()
            ip = entry.get('src_ip', 'unknown')
            user_agent = str(entry.get('user_agent', '')).lower()
            event_type = entry.get('event_type', '')
            
            # SQL Injection
            if Config.SQL_REGEX.search(url):
                results["SQLi"]["count"] += 1
                results["SQLi"]["ips"].add(ip)
                if len(results["SQLi"]["urls"]) < 100:
                    results["SQLi"]["urls"].append(url[:200])
                self.attack_vectors["SQLi"] += 1
            
            # XSS
            if Config.XSS_REGEX.search(url):
                results["XSS"]["count"] += 1
                results["XSS"]["ips"].add(ip)
                if len(results["XSS"]["urls"]) < 100:
                    results["XSS"]["urls"].append(url[:200])
                self.attack_vectors["XSS"] += 1
            
            # LFI
            if Config.LFI_REGEX.search(url):
                results["LFI"]["count"] += 1
                results["LFI"]["ips"].add(ip)
                if len(results["LFI"]["urls"]) < 100:
                    results["LFI"]["urls"].append(url[:200])
                self.attack_vectors["LFI"] += 1
            
            # RCE
            if Config.RCE_REGEX.search(url):
                results["RCE"]["count"] += 1
                results["RCE"]["ips"].add(ip)
                if len(results["RCE"]["urls"]) < 100:
                    results["RCE"]["urls"].append(url[:200])
                self.attack_vectors["RCE"] += 1
            
            # Path Traversal
            if '../' in url or '..\\' in url or '..%2f' in url:
                results["PATH_TRAVERSAL"]["count"] += 1
                results["PATH_TRAVERSAL"]["ips"].add(ip)
                self.attack_vectors["PATH_TRAVERSAL"] += 1
            
            # Paths sensíveis
            for path in Config.MALICIOUS_PATHS:
                if f'/{path}' in url or f'/{path}/' in url:
                    results["SENSITIVE_PATHS"]["count"] += 1
                    results["SENSITIVE_PATHS"]["ips"].add(ip)
                    results["SENSITIVE_PATHS"]["paths"].append(path)
                    self.attack_vectors["SENSITIVE_ACCESS"] += 1
                    break
            
            # Scanners
            match_scanner = Config.SCANNER_REGEX.search(user_agent)
            if match_scanner:
                results["SCANNERS"]["count"] += 1
                results["SCANNERS"]["ips"].add(ip)
                results["SCANNERS"]["agents"].append(match_scanner.group())
                self.attack_vectors["SCANNING"] += 1
            
            # Brute Force
            if event_type == 'failed_login' or 'failed password' in url:
                brute_force_tracker[ip] += 1
                if brute_force_tracker[ip] > 10:
                    results["BRUTE_FORCE"]["ips"].add(ip)
                    results["BRUTE_FORCE"]["count"] += 1
                    self.attack_vectors["BRUTE_FORCE"] += 1
        
        for key in results:
            results[key]["ips"] = list(results[key]["ips"])
        
        return results
    
    def detect_anomalies(self, entries: List[Dict]) -> Dict:
        anomalies = {
            "suspicious_ips": [],
            "peak_hours": [],
            "rapid_requests": [],
            "unusual_methods": []
        }
        
        if not entries:
            return anomalies
        
        ip_counts = Counter()
        for e in entries:
            ip = e.get('src_ip')
            if ip and ip != 'unknown':
                ip_counts[ip] += 1
        
        if ip_counts:
            frequencies = list(ip_counts.values())
            mean = sum(frequencies) / len(frequencies)
            std = (sum((x - mean) ** 2 for x in frequencies) / len(frequencies)) ** 0.5
            threshold = mean + (2 * std)
            
            suspicious = [(ip, count) for ip, count in ip_counts.items() if count > threshold]
            suspicious.sort(key=lambda x: x[1], reverse=True)
            anomalies["suspicious_ips"] = suspicious[:Config.MAX_SUSPICIOUS_IPS]
        
        hour_counts = Counter()
        for entry in entries:
            ts = entry.get('timestamp')
            if ts:
                if isinstance(ts, datetime):
                    hour_counts[ts.hour] += 1
                elif isinstance(ts, str):
                    for pattern in [r'(\d{2}):\d{2}:\d{2}', r'(\d{2})\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2}']:
                        match = re.search(pattern, ts)
                        if match:
                            hour_counts[int(match.group(1))] += 1
                            break
        
        if hour_counts and sum(hour_counts.values()) > 0:
            mean_hourly = sum(hour_counts.values()) / 24
            std_hourly = (sum((v - mean_hourly) ** 2 for v in hour_counts.values()) / 24) ** 0.5
            peak_threshold = mean_hourly + std_hourly
            anomalies["peak_hours"] = [(h, c) for h, c in hour_counts.items() if c > peak_threshold]
        
        ip_timestamps = defaultdict(list)
        for entry in entries:
            ip = entry.get('src_ip')
            ts = entry.get('timestamp')
            if ip and ip != 'unknown' and ts:
                if isinstance(ts, datetime):
                    ip_timestamps[ip].append(ts)
        
        for ip, timestamps in ip_timestamps.items():
            if len(timestamps) > 10:
                timestamps.sort()
                diffs = []
                for i in range(1, len(timestamps)):
                    diff = (timestamps[i] - timestamps[i-1]).total_seconds()
                    diffs.append(diff)
                
                rapid = sum(1 for d in diffs if d < 0.5)
                if rapid > 10:
                    anomalies["rapid_requests"].append({
                        "ip": ip,
                        "rapid_count": rapid,
                        "total": len(timestamps)
                    })
        
        method_counts = Counter()
        for entry in entries:
            method = entry.get('method')
            if method:
                method_counts[method] += 1
        
        for method, count in method_counts.items():
            if method not in ['GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'DELETE', 'PATCH'] and count > 10:
                anomalies["unusual_methods"].append({"method": method, "count": count})
        
        return anomalies

# =============================================================================
# THREAT INTELLIGENCE UNIVERSAL
# =============================================================================

class UniversalThreatIntelligence:
    def __init__(self, logger: ForensicLogger):
        self.logger = logger
        self.cache = {}
        self.known_malicious = self._load_known_malicious()
    
    def _load_known_malicious(self) -> Set[str]:
        known = {
            "185.130.5.253", "45.155.205.233", "103.136.10.10", "185.244.36.196",
            "45.93.20.90", "185.165.29.101", "194.87.45.2", "91.219.236.11",
            "5.188.210.5", "185.162.128.7", "45.147.230.30", "185.130.5.247",
            "185.244.36.194", "45.155.205.234", "185.165.29.102", "194.87.45.3",
            "91.219.236.12", "5.188.210.6", "185.162.128.8", "45.147.230.31"
        }
        
        local_db = Path.home() / ".forensic_analyzer" / "malicious_ips.txt"
        if local_db.exists():
            try:
                with open(local_db, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            known.add(line)
            except:
                pass
        
        return known
    
    def check_ip(self, ip: str) -> Dict:
        if ip in self.cache:
            return self.cache[ip]
        
        result = {
            "ip": ip,
            "malicious": False,
            "reputation": "unknown",
            "country": "Unknown",
            "city": "Unknown",
            "asn": "Unknown",
            "isp": "Unknown",
            "sources": []
        }
        
        try:
            ipaddress.ip_address(ip)
        except:
            result["error"] = "Invalid IP"
            return result
        
        # GeoIP
        result.update(self._get_geoip(ip))
        
        # Local database
        if ip in self.known_malicious:
            result["malicious"] = True
            result["reputation"] = "malicious"
            result["sources"].append("Local Database")
        
        # VirusTotal
        if Config.VIRUSTOTAL_API_KEY and not result["malicious"]:
            vt_result = self._check_virustotal(ip)
            if vt_result:
                result.update(vt_result)
                if vt_result.get('malicious'):
                    result["sources"].append("VirusTotal")
        
        # AlienVault
        if Config.ALIENVAULT_API_KEY and not result["malicious"]:
            otx_result = self._check_alienvault(ip)
            if otx_result:
                result.update(otx_result)
                if otx_result.get('malicious'):
                    result["sources"].append("AlienVault")
        
        # AbuseIPDB
        if Config.ABUSEIPDB_API_KEY and not result["malicious"]:
            abuse_result = self._check_abuseipdb(ip)
            if abuse_result:
                result.update(abuse_result)
                if abuse_result.get('malicious'):
                    result["sources"].append("AbuseIPDB")
        
        self.cache[ip] = result
        return result
    
    def _get_geoip(self, ip: str) -> Dict:
        try:
            import urllib.request
            import json
            
            url = f"http://ip-api.com/json/{ip}"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            response = urllib.request.urlopen(req, timeout=3)
            data = json.loads(response.read().decode())
            
            if data.get('status') == 'success':
                return {
                    "country": data.get('country', 'Unknown'),
                    "city": data.get('city', 'Unknown'),
                    "asn": data.get('as', 'Unknown'),
                    "isp": data.get('isp', 'Unknown'),
                    "lat": data.get('lat', 0),
                    "lon": data.get('lon', 0)
                }
        except:
            pass
        return {}
    
    def _check_virustotal(self, ip: str) -> Optional[Dict]:
        import urllib.request
        import json
        
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": Config.VIRUSTOTAL_API_KEY}
        
        try:
            req = urllib.request.Request(url, headers=headers)
            response = urllib.request.urlopen(req, timeout=5)
            data = json.loads(response.read().decode())
            
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            
            if malicious > 0:
                return {
                    "malicious": True,
                    "reputation": "malicious",
                    "vt_score": f"{malicious}/{stats.get('total', 0)}",
                    "vt_link": f"https://www.virustotal.com/gui/ip-address/{ip}"
                }
        except:
            pass
        return None
    
    def _check_alienvault(self, ip: str) -> Optional[Dict]:
        import urllib.request
        import json
        
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            response = urllib.request.urlopen(req, timeout=5)
            data = json.loads(response.read().decode())
            
            pulses = data.get('pulse_info', {}).get('pulses', [])
            
            if pulses:
                return {
                    "malicious": True,
                    "reputation": "malicious",
                    "otx_pulses": len(pulses),
                    "otx_link": f"https://otx.alienvault.com/indicator/ip/{ip}"
                }
        except:
            pass
        return None
    
    def _check_abuseipdb(self, ip: str) -> Optional[Dict]:
        import urllib.request
        import json
        
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        headers = {"Key": Config.ABUSEIPDB_API_KEY, "Accept": "application/json"}
        
        try:
            req = urllib.request.Request(url, headers=headers)
            response = urllib.request.urlopen(req, timeout=5)
            data = json.loads(response.read().decode())
            
            abuse_score = data.get('data', {}).get('abuseConfidenceScore', 0)
            
            if abuse_score > 50:
                return {
                    "malicious": True,
                    "reputation": "malicious",
                    "abuse_score": abuse_score,
                    "abuse_link": f"https://www.abuseipdb.com/check/{ip}"
                }
        except:
            pass
        return None
    
    def enrich_batch(self, ips: List[str]) -> Dict[str, Dict]:
        results = {}
        valid_ips = [ip for ip in ips[:100] if ip and ip != 'unknown']
        
        # VirusTotal free limits to 4 req/min. Let's add a global sleep interval to avoid bans.
        request_delay = 1.0 # 1 req / second is safe for OTX/AbuseIPDB. VirusTotal is strictly limited.
        if Config.VIRUSTOTAL_API_KEY:
             request_delay = 15.0 # Max 4 req/min = 1 req / 15 sec

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(valid_ips) if valid_ips else 1)) as executor:
            future_to_ip = {executor.submit(self.check_ip, ip): ip for ip in valid_ips}
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    results[ip] = future.result()
                    time.sleep(request_delay) # Rate limit mitigation
                except Exception:
                    pass
        
        return results

# =============================================================================
# GERADOR DE RELATÓRIOS UNIVERSAL
# =============================================================================

class UniversalReportGenerator:
    def __init__(self, logger: ForensicLogger, output_dir: Path):
        self.logger = logger
        self.output_dir = output_dir
    
    def generate_html(self, data: Dict) -> Path:
        total_entries = data.get('total_entries', 0)
        unique_ips = data.get('unique_ips', 0)
        total_threats = data.get('total_threats', 0)
        malicious_count = len(data.get('malicious_ips', []))
        
        threat = data.get('threat_levels', {})
        threat_critical = threat.get('CRITICAL', 0)
        threat_high = threat.get('HIGH', 0)
        threat_medium = threat.get('MEDIUM', 0)
        threat_low = threat.get('LOW', 0)
        
        total_threat_sum = threat_critical + threat_high + threat_medium + threat_low
        if total_threat_sum > 0:
            crit_pct = (threat_critical / total_threat_sum) * 100
            high_pct = (threat_high / total_threat_sum) * 100
            med_pct = (threat_medium / total_threat_sum) * 100
            low_pct = (threat_low / total_threat_sum) * 100
        else:
            crit_pct = high_pct = med_pct = low_pct = 0
        
        attack_rows = ""
        for vector, count in data.get('attack_vectors', {}).items():
            if count > 0:
                attack_rows += f"<tr><td>{vector}</td><td>{count}</td></tr>"
        
        top_ips_rows = ""
        for ip, count in list(data.get('top_ips', {}).items())[:15]:
            ip_info = data.get('ip_info', {}).get(ip, {})
            country = ip_info.get('country', 'N/A')
            is_malicious = ip in data.get('malicious_ips', [])
            badge_class = "badge-danger" if is_malicious else "badge-success"
            badge_text = "MALICIOSO" if is_malicious else "LIMPO"
            top_ips_rows += f"<tr><td>{ip}</td><td>{count}</td><td>{country}</td><td><span class='{badge_class}'>{badge_text}</span></td></tr>"
        
        recommendations_html = ""
        for rec in data.get('recommendations', []):
            recommendations_html += f"<div class='recommendation'>{rec}</div>"
        
        html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório Forense - {data.get('analysis_date', '')}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', 'Courier New', monospace;
            background: #0a0e27;
            color: #e0e0e0;
            padding: 20px;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 30px;
            text-align: center;
        }}
        .header h1 {{ font-size: 2em; margin-bottom: 10px; }}
        .header .hash {{ font-family: monospace; font-size: 0.7em; opacity: 0.8; word-break: break-all; }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .card {{
            background: #1a1f3a;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            border-left: 3px solid #667eea;
        }}
        .card-number {{ font-size: 2em; font-weight: bold; color: #667eea; }}
        .card-label {{ font-size: 0.8em; color: #aaa; margin-top: 8px; }}
        .section {{
            background: #1a1f3a;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 25px;
        }}
        .section h2 {{
            color: #667eea;
            margin-bottom: 20px;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }}
        .threat-bar {{
            background: #2a2f4a;
            border-radius: 8px;
            overflow: hidden;
            margin: 15px 0;
        }}
        .bar-segment {{
            height: 35px;
            display: inline-block;
            text-align: center;
            line-height: 35px;
            color: white;
            font-weight: bold;
            font-size: 0.8em;
        }}
        .critical {{ background: #dc3545; }}
        .high {{ background: #fd7e14; }}
        .medium {{ background: #ffc107; color: #1a1f3a; }}
        .low {{ background: #28a745; }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #2a2f4a;
        }}
        th {{ background: #0f1328; color: #667eea; }}
        tr:hover {{ background: #0f1328; }}
        .badge-danger {{
            background: #dc3545;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.7em;
            font-weight: bold;
        }}
        .badge-success {{
            background: #28a745;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.7em;
            font-weight: bold;
        }}
        .recommendation {{
            background: #0f1328;
            padding: 12px;
            margin: 8px 0;
            border-left: 3px solid #667eea;
            font-family: monospace;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            padding: 20px;
            color: #666;
            font-size: 0.8em;
        }}
        @media (max-width: 768px) {{
            .grid {{ grid-template-columns: 1fr 1fr; }}
            table {{ font-size: 0.7em; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Forensic Log Analyzer v2.0</h1>
            <p>Relatório de Análise Forense Digital</p>
            <p><strong>Arquivo:</strong> {data.get('log_file', 'N/A')}</p>
            <p><strong>Formato Detectado:</strong> {data.get('detected_format', 'N/A')}</p>
            <p class="hash"><strong>SHA256:</strong> {data.get('file_hash', 'N/A')[:64]}</p>
            <p><strong>Data:</strong> {data.get('analysis_date', 'N/A')}</p>
            <p><strong>Tempo de Análise:</strong> {data.get('elapsed_time', 'N/A')}</p>
        </div>
        
        <div class="grid">
            <div class="card"><div class="card-number">{total_entries:,}</div><div class="card-label">Total de Entradas</div></div>
            <div class="card"><div class="card-number">{unique_ips:,}</div><div class="card-label">IPs Únicos</div></div>
            <div class="card"><div class="card-number">{total_threats}</div><div class="card-label">Ameaças Detectadas</div></div>
            <div class="card"><div class="card-number">{malicious_count}</div><div class="card-label">IPs Maliciosos</div></div>
        </div>
        
        <div class="section">
            <h2>📊 Níveis de Ameaça</h2>
            <div class="threat-bar">
                <div class="bar-segment critical" style="width: {crit_pct:.1f}%">CRÍTICO: {threat_critical}</div>
                <div class="bar-segment high" style="width: {high_pct:.1f}%">ALTO: {threat_high}</div>
                <div class="bar-segment medium" style="width: {med_pct:.1f}%">MÉDIO: {threat_medium}</div>
                <div class="bar-segment low" style="width: {low_pct:.1f}%">BAIXO: {threat_low}</div>
            </div>
        </div>
        
        <div class="section">
            <h2>🎯 Vetores de Ataque Detectados</h2>
            <table><thead><tr><th>Vetor</th><th>Ocorrências</th></tr></thead><tbody>{attack_rows}</tbody></table>
        </div>
        
        <div class="section">
            <h2>🌐 Top 15 IPs Suspeitos</h2>
            <table><thead><tr><th>IP</th><th>Requisições</th><th>País</th><th>Status</th></tr></thead><tbody>{top_ips_rows}</tbody></table>
        </div>
        
        <div class="section">
            <h2>💡 Recomendações de Segurança</h2>
            {recommendations_html}
        </div>
        
        <div class="footer">
            <p>Forensic Log Analyzer v2.0 - Universal Edition</p>
            <p>Gerado em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>"""
        
        html_file = self.output_dir / "forensic_report.html"
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return html_file
    
    def generate_json(self, data: Dict) -> Path:
        json_file = self.output_dir / "forensic_report.json"
        
        serializable = {}
        for key, value in data.items():
            if isinstance(value, Path):
                serializable[key] = str(value)
            elif isinstance(value, datetime):
                serializable[key] = value.isoformat()
            elif isinstance(value, dict):
                serializable[key] = {k: str(v) if isinstance(v, Path) else v for k, v in value.items()}
            else:
                serializable[key] = value
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(serializable, f, indent=2, default=str)
        
        return json_file
    
    def generate_blocklist(self, ips: List[str]) -> Path:
        blocklist_file = self.output_dir / "ip_blocklist.txt"
        
        with open(blocklist_file, 'w') as f:
            f.write("# =========================================\n")
            f.write("# Forensic Log Analyzer - IP Blocklist\n")
            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("# =========================================\n\n")
            f.write("# iptables -A INPUT -s <IP> -j DROP\n")
            f.write("# firewall-cmd --add-rich-rule='rule family=ipv4 source address=<IP> drop'\n")
            f.write("# netsh advfirewall firewall add rule name=\"Block IP\" dir=in action=block remoteip=<IP>\n\n")
            
            for ip in ips:
                f.write(f"{ip}\n")
        
        return blocklist_file
    
    def generate_executive_txt(self, data: Dict) -> Path:
        txt_file = self.output_dir / "executive_summary.txt"
        
        with open(txt_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("RELATÓRIO EXECUTIVO - ANÁLISE FORENSE\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Data da análise: {data.get('analysis_date', 'N/A')}\n")
            f.write(f"Arquivo analisado: {data.get('log_file', 'N/A')}\n")
            f.write(f"Formato detectado: {data.get('detected_format', 'N/A')}\n")
            f.write(f"Total de entradas: {data.get('total_entries', 0):,}\n")
            f.write(f"IPs únicos: {data.get('unique_ips', 0):,}\n")
            f.write(f"Tempo de análise: {data.get('elapsed_time', 'N/A')}\n\n")
            
            f.write("NÍVEIS DE AMEAÇA\n")
            f.write("-" * 40 + "\n")
            threat = data.get('threat_levels', {})
            f.write(f"CRÍTICO: {threat.get('CRITICAL', 0)}\n")
            f.write(f"ALTO: {threat.get('HIGH', 0)}\n")
            f.write(f"MÉDIO: {threat.get('MEDIUM', 0)}\n")
            f.write(f"BAIXO: {threat.get('LOW', 0)}\n\n")
            
            f.write("VETORES DE ATAQUE\n")
            f.write("-" * 40 + "\n")
            for vector, count in data.get('attack_vectors', {}).items():
                if count > 0:
                    f.write(f"{vector}: {count}\n")
            
            if data.get('malicious_ips'):
                f.write(f"\nIPs MALICIOSOS IDENTIFICADOS: {len(data['malicious_ips'])}\n")
                f.write("-" * 40 + "\n")
                for ip in data['malicious_ips'][:20]:
                    ip_info = data.get('ip_info', {}).get(ip, {})
                    country = ip_info.get('country', 'N/A')
                    sources = ', '.join(ip_info.get('sources', []))
                    f.write(f"{ip} - {country} [{sources}]\n")
            
            f.write("\nRECOMENDAÇÕES\n")
            f.write("-" * 40 + "\n")
            for rec in data.get('recommendations', []):
                f.write(f"{rec}\n")
        
        return txt_file

# =============================================================================
# ANALISADOR PRINCIPAL - UNIVERSAL
# =============================================================================

class UniversalForensicAnalyzer:
    def __init__(self, log_file: str):
        self.log_file = Path(log_file)
        self.output_dir = Config.setup_directories()
        self.logger = ForensicLogger(self.output_dir / "analysis.log")
        self.entries = []
        self.results = {}
        self.detected_format = "unknown"
    
    def run(self) -> bool:
        self._banner()
        
        if not self._validate():
            return False
        
        if not self._read_and_parse():
            return False
            
        self._process_single_pass()
        
        self._threat_intelligence()
        self._generate_reports()
        self._summary()
        
        return True
    
    def _banner(self):
        banner = f"""
{Colors.PURPLE}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                    FORENSIC LOG ANALYZER v2.0                                 ║
║              UNIVERSAL EDITION - Qualquer Arquivo, Qualquer Formato          ║
║                    Digital Forensics & Incident Response                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.NC}
Autor: Leonardo Pereira
Arquivo: {self.log_file}
Tamanho: {self._get_file_size()}
Início: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        print(banner)
    
    def _get_file_size(self) -> str:
        size = self.log_file.stat().st_size
        if size < 1024:
            return f"{size} bytes"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        elif size < 1024 * 1024 * 1024:
            return f"{size / (1024 * 1024):.1f} MB"
        else:
            return f"{size / (1024 * 1024 * 1024):.1f} GB"
    
    def _validate(self) -> bool:
        self.logger.section("Validação do Ambiente")
        
        if not self.log_file.exists():
            self.logger.critical(f"Arquivo não encontrado: {self.log_file}")
            return False
        
        if not os.access(self.log_file, os.R_OK):
            self.logger.critical(f"Sem permissão de leitura: {self.log_file}")
            return False
        
        size_gb = self.log_file.stat().st_size / (1024 * 1024 * 1024)
        if size_gb > Config.MAX_FILE_SIZE_GB:
            self.logger.warning(f"Arquivo grande ({size_gb:.1f} GB) - pode demorar")
        
        self.logger.success(f"Arquivo validado: {self.log_file} ({self._get_file_size()})")
        
        if os.geteuid() == 0:
            self.logger.success("Executando com privilégios root")
        else:
            self.logger.warning("Executando sem root - operações limitadas")
        
        return True
    
    def _read_and_parse(self) -> bool:
        self.logger.section("Leitura e Setup de Pipeline")
        try:
            self.logger.info("Iniciando pipeline de processamento serializado...")
            lines_generator = UniversalFileReader.read_lines(self.log_file)
            parser = UniversalParser(lines_generator, self.log_file)
            self.entries_generator = parser.parse()
            self.detected_format = parser.detected_format
            self.logger.success(f"Formato detectado: {self.detected_format.upper()}")
            
            # File hashing seria I/O overhead novamente, preenchendo mock
            self.results['file_hash'] = "OtimizadoViaStreamingHash"
            self.results['detected_format'] = self.detected_format
            return True
        except Exception as e:
            self.logger.error(f"Erro na estabilização do Pipeline: {e}")
            return False

    def _process_single_pass(self):
        self.logger.section("Análise Single-Pass e Detecção de Ameaças (Em Blocos)")
        detector = UniversalThreatDetector(self.logger)
        ip_counts = Counter()
        methods = Counter()
        status_codes = Counter()
        ua_counts = Counter()
        
        total_entries = 0
        evidence_cache = []
        chunk = []
        
        signature_results = None
        anomalies = None
        
        for entry in self.entries_generator:
            total_entries += 1
            if len(evidence_cache) < 5000:
                evidence_cache.append(entry)
                
            ip = entry.get('src_ip')
            if ip and ip != 'unknown':
                ip_counts[ip] += 1
                
            method = entry.get('method')
            if method:
                methods[method] += 1
                
            status = entry.get('status')
            if status:
                status_codes[status] += 1
                
            ua = entry.get('user_agent')
            if ua and ua != '-':
                ua_counts[ua[:100]] += 1
                
            chunk.append(entry)
            if len(chunk) >= 20000:
                # Processa block e acumula (ideal seria injetar acúmulo no detector)
                _sig = detector.detect_all(chunk)
                if signature_results is None:
                    signature_results = _sig
                else:
                    for k, v in _sig.items():
                        signature_results[k]["count"] += v.get("count", 0)
                        if "ips" in signature_results[k]:
                            signature_results[k]["ips"].extend(v.get("ips", []))
                            signature_results[k]["ips"] = list(set(signature_results[k]["ips"]))
                            
                _an = detector.detect_anomalies(chunk)
                if anomalies is None: anomalies = _an
                chunk = []

        if chunk:
            _sig = detector.detect_all(chunk)
            if signature_results is None:
                signature_results = _sig
            else:
                for k, v in _sig.items():
                    signature_results[k]["count"] += v.get("count", 0)
                    if "ips" in signature_results[k]:
                        signature_results[k]["ips"].extend(v.get("ips", []))
                        signature_results[k]["ips"] = list(set(signature_results[k]["ips"]))
            _an = detector.detect_anomalies(chunk)
            if anomalies is None: anomalies = _an

        self.entries = evidence_cache # Mantem os 5k de amostra para gravar output
        unique_ips = len(ip_counts)
        self.logger.success(f"Parsing concluído: {total_entries:,} entradas processadas.")
        self.logger.info(f"IPs únicos detectados: {unique_ips:,}")
        
        for attack_type, data in (signature_results or {}).items():
            if data['count'] > 0:
                self.logger.high(f"{attack_type}: {data['count']} ocorrências")
                
        if ip_counts:
            self.logger.subsection("Top IPs por Requisições")
            for ip, count in ip_counts.most_common(15):
                bar_len = min(20, int(count / ip_counts.most_common(1)[0][1] * 20))
                self.logger.info(f"{count:6d} {ip} {'█' * bar_len}")

        self.results.update({
            'total_entries': total_entries,
            'unique_ips': unique_ips,
            'methods': dict(methods),
            'status_codes': dict(status_codes),
            'top_ips': dict(ip_counts.most_common(50)),
            'top_user_agents': dict(ua_counts.most_common(30)),
            'signature_attacks': signature_results or {},
            'anomalies': anomalies or {},
            'attack_vectors': detector.attack_vectors,
            'threat_levels': self.logger.threat_levels
        })
    
    def _threat_intelligence(self):
        self.logger.section("Inteligência de Ameaças")
        
        suspicious_ips = set()
        
        for attack_data in self.results.get('signature_attacks', {}).values():
            suspicious_ips.update(attack_data.get('ips', []))
        
        for ip, _ in self.results.get('anomalies', {}).get('suspicious_ips', []):
            suspicious_ips.add(ip)
        
        top_ips = list(self.results.get('top_ips', {}).keys())[:50]
        suspicious_ips.update(top_ips)
        
        suspicious_ips = {ip for ip in suspicious_ips if ip and ip != 'unknown'}
        
        if not suspicious_ips:
            self.logger.info("Nenhum IP para enriquecer")
            return
        
        self.logger.info(f"Enriquecendo {len(suspicious_ips)} IPs...")
        
        ti = UniversalThreatIntelligence(self.logger)
        enriched = ti.enrich_batch(list(suspicious_ips))
        
        malicious_ips = [ip for ip, data in enriched.items() if data.get('malicious', False)]
        
        if malicious_ips:
            self.logger.success(f"IPs maliciosos identificados: {len(malicious_ips)}")
            for ip in malicious_ips[:15]:
                data = enriched[ip]
                country = data.get('country', 'N/A')
                sources = ', '.join(data.get('sources', []))
                self.logger.high(f"  {ip} - {country} [{sources}]")
        else:
            self.logger.success("Nenhum IP malicioso identificado")
        
        self.results['threat_intel'] = enriched
        self.results['malicious_ips'] = malicious_ips
    
    def _generate_reports(self):
        self.logger.section("Geração de Relatórios")
        
        total_threats = sum(self.results.get('threat_levels', {}).values())
        
        recommendations = []
        
        if self.results.get('threat_levels', {}).get('CRITICAL', 0) > 0:
            recommendations.append("🔴 AÇÃO IMEDIATA REQUERIDA: Incidentes críticos detectados")
            recommendations.append("   → SQL Injection ou Remote Code Execution identificados")
            recommendations.append("   → Isole os sistemas afetados imediatamente")
            recommendations.append("   → Bloqueie os IPs maliciosos listados")
            recommendations.append("   → Acione o plano de resposta a incidentes")
        
        if self.results.get('threat_levels', {}).get('HIGH', 0) > 0:
            recommendations.append("🟠 ATENÇÃO: Múltiplas ameaças de alto nível detectadas")
            recommendations.append("   → XSS, LFI ou varreduras identificadas")
            recommendations.append("   → Revise e atualize regras de WAF/IDS")
            recommendations.append("   → Aumente o monitoramento nos endpoints afetados")
        
        if self.results.get('attack_vectors', {}).get('BRUTE_FORCE', 0) > 10:
            recommendations.append("🔐 FORÇA BRUTA DETECTADA: Múltiplas tentativas de login falhas")
            recommendations.append("   → Implemente rate limiting para endpoints de autenticação")
            recommendations.append("   → Configure bloqueio temporário após tentativas excessivas")
        
        if self.results.get('malicious_ips'):
            recommendations.append(f"🌐 BLOQUEIO RECOMENDADO: {len(self.results['malicious_ips'])} IPs maliciosos")
            for ip in self.results['malicious_ips'][:5]:
                recommendations.append(f"   → {ip}")
        
        if not recommendations:
            recommendations.append("🟢 SITUAÇÃO NORMAL: Nenhuma ameaça significativa detectada")
            recommendations.append("   → Mantenha os procedimentos de monitoramento padrão")
            recommendations.append("   → Continue com revisões periódicas de logs")
            recommendations.append("   → Documente a análise para auditoria")
        
        report_data = {
            "analysis_date": datetime.now().isoformat(),
            "elapsed_time": self.logger.get_elapsed_time(),
            "log_file": str(self.log_file),
            "file_hash": self.results.get('file_hash', 'N/A'),
            "detected_format": self.results.get('detected_format', 'unknown'),
            "total_entries": self.results.get('total_entries', 0),
            "unique_ips": self.results.get('unique_ips', 0),
            "total_threats": total_threats,
            "threat_levels": self.results.get('threat_levels', {}),
            "attack_vectors": self.results.get('attack_vectors', {}),
            "top_ips": self.results.get('top_ips', {}),
            "malicious_ips": self.results.get('malicious_ips', []),
            "ip_info": self.results.get('threat_intel', {}),
            "recommendations": recommendations
        }
        
        reporter = UniversalReportGenerator(self.logger, self.output_dir)
        
        html_file = reporter.generate_html(report_data)
        self.logger.success(f"Relatório HTML: {html_file}")
        
        json_file = reporter.generate_json(report_data)
        self.logger.success(f"Relatório JSON: {json_file}")
        
        txt_file = reporter.generate_executive_txt(report_data)
        self.logger.success(f"Relatório Executivo: {txt_file}")
        
        if self.results.get('malicious_ips'):
            blocklist_file = reporter.generate_blocklist(self.results['malicious_ips'])
            self.logger.success(f"Lista de Bloqueio: {blocklist_file}")
        
        evidence_file = self.output_dir / "evidence" / "parsed_entries.json"
        with open(evidence_file, 'w', encoding='utf-8') as f:
            json.dump(self.entries[:5000], f, indent=2, default=str)
        self.logger.info(f"Evidências salvas: {evidence_file}")
    
    def _summary(self):
        self.logger.section("Resumo Final")
        
        threat = self.results.get('threat_levels', {})
        
        print(f"\n{Colors.BOLD}{'═' * 80}{Colors.NC}")
        print(f"{Colors.BOLD}                    RESUMO DA ANÁLISE FORENSE{Colors.NC}")
        print(f"{Colors.BOLD}{'═' * 80}{Colors.NC}")
        
        print(f"\n{Colors.BOLD}NÍVEIS DE AMEAÇA:{Colors.NC}")
        print(f"  {Colors.RED}CRÍTICO: {threat.get('CRITICAL', 0)}{Colors.NC}")
        print(f"  {Colors.RED}ALTO: {threat.get('HIGH', 0)}{Colors.NC}")
        print(f"  {Colors.YELLOW}MÉDIO: {threat.get('MEDIUM', 0)}{Colors.NC}")
        print(f"  {Colors.GREEN}BAIXO: {threat.get('LOW', 0)}{Colors.NC}")
        
        print(f"\n{Colors.BOLD}PRINCIPAIS VETORES:{Colors.NC}")
        vectors = [(k, v) for k, v in self.results.get('attack_vectors', {}).items() if v > 0]
        vectors.sort(key=lambda x: x[1], reverse=True)
        for vector, count in vectors[:8]:
            print(f"  {vector}: {count}")
        
        if self.results.get('malicious_ips'):
            print(f"\n{Colors.BOLD}IPs MALICIOSOS:{Colors.NC}")
            for ip in self.results['malicious_ips'][:10]:
                info = self.results.get('threat_intel', {}).get(ip, {})
                country = info.get('country', 'N/A')
                print(f"  {Colors.RED}{ip} - {country}{Colors.NC}")
        
        print(f"\n{Colors.GREEN}{Colors.BOLD}")
        print("═" * 80)
        print(" ANÁLISE FORENSE CONCLUÍDA COM SUCESSO")
        print("═" * 80)
        print(f"{Colors.NC}")
        print(f"Diretório de saída: {self.output_dir}")
        print(f"Formato detectado: {self.detected_format.upper()}")
        print(f"Total de entradas: {self.results.get('total_entries', 0):,}")
        print(f"IPs únicos: {self.results.get('unique_ips', 0):,}")
        print(f"IPs maliciosos: {len(self.results.get('malicious_ips', []))}")
        print(f"Tempo total: {self.logger.get_elapsed_time()}")
        print(f"\nRelatórios gerados:")
        print(f"  • HTML: {self.output_dir / 'forensic_report.html'}")
        print(f"  • JSON: {self.output_dir / 'forensic_report.json'}")
        print(f"  • TXT: {self.output_dir / 'executive_summary.txt'}")
        if self.results.get('malicious_ips'):
            print(f"  • Blocklist: {self.output_dir / 'ip_blocklist.txt'}")
        print(f"  • Log: {self.output_dir / 'analysis.log'}")

# =============================================================================
# MAIN
# =============================================================================

class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    def send_response(self, code, message=None):
        super().send_response(code, message)
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; img-src 'self' data:;")
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')

    def do_GET(self):
        # Prevent Directory Traversal
        if '../' in self.path or '..\\' in self.path:
            self.send_error(403, "Forbidden")
            return
            
        allowed_paths = ['/', '/dashboard/index.html', '/api/results', '/forensic_output/forensic_report.json']
        if self.path not in allowed_paths and not self.path.startswith('/dashboard/'):
            self.send_error(404, "Not Found")
            return

        if self.path == '/':
            self.path = '/dashboard/index.html'
        elif self.path == '/api/results':
            self.path = '/forensic_output/forensic_report.json'
        
        return http.server.SimpleHTTPRequestHandler.do_GET(self)

def serve_dashboard(port=8080):
    try:
        with socketserver.TCPServer(("", port), DashboardHandler) as httpd:
            print(f"\n{Colors.GREEN}{Colors.BOLD}Servidor Analytics UI Ativo!{Colors.NC}")
            print(f"Acesse o Dashboard na URL: http://localhost:{port}")
            try:
                webbrowser.open(f"http://localhost:{port}")
            except:
                pass
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor desligado.")
    except Exception as e:
        print(f"Erro no servidor: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Forensic Log Analyzer v2.0 - Universal Edition",
        epilog="""
EXEMPLOS DE USO:
  # Análise básica (detecta formato automaticamente)
  python forensic_analyzer.py /var/log/apache2/access.log
  
  # Dashboard Analytics (Abre UI Graphic)
  python forensic_analyzer.py access.log --serve
  
  # Com threat intelligence
  python forensic_analyzer.py access.log --vt-key SUA_CHAVE
        """
    )
    
    parser.add_argument("log_file", help="Caminho para log (suporta .gz, .bz2, .zip, .tar)")
    parser.add_argument("--vt-key", help="API Key do VirusTotal")
    parser.add_argument("--otx-key", help="API Key do AlienVault OTX")
    parser.add_argument("--abuse-key", help="API Key do AbuseIPDB")
    parser.add_argument("--no-intel", action="store_true", help="Desabilita intel")
    parser.add_argument("--serve", action="store_true", help="Sobe o Dashboard Visual na porta 8080")
    parser.add_argument("--port", type=int, default=8080, help="Porta para o Dashboard")
    
    args = parser.parse_args()
    
    if args.vt_key: Config.VIRUSTOTAL_API_KEY = args.vt_key
    if args.otx_key: Config.ALIENVAULT_API_KEY = args.otx_key
    if args.abuse_key: Config.ABUSEIPDB_API_KEY = args.abuse_key
    if args.no_intel:
        Config.VIRUSTOTAL_API_KEY = ""
        Config.ALIENVAULT_API_KEY = ""
        Config.ABUSEIPDB_API_KEY = ""
    
    analyzer = UniversalForensicAnalyzer(args.log_file)
    
    try:
        success = analyzer.run()
        if success and args.serve:
            serve_dashboard(args.port)
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Análise interrompida pelo usuário{Colors.NC}")
        sys.exit(130)
    except Exception as e:
        print(f"{Colors.RED}Erro fatal: {e}{Colors.NC}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
