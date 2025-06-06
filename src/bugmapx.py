#!/usr/bin/env python3
# -*- coding: future_fusions -*-
"""
██████╗ ██╗   ██╗ ██████╗ ███╗   ███╗ █████╗ ██████╗ ██╗  ██╗
██╔══██╗██║   ██║██╔════╝ ████╗ ████║██╔══██╗██╔══██╗╚██╗██╔╝
██████╔╝██║   ██║██║  ███╗██╔████╔██║███████║██████╔╝ ╚███╔╝ 
██╔══██╗██║   ██║██║   ██║██║╚██╔╝██║██╔══██║██╔═══╝  ██╔██╗ 
██████╔╝╚██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║     ██╔╝ ██╗
╚═════╝  ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝
"""
import os
import sys
import json
import re
import asyncio
import aiohttp
import dns.resolver
import nmap
import random
import time
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn
import yaml
import toml
import subprocess
import logging
from datetime import datetime
from transformers import pipeline
import torch
import hashlib
import stem
from stem.control import Controller
from fake_useragent import UserAgent
from bs4 import BeautifulSoup
from typing import Dict, List, Set, Any, Optional, Tuple
from cryptography.fernet import Fernet
from shutil import which

# ===== CONSTANTS =====
TOR_PORTS = [9050, 9150]
ENUM_TOOLS = {
    "subfinder": "subfinder -d {target} -silent",
    "amass": "amass enum -passive -d {target}",
    "assetnote": "curl -s 'https://api.assetnote.io/v1/subdomains?domain={target}' -H 'Authorization: Bearer {api_key}'",
    "sublist3r": "sublist3r -d {target} -o /dev/stdout",
    "findomain": "findomain -t {target} -q",
    "ffuf": "ffuf -w wordlist.txt -u https://{target}/FUZZ -fs 0",
    "shodan": "shodan domain {target} --fields hostnames",
    "crt.sh": "curl -s 'https://crt.sh/?q=%25.{target}&output=json'",
    "securitytrails": "curl -s 'https://api.securitytrails.com/v1/domain/{target}/subdomains' -H 'APIKEY: {api_key}'",
    "dnsdumpster": "curl -s 'https://dnsdumpster.com' -X POST -d 'targetip={target}'",
    "google": "googlesearch -q 'site:{target}'"
}
PORT_SCANNERS = {
    "nmap": "nmap -T4 -p- {target}",
    "masscan": "masscan -p1-65535 {target} --rate=1000",
    "netcat": "nc -zv {target} 1-65535 2>&1 | grep succeeded"
}
AI_MODELS = {
    "light": "distilbert-base-uncased",
    "medium": "microsoft/phi-2",
    "heavy": "gpt-4"
}
ENCRYPTED_LOG_FORMAT = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# ===== ENCRYPTED LOG HANDLER =====
class EncryptedFileHandler(logging.Handler):
    def __init__(self, filename: str, encryption_key: bytes):
        super().__init__()
        self.filename = filename
        self.cipher = Fernet(encryption_key)
        
    def emit(self, record):
        try:
            msg = self.format(record)
            encrypted = self.cipher.encrypt(msg.encode())
            with open(self.filename, 'ab') as f:
                f.write(encrypted + b'\n')
        except Exception:
            self.handleError(record)

# ===== CONFIG MANAGER =====
class ConfigManager:
    def __init__(self):
        self.encryption_key = Fernet.generate_key()
        self.config = self._load_config()
        self.logger = self._setup_secure_logger()
        
    def _load_config(self) -> Dict[str, Any]:
        config_paths = [
            Path("~/.bugmapx/config.yaml").expanduser(),
            Path("/etc/bugmapx/config.yaml"),
            Path("config.yaml")
        ]
        
        for path in config_paths:
            if path.exists():
                with open(path) as f:
                    return yaml.safe_load(f)
        
        return {
            "tor": {"enabled": False, "password": os.urandom(16).hex()},
            "ai": {"model": "medium", "enabled": True},
            "scan": {"aggression": 5, "timeout": 30},
            "apis": {"shodan": "", "securitytrails": ""}
        }
    
    def _setup_secure_logger(self) -> logging.Logger:
        logger = logging.getLogger('BugMapX')
        logger.setLevel(logging.DEBUG)
        
        # Encrypted file handler
        fh = EncryptedFileHandler('bugmapx_audit.log.enc', self.encryption_key)
        fh.setLevel(logging.INFO)
        fh.setFormatter(ENCRYPTED_LOG_FORMAT)
        logger.addHandler(fh)
        
        return logger

# ===== TOOL VALIDATOR =====
class ToolValidator:
    @staticmethod
    def is_tool_installed(tool_name: str) -> bool:
        """Check if CLI tool is available in PATH"""
        return which(tool_name) is not None
    
    @staticmethod
    def validate_enum_tools() -> Dict[str, bool]:
        """Check availability of enumeration tools"""
        return {
            tool: ToolValidator.is_tool_installed(tool.split()[0])
            for tool in ENUM_TOOLS.values()
            if not tool.startswith('curl')  # Skip API-based tools
        }

# ===== SUBDOMAIN ENUMERATOR =====
class SubdomainHunter:
    def __init__(self, target: str, config: ConfigManager):
        self.target = target
        self.console = Console()
        self.config = config
        self.results: Set[str] = set()
        self.available_tools = ToolValidator.validate_enum_tools()
    
    async def run_all(self) -> List[str]:
        """Execute all available enumeration tools"""
        tasks = []
        
        for tool_name, cmd_template in ENUM_TOOLS.items():
            # Skip unavailable CLI tools
            if tool_name in self.available_tools and not self.available_tools[tool_name]:
                self.config.logger.warning(f"Skipping unavailable tool: {tool_name}")
                continue
                
            tasks.append(asyncio.create_task(self._run_tool(tool_name, cmd_template)))
        
        await asyncio.gather(*tasks)
        return sorted(self.results)
    
    async def _run_tool(self, tool_name: str, cmd_template: str):
        """Execute specific enumeration tool"""
        try:
            cmd = cmd_template.format(
                target=self.target,
                api_key=self.config.config["apis"].get(tool_name, "")
            )
            result = await self._execute_cmd(cmd)
            self._parse_output(tool_name, result)
        except Exception as e:
            self.config.logger.error(f"{tool_name} failed: {str(e)}")
    
    async def _execute_cmd(self, cmd: str) -> str:
        """Execute shell command asynchronously"""
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            self.config.logger.warning(f"Command failed: {cmd}\n{stderr.decode()}")
        return stdout.decode()
    
    def _parse_output(self, tool: str, output: str):
        """Parse tool-specific output with enhanced error handling"""
        try:
            if tool == "crt.sh":
                data = json.loads(output)
                for item in data:
                    self.results.add(item['name_value'].lower())
            elif tool == "google":
                for line in output.splitlines():
                    if self.target in line:
                        self.results.add(line.split(' ')[0])
            elif tool == "securitytrails":
                data = json.loads(output)
                for subdomain in data.get('subdomains', []):
                    self.results.add(f"{subdomain}.{self.target}")
            elif tool == "shodan":
                for hostname in output.splitlines():
                    if hostname.strip():
                        self.results.add(hostname.strip())
            else:
                for line in output.splitlines():
                    if self.target in line and not line.startswith(('http', '#')):
                        sub = line.strip()
                        if re.match(r"^[a-z0-9.-]+$", sub):
                            self.results.add(sub)
        except json.JSONDecodeError:
            self.config.logger.error(f"JSON parse failed for {tool}")
        except Exception as e:
            self.config.logger.error(f"Parser error for {tool}: {str(e)}")

# ===== AI VULN ANALYZER =====
class NeuroAnalyzer:
    def __init__(self, model_size: str = "medium"):
        self.model_size = model_size
        self.api_mode = model_size == "heavy"
        
        if not self.api_mode:
            self.model = pipeline(
                "text-classification",
                model=AI_MODELS[model_size],
                torch_dtype=torch.float16 if torch.cuda.is_available() else None,
                device=0 if torch.cuda.is_available() else -1
            )
    
    def analyze_service(self, service_info: Dict) -> Dict:
        """Analyze service for vulnerabilities with fallback handling"""
        if self.api_mode:
            return self._gpt4_analysis(service_info)
        else:
            return self._local_analysis(service_info)
    
    def _gpt4_analysis(self, service_info: Dict) -> Dict:
        """Use GPT-4 API for vulnerability analysis"""
        # This would be replaced with actual API calls
        return {
            "vulnerability_type": "API-based analysis not implemented",
            "severity": "High",
            "confidence_score": 0.85,
            "remediation_advice": "Implement API integration in production",
            "reference_links": ["https://platform.openai.com/docs/api-reference"]
        }
    
    def _local_analysis(self, service_info: Dict) -> Dict:
        """Local model analysis with JSON fallback"""
        prompt = f"""
        [SECURITY ANALYSIS] Service: {service_info}
        Identify potential vulnerabilities and provide JSON with:
        - vulnerability_type
        - severity (Low/Medium/High/Critical)
        - confidence_score (0-1)
        - remediation_advice
        - reference_links
        """
        try:
            result = self.model(prompt)
            return self._safe_json_parse(result[0]['generated_text'])
        except Exception as e:
            return {"error": str(e)}
    
    def _safe_json_parse(self, text: str) -> Dict:
        """Extract JSON from text with fallback"""
        try:
            # Look for JSON-like substring
            json_str = re.search(r'\{.*\}', text, re.DOTALL)
            if json_str:
                return json.loads(json_str.group(0))
            return {"raw_output": text}
        except json.JSONDecodeError:
            return {"raw_output": text}

# ===== TOR MANAGER =====
class TorManager:
    def __init__(self, password: str):
        self.controller: Optional[Controller] = None
        self.session: Optional[aiohttp.ClientSession] = None
        self.password = password
    
    async def __aenter__(self):
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc, tb):
        await self.close()
    
    async def start(self):
        """Initialize Tor connection"""
        try:
            self.controller = Controller.from_port(port=random.choice(TOR_PORTS))
            self.controller.authenticate(password=self.password)
            self.session = aiohttp.ClientSession(
                trust_env=True,
                connector=aiohttp.TCPConnector(ssl=False)
        except Exception as e:
            logging.error(f"Tor initialization failed: {str(e)}")
            raise
    
    async def rotate(self):
        """Rotate Tor identity with jitter"""
        if self.controller:
            self.controller.signal(stem.Signal.NEWNYM)
            await asyncio.sleep(random.uniform(1, 3))
    
    async def close(self):
        """Cleanup resources"""
        if self.session:
            await self.session.close()
        if self.controller:
            self.controller.close()

# ===== MAIN ENGINE =====
class BugMapX:
    def __init__(self, target: str):
        self.target = target
        self.console = Console()
        self.config = ConfigManager()
        self.dns = DNSWarrior()
        self.tor = None
        self.ai = NeuroAnalyzer(self.config.config["ai"]["model"])
        self.results: Dict[str, Any] = {
            "target": target,
            "subdomains": {},
            "vulnerabilities": []
        }
    
    async def execute(self):
        """Main execution flow with Tor context management"""
        if self.config.config["tor"]["enabled"]:
            async with TorManager(self.config.config["tor"]["password"]) as tor:
                self.tor = tor
                await self._run_scan()
        else:
            await self._run_scan()
        
        self._generate_report()
    
    async def _run_scan(self):
        """Scanning workflow"""
        with Progress() as progress:
            # Subdomain enumeration
            task = progress.add_task("[cyan]Enumerating subdomains...", total=len(ENUM_TOOLS))
            hunter = SubdomainHunter(self.target, self.config)
            subdomains = await hunter.run_all()
            progress.update(task, completed=len(ENUM_TOOLS))
            
            # Scanning phase
            scan_task = progress.add_task("[green]Scanning targets...", total=len(subdomains))
            for subdomain in subdomains:
                await self._scan_subdomain(subdomain, progress, scan_task)
    
    async def _scan_subdomain(self, subdomain: str, progress: Progress, task_id: int):
        """Scan individual subdomain"""
        try:
            ips = self.dns.resolve(subdomain)
            self.results["subdomains"][subdomain] = {"ips": ips}
            
            for ip in ips:
                scanner = PortAssassin(ip, self.tor is not None)
                scan_result = scanner.scan()
                self.results["subdomains"][subdomain]["scan"] = scan_result
                
                # AI analysis
                if self.config.config["ai"]["enabled"]:
                    for port, service in scan_result["services"].items():
                        ai_result = self.ai.analyze_service(service)
                        self.results["vulnerabilities"].append({
                            "target": f"{subdomain}:{port}",
                            "service": service,
                            "analysis": ai_result
                        })
                
                # Rotate Tor every 3 scans
                if self.tor and len(self.results["vulnerabilities"]) % 3 == 0:
                    await self.tor.rotate()
        except Exception as e:
            self.config.logger.error(f"Scan failed for {subdomain}: {str(e)}")
        finally:
            progress.update(task_id, advance=1)

# ... [Other classes remain optimized as before] ...
class ToolValidator:
    @staticmethod
    def is_tool_installed(tool_name: str) -> bool:
        return which(tool_name) is not None

def _safe_json_parse(self, text: str) -> Dict:
    try:
        json_str = re.search(r'\{.*\}', text, re.DOTALL)
        return json.loads(json_str.group(0)) if json_str else {"raw_output": text}
    except:
        return {"raw_output": text}

async with TorManager(self.config.config["tor"]["password"]) as tor:
    self.tor = tor
    await self._run_scan()

class EncryptedFileHandler(logging.Handler):
    def emit(self, record):
        encrypted = self.cipher.encrypt(msg.encode())
        with open(self.filename, 'ab') as f:
            f.write(encrypted + b'\n')
            try:
    data = json.loads(output)
except json.JSONDecodeError:
    self.config.logger.error(f"JSON parse failed for {tool}")
tor:
  enabled: true
  password: "{{ openssl rand -hex 16 }}"  # Generated during install
