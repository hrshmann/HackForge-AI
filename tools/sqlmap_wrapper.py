print("SQLMAP WRAPPER LOADED")
import subprocess
import os
import re
import tempfile
import sys
from typing import Dict, List
from pathlib import Path

class SQLMapWrapper:
    def __init__(self, target_url: str, data: Dict = None):
        self.target_url = target_url
        self.data = data
        self.sqlmap_path = self._find_sqlmap()
        
    def _find_sqlmap(self):
        """Find SQLmap installation"""
        possible_paths = [
            'tools/sqlmap/sqlmap.py',
            'tools\\sqlmap\\sqlmap.py',
            Path(__file__).parent.parent / 'tools' / 'sqlmap' / 'sqlmap.py'
        ]
        
        for path in possible_paths:
            path = Path(path)
            if path.exists():
                return str(path.absolute())
        
        raise FileNotFoundError("SQLmap not found. Install: cd tools && git clone https://github.com/sqlmapproject/sqlmap.git")
    
    def scan(self, level: int = 2, risk: int = 1, timeout: int = 300) -> Dict:
        """Run SQLmap scan"""
        
        print(f"🔍 Running SQLmap on {self.target_url}...")
        
        cmd = [
            sys.executable,  # Use current Python
            self.sqlmap_path,
            '-u', self.target_url,
            '--batch',  # Non-interactive
            '--level', str(level),
            '--risk', str(risk),
            '--threads', '2',
            '--timeout', '30',
            '--retries', '1',
            '--technique', 'BEUST',  # All techniques
            '--random-agent',
            '--skip-waf'
        ]
        
        if self.data:
            data_str = '&'.join([f"{k}={v}" for k, v in self.data.items()])
            cmd.extend(['--data', data_str])
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=os.path.dirname(self.sqlmap_path)  # Run from SQLmap directory
            )
            
            stdout, stderr = process.communicate(timeout=timeout)
            
            return self._parse_output(stdout)
            
        except subprocess.TimeoutExpired:
            process.kill()
            print("  ⚠ SQLmap timeout")
            return {'vulnerable': False, 'error': 'Timeout', 'confidence': 0.0}
        except Exception as e:
            print(f"  ✗ SQLmap error: {str(e)}")
            return {'vulnerable': False, 'error': str(e), 'confidence': 0.0}
    
    def _parse_output(self, output: str) -> Dict:
        """Parse SQLmap output"""
        
        vulnerable = False
        details = {}
        confidence = 0.0
        
        # Check for vulnerability indicators
        vuln_patterns = [
            r'Parameter.*?appears to be.*?injectable',
            r'is vulnerable',
            r'sqlmap identified the following injection',
            r'Type:.*?(boolean-based|time-based|error-based|UNION|stacked)'
        ]
        
        for pattern in vuln_patterns:
            if re.search(pattern, output, re.IGNORECASE):
                vulnerable = True
                break
        
        if vulnerable:
            # Extract injection type
            type_match = re.search(r'Type:\s*([^\n]+)', output)
            if type_match:
                details['injection_type'] = type_match.group(1).strip()
            
            # Extract database
            db_match = re.search(r'back-end DBMS:\s*([^\n]+)', output)
            if db_match:
                details['database'] = db_match.group(1).strip()
            
            # Extract payload
            payload_match = re.search(r'Payload:\s*([^\n]+)', output)
            if payload_match:
                details['payload'] = payload_match.group(1).strip()
            
            # Extract parameter
            param_match = re.search(r'Parameter:\s*(\w+)', output)
            if param_match:
                details['parameter'] = param_match.group(1)
            
            confidence = 0.95
            
            print(f"  ✅ SQL Injection found! ({details.get('injection_type', 'unknown')})")
        else:
            print(f"  ✓ No SQL injection detected")
        
        return {
            'vulnerable': vulnerable,
            'details': details,
            'confidence': confidence,
            'severity': 'critical' if vulnerable else 'safe',
            'raw_output': output[:500]  # First 500 chars
        }
print("CLASS EXISTS:", "SQLMapWrapper" in globals())