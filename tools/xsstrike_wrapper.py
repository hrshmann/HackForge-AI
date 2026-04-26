print("XSSTRIKE WRAPPER LOADED")
import subprocess
import json
from typing import Dict, List
import re
import sys
import os
from pathlib import Path

class XSStrikeWrapper:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.payloads_tested = 0
        self.xsstrike_path = self._find_xsstrike()

    def _find_xsstrike(self):
        possible_paths = [
            Path(__file__).parent.parent / 'tools' / 'xsstrike' / 'xsstrike.py',
            'tools/xsstrike/xsstrike.py'
        ]

        for path in possible_paths:
            path = Path(path)
            if path.exists():
                return str(path.absolute())

        raise FileNotFoundError("XSStrike not found inside tools/xsstrike")

    def scan(self, timeout: int = 180) -> Dict:
        cmd = [
            sys.executable,
            self.xsstrike_path,
            '-u', self.target_url,
            '--crawl',
            '--skip-dom',
            '--threads', '5'
        ]

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=os.path.dirname(self.xsstrike_path)
            )

            stdout, stderr = process.communicate(timeout=timeout)

            results = self._parse_results(stdout)

            return {
                'vulnerable': results['vulnerable'],
                'xss_type': results['xss_type'],
                'details': results['details'],
                'confidence': results['confidence'],
                'severity': 'high' if results['vulnerable'] else 'safe'
            }

        except subprocess.TimeoutExpired:
            process.kill()
            return {
                'vulnerable': False,
                'error': 'Timeout',
                'confidence': 0.0
            }
        except Exception as e:
            return {
                'vulnerable': False,
                'error': str(e),
                'confidence': 0.0
            }

    def _parse_results(self, output: str) -> Dict:
        vulnerable = False
        xss_type = []
        details = []
        confidence = 0.0

        if re.search(r'Reflected XSS', output, re.IGNORECASE):
            vulnerable = True
            xss_type.append('Reflected')
            confidence = 0.9

        if re.search(r'Stored XSS', output, re.IGNORECASE):
            vulnerable = True
            xss_type.append('Stored')
            confidence = 0.95

        if re.search(r'DOM XSS', output, re.IGNORECASE):
            vulnerable = True
            xss_type.append('DOM-based')
            confidence = 0.85

        if vulnerable:
            details = {
                'payload': self._extract_payload(output),
                'parameter': self._extract_parameter(output),
                'context': self._extract_context(output)
            }

        return {
            'vulnerable': vulnerable,
            'xss_type': xss_type,
            'details': details,
            'confidence': confidence
        }

    def _extract_payload(self, output: str) -> str:
        payload_pattern = r"Payload:\s*(.+?)(?:\\n|$)"
        match = re.search(payload_pattern, output)
        return match.group(1).strip() if match else ''

    def _extract_parameter(self, output: str) -> str:
        param_pattern = r"Parameter:\s*(\w+)"
        match = re.search(param_pattern, output)
        return match.group(1) if match else ''

    def _extract_context(self, output: str) -> str:
        if 'attribute' in output.lower():
            return 'HTML attribute'
        elif 'script' in output.lower():
            return 'JavaScript context'
        elif 'tag' in output.lower():
            return 'HTML tag'
        return 'unknown'

print("CLASS EXISTS:", "XSStrikeWrapper" in globals())