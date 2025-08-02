import subprocess
import re
import tempfile
from pathlib import Path
from typing import Dict, Any
from concurrent.futures import ThreadPoolExecutor

def parse_toxin_output(output: str) -> Dict[str, Any]:
    """Ultra-fast XSS results parser"""
    xss_re = re.compile(
        r'\[VULNERABLE\] URL: (.+?)\n.*?'
        r'Parameter: (.+?)\n.*?'
        r'Payload: (.+?)(?:\n|$)',
        re.DOTALL
    )
    
    return {
        'vulnerabilities': [
            {'url': m[0], 'parameter': m[1], 'payload': m[2]}
            for m in xss_re.finditer(output)
        ],
        'scan_stats': {
            'requests': int(re.search(r'Total requests:\s+(\d+)', output).group(1)),
            'tested_params': int(re.search(r'Tested parameters:\s+(\d+)', output).group(1))
        }
    }

def run_toxin_scan(args: list) -> Dict[str, Any]:
    """High-performance XSS scanner with automated handling"""
    responses = {
        b"Follow redirects? [y/N]": b"y\n",
        b"Save results to file? [y/N]": b"N\n",
        b"Continue scanning? [Y/n]": b"Y\n"
    }

    speed_args = [
        '--fast',
        '--threads=10',
        '--timeout=15',
        '--no-crawl',
        '--smart',
        '--retries=1'
    ]

    with ThreadPoolExecutor() as executor:
        proc = subprocess.Popen(
            ['toxin'] + speed_args + args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1  # Line-buffered
        )

        output = bytearray()
        future = executor.submit(proc.communicate)

        while not future.done():
            chunk = proc.stdout.read1(4096)
            if not chunk:
                break
            output.extend(chunk)
            
            for prompt, response in responses.items():
                if prompt in chunk:
                    proc.stdin.write(response)
                    proc.stdin.flush()

        stdout, stderr = future.result()
        full_output = (output + stdout).decode('utf-8', 'replace')
        
        return {
            'findings': parse_toxin_output(full_output),
            'success': proc.returncode == 0,
            'raw_output': full_output[-5000:]  # Last 5KB for debugging
        }
