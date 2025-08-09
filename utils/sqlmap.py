import subprocess
import re
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import time
def parse_output(output: str) -> dict:
    """Lightning-fast output parser using regex pre-compilation"""
    vuln_re = re.compile(r'Parameter: (.+?)\n.*?Type: (.+?)\n.*?Title: (.+?)(?:\n|$)')
    db_re = re.compile(r'back-end DBMS: (.+)')
    table_re = re.compile(r'Database: (.+?)\nTable: (.+?)\n')
    
    return {
        'vulnerabilities': [
            {'parameter': m[0], 'type': m[1], 'title': m[2]} 
            for m in vuln_re.findall(output)
        ],
        'database': (db_re.search(output) or [''])[0],
        'tables': [
            {'database': m[0], 'table': m[1]} 
            for m in table_re.findall(output)
        ]
    }

def run_sqlmap_fast(args: list) -> dict:
    """Optimized sqlmap runner with zero disk I/O and parallel processing"""
    # Pre-defined responses for 100% automation
    responses = {
        b"continue? [y/N]": b"y\n",
        b"use common payloads? [Y/n]": b"Y\n",
        b"skip other tests? [y/N]": b"N\n",
        b"follow redirects? [Y/n]": b"Y\n"
    }

    # Critical args for speed (tuned for performance)
    speed_args = [
        '--batch', '--smart', '--keep-alive',
        '--threads=10', '--flush-session',
        '--disable-coloring', '--fresh-queries',
        '--predict-output', '--offline'
    ]

    with ThreadPoolExecutor() as executor:
        proc = subprocess.Popen(
            ['sqlmap'] + speed_args + args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        # Parallel output processing
        output = bytearray()
        future = executor.submit(proc.communicate)
        
        while not future.done():
            line = proc.stdout.read1()  # Non-blocking read
            if not line:
                break
            output.extend(line)
            
            # Ultra-fast prompt response
            for prompt, response in responses.items():
                if prompt in line:
                    proc.stdin.write(response)
                    proc.stdin.flush()
                    break

        stdout, stderr = future.result()
        parsed = parse_output((output + stdout).decode('utf-8', 'replace'))
        
        return {
            'success': proc.returncode == 0,
            'findings': parsed,
            'time': time.time() - start_time
        }
