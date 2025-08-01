import os
import subprocess
import tempfile
from pathlib import Path

def run_sqlmap(args):
    """
    Run sqlmap with specified arguments in memory-safe mode
    Returns CompletedProcess with stdout, stderr, and returncode
    """
    # Use shared memory if available for temp files
    temp_dir = Path('/dev/shm') if Path('/dev/shm').is_dir() else None

    with tempfile.TemporaryDirectory(prefix='sqlmap_', dir=temp_dir) as tmp_dir:
        env = os.environ.copy()
        # Redirect all file storage to memory-backed temp directory
        env['HOME'] = tmp_dir
        env['TMPDIR'] = tmp_dir
        
        cmd = ['sqlmap', '--output-dir', tmp_dir, '--batch'] + args
        
        try:
            process = subprocess.run(
                cmd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False
            )
            return process
        except Exception as e:
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=-1,
                stdout=b'',
                stderr=str(e).encode()
            )
