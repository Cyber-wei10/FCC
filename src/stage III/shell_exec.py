import subprocess
import time
import signal
import os
from typing import Optional, Dict, Union

def run_shell_command(
    command: Union[str, list], 
    cwd: Optional[str] = None, 
    shell: bool = True,
    timeout: Optional[int] = 600
) -> Dict[str, Union[str, int]]:
    
    if not shell and not isinstance(command, list):
        return {
            "stdout": "",
            "stderr": "When shell=False, command must be passed as a list",
            "returncode": -3
        }
    
    if cwd and not os.path.exists(cwd):
        return {
            "stdout": "",
            "stderr": f"Specified working directory does not exist: {cwd}",
            "returncode": -4
        }

    process = None
    try:
        preexec_fn = os.setsid
        process = subprocess.Popen(
            command,
            cwd=cwd,
            shell=shell,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            preexec_fn=preexec_fn
        )
        
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            returncode = process.returncode
        except subprocess.TimeoutExpired:
            stdout = ""
            stderr = ""
            
            try:
                if process.stdout:
                    stdout = process.stdout.read()
                if process.stderr:
                    stderr = process.stderr.read()
            except Exception as e:
                stderr = f"Failed to read timeout output: {str(e)}"
            
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                time.sleep(0.5)
                if process.poll() is None:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except Exception as e:
                stderr += f"\nFailed to kill process: {str(e)}"
            
            stderr += f"\nCommand execution timed out ({timeout} seconds)"
            returncode = -2
        
        return {
            "stdout": stdout.strip(),
            "stderr": stderr.strip(),
            "returncode": returncode
        }
    except Exception as e:
        if process and process.poll() is None:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except:
                pass
        return {
            "stdout": "",
            "stderr": f"Command execution exception: {str(e)}",
            "returncode": -1
        }
if __name__ == "__main__":
    result = run_shell_command('echo "hello world"', timeout=1)
    print(result)
