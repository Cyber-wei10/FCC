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
    """
        Unified Shell command execution, encapsulating subprocess to provide standardized return results
        
        Parameters:
            command: Command to execute (string/list, when using list, shell must be set to False)
            cwd: Working directory for command execution (default None, uses current directory)
            shell: Whether to use Shell for execution (default True, compatible with string commands)
            timeout: Command timeout in seconds (default 600 seconds, None means no limit)
        
        Returns:
            dict: Contains stdout (standard output), stderr (standard error), returncode (return code)
        """
    if not shell and not isinstance(command, list):
        return {
            "stdout": "",
            "stderr": "When shell=False, command must be a list",
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
                stderr += f"Failed to terminate process: {str(e)}"
            
            stderr += f"\nCommand execution timeout ({timeout} seconds)"
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