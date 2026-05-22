import subprocess
from typing import Optional, Dict, Union

def run_shell_command(
    command: Union[str, list], 
    cwd: Optional[str] = None, 
    shell: bool = True,
    timeout: Optional[int] = 6000
) -> Dict[str, Union[str, int]]:
    """
    Unified Shell command execution, encapsulating subprocess to provide standardized return results
    
    Parameters:
        command: Command to execute (string/list, when using list, shell must be set to False)
        cwd: Working directory for command execution (default None, uses current directory)
        shell: Whether to use Shell for execution (default True, compatible with string commands)
        timeout: Command timeout in seconds (default 60 seconds, None means no limit)
    
    Returns:
        dict: Contains stdout (standard output), stderr (standard error), returncode (return code)
    """
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            shell=shell,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )
        return {
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": f"Command execution timeout ({timeout} seconds)",
            "returncode": -2
        }
    except Exception as e:
        return {
            "stdout": "",
            "stderr": f"Command execution exception: {str(e)}",
            "returncode": -1
        }
