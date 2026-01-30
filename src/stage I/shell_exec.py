import subprocess
from typing import Optional, Dict, Union

def run_shell_command(
    command: Union[str, list], 
    cwd: Optional[str] = None, 
    shell: bool = True,
    timeout: Optional[int] = 600
) -> Dict[str, Union[str, int]]:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            shell=shell,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
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
            "stderr": f"Command execution timed out ({timeout} seconds)",
            "returncode": -2
        }
    except Exception as e:
        return {
            "stdout": "",
            "stderr": f"Command execution exception: {str(e)}",
            "returncode": -1
        }
