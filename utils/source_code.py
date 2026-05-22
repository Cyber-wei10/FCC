import os
from utils.shell_exec_simple import run_shell_command

def download_source_code(cve: str, version: str, source_code_url: str) -> bool:
    if os.path.exists(f"./{cve}-linux-{version}"):
        return True
    if os.path.exists(f"./linux-{version}.tar.xz"):
        pass
    else:
        source_code=source_code_url.format(
            version_part=version[0],
            version=version
        )
        res1 = run_shell_command(f"wget --no-check-certificate {source_code}")
        if res1["returncode"] != 0:
            return False
    temp_dir = "./temp"
    res2 = run_shell_command(f"mkdir -p {temp_dir}")
    if res2["returncode"] != 0:
        return False
    res3 = run_shell_command(f"tar -xvf linux-{version}.tar.xz -C {temp_dir}")
    if res3["returncode"] != 0:
        return False
    original_dir = f"{temp_dir}/linux-{version}"
    new_dir = f"{cve}-linux-{version}"
    res4 = run_shell_command(f"mv {original_dir} {new_dir}")
    if res4["returncode"] != 0:
        return False
    res5 = run_shell_command(f"rm -rf {temp_dir} linux-{version}.tar.xz")
    if res5["returncode"] != 0:
        return False
    return True

def delete_source_code(cve, version) -> bool:
    if os.path.exists(f"./{cve}-linux-{version}"):
        res1 = run_shell_command(f"rm -rf {cve}-linux-{version}")
        if res1["returncode"] != 0:
            return False
    return True