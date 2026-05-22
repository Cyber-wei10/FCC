import os
import json
import pandas as pd
from typing import Dict, List, Set
from utils.shell_exec import run_shell_command
import requests
import time
import subprocess
import glob
import re
from utils.source_code import *
from utils.check_compile import verify_config
import subprocess
import threading
import time
import psutil
class Config_Minimization:
    def __init__(self, api_key: str, base_url: str, model: str,source_code_url: str, qemu_dir: str):
        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self.DEF_ENABLED_CONS=["CONFIG_FRAME_POINTER","CONFIG_KALLSYMS","CONFIG_KALLSYMS_ALL","CONFIG_DEBUG_INFO","CONFIG_BINFMT_MISC","CONFIG_USER_NS","CONFIG_NET_NS","CONFIG_E1000","CONFIG_E1000E","CONFIG_SYSVIPC","CONFIG_DEBUG_INFO_DWARF4","CONFIG_CONFIGFS_FS","CONFIG_SECURITYFS","CONFIG_KCOV","CONFIG_KASAN","CONFIG_KASAN_INLINE","CONFIG_USERFAULTFD","CONFIG_KEY_DH_OPERATIONS"]
        self.source_code_url=source_code_url
        self.qemu_dir=qemu_dir
    
    def dfs(self, config: str, graph: Dict[str, List[str]], visited: Set[str]):

        if config not in graph or config in visited or config.startswith("None"):
            return
        visited.add(config)
        for neighbor in graph[config]:
            if neighbor not in visited:
                visited.add(neighbor)
                self.dfs(neighbor, graph, visited)

    def call_llm_api(self, prompt: str) -> list:

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        data = {
            "model": "deepseek-v4-flash",
            "messages": [
                {"role": "system", "content": "You are a professional Linux kernel configuration analyst, strictly follow the output requirements."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.0,
            "max_tokens": 5000,
            "stream": False
        }
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    url=self.base_url,
                    headers=headers,
                    data=json.dumps(data),
                    timeout=300,
                    verify=False
                )
                response_json = response.json()
                
                content = response_json["choices"][0]["message"]["content"].strip()
                tokens = response_json["usage"]["total_tokens"]
                
                return content, tokens

            except requests.exceptions.RequestException as e:
                print(f"[Stage 3] [WARNING] HTTP request failed (attempt {attempt + 1}/{max_retries}): {str(e)}")
                if attempt < max_retries - 1:
                    print(f"[Stage 3] [INFO] Retrying in 2 seconds...")
                    time.sleep(2)
                else:
                    print(f"[Stage 3] [ERROR] All {max_retries} attempts failed, returning default result")
                    return "Vulnerability not triggered", -1
            except KeyError as e:
                print(f"[Stage 3] [WARNING] Response format parsing failed (attempt {attempt + 1}/{max_retries}): missing field {e}")
                if attempt < max_retries - 1:
                    print(f"[Stage 3] [INFO] Retrying in 2 seconds...")
                    time.sleep(2)
                else:
                    print(f"[Stage 3] [ERROR] All {max_retries} attempts failed, returning default result")
                    return "Vulnerability not triggered", -1
            except Exception as e:
                print(f"[Stage 3] [WARNING] API call failed (attempt {attempt + 1}/{max_retries}): {str(e)}")
                if attempt < max_retries - 1:
                    print(f"[Stage 3] [INFO] Retrying in 2 seconds...")
                    time.sleep(2)
                else:
                    print(f"[Stage 3] [ERROR] All {max_retries} attempts failed, returning default result")
                    return "Vulnerability not triggered", -1
        return "Vulnerability not triggered", -1

    def check_vulnerability_with_llm(self, reference_output: str, test_output: str, cve: str, config: str) -> bool:

        prompt = f"""
        I am testing Linux kernel {cve} vulnerability.
        Please determine whether the test result shows the vulnerability EXISTS OR IS TRIGGERED, based purely on comparing with the reference result.

        [Reference Result] (Vulnerability triggered state):
        {reference_output}

        [Current Test Result]:
        {test_output}

        RULES:
        Rule 1. If both reference and current test contain similar error indicators such as KASAN, BUG, Oops, Call Trace, or kernel panic, output "Vulnerability confirmed".

        Rule 2. If neither reference nor current test contains any of these error indicators, compare their output similarity. If they show the same behavior pattern or similar output features, output "Vulnerability confirmed". Otherwise output "Vulnerability not triggered".

        Rule 3. If reference contains error indicators but current test does not, output "Vulnerability not triggered".

        Only output one of the two phrases: "Vulnerability confirmed" or "Vulnerability not triggered"
        """


        llm_result, tokens = self.call_llm_api(prompt)
        if "Vulnerability confirmed" in llm_result:
            return True,tokens
        else:
            return False,tokens
    def kill_qemu_processes(self):
        """
        Clean up all QEMU processes to prevent memory usage and resource leaks
        """
        try:
            killed_count = 0
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if proc.info['name'] and 'qemu-system-x86_64' in proc.info['name'].lower():
                        print(f"[Stage 3] [INFO] Killing qemu process: PID={proc.info['pid']}, Name={proc.info['name']}")
                        proc.kill()
                        killed_count += 1
                    elif proc.info['cmdline']:
                        cmdline = ' '.join(proc.info['cmdline'])
                        if 'qemu-system-x86_64' in cmdline.lower():
                            print(f"[Stage 3] [INFO] Killing qemu process: PID={proc.info['pid']}, Cmdline={cmdline[:100]}")
                            proc.kill()
                            killed_count += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            time.sleep(2)
            if killed_count > 0:
                print(f"[Stage 3] [INFO] Total killed {killed_count} qemu process(es)")
        except Exception as e:
            print(f"[Stage 3] [WARNING] Failed to kill qemu processes: {str(e)}")

    def run_poc_test(self, cve: str, exp_dir: str, exp_name: str, poc_time: float=1.0) -> tuple:
        """
        Keep the original interface unchanged:
        Returns: (whether command was sent for execution successfully, pure output after POC execution, QEMU startup time)
        Output only contains content after ./poc execution, excluding boot logs
        Supports passing \n in exp_name to split multi-line commands
        Supports passing ^C in exp_name to indicate sending Ctrl+C
        Automatic output truncation: from beginning -> first ERROR/KASAN/BUG/Call Trace + 10 lines after
        """
        vm_output = []
        qemu_process = None
        vm_ready = threading.Event()
        qemu_boot_time = -1

        PROMPT_PATTERNS = [
            r'\s*syzkaller login:',
            r'\s*Password:',
            r'\s*~.*\s*[#$]',
            r'\s*/.*\s*[#$]',
            r'\s*[#$]', 
        ]
        def read_output_thread():
            buffer = ""
            while True:
                try:
                    char = qemu_process.stdout.read(1)
                    if not char:
                        if vm_ready.is_set():
                            break
                        time.sleep(0.001)
                        continue
                    buffer += char
                    for p in PROMPT_PATTERNS:
                        if re.search(p, buffer):
                            if not vm_ready.is_set():
                                print(f"[Stage 3] [DEBUG] Detected command prompt: {buffer}")
                                vm_ready.set()
                                break
                    if char == "\n":
                        vm_output.append(buffer)
                        buffer = ""

                except:
                    break

        print(f"[Stage 3] Starting QEMU test...")
        try:
            qemu_start_time = time.time()
            qemu_process = subprocess.Popen(
                "sh ./start.sh",
                cwd=exp_dir,
                shell=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=0,
                universal_newlines=True
            )

            t = threading.Thread(target=read_output_thread, daemon=True)
            t.start()

            print(f"[Stage 3] [INFO] Waiting for VM to boot (max 60 seconds)...")
            boot_success = False
            for _ in range(60):
                if vm_ready.is_set():
                    boot_success = True
                    break
                if qemu_process.poll() is not None:
                    print(f"[Stage 3] [ERROR] QEMU process died immediately!")
                    self.kill_qemu_processes()
                    return False, "Failed to boot QEMU", -1
                time.sleep(0.5)

            if not boot_success:
                print(f"[Stage 3] [ERROR] QEMU boot timeout (60s), no prompt")
                self.kill_qemu_processes()
                return False, "Failed to boot QEMU", -1

            
            qemu_boot_time = time.time() - qemu_start_time
            print(f"[Stage 3] [INFO] VM is ready, boot time: {qemu_boot_time:.2f}s")

            before_poc_length = len(vm_output)

            command_lines = exp_name.split(r"\n")
            for cmd_line in command_lines:
                cmd_line = cmd_line.strip()
                if not cmd_line:
                    continue
                print(cmd_line)
                if cmd_line == "^C":
                    print(f"[Stage 3] [INFO] Sending Ctrl+C")
                    qemu_process.stdin.write("\x03")
                    qemu_process.stdin.flush()
                    time.sleep(0.5)
                    continue
                print(f"[Stage 3] Executing: {cmd_line}")
                qemu_process.stdin.write(f"{cmd_line}\n")
                qemu_process.stdin.flush()
                time.sleep(0.3)

            if poc_time > 0:
                time.sleep(poc_time)
            else:
                time.sleep(1)

            raw_lines = vm_output[before_poc_length:]
            raw_lines = [line.rstrip() for line in raw_lines if line.strip()]

            KEYWORDS = [r"BUG", r"KASAN", r"Call Trace"]
            pattern = re.compile("|".join(KEYWORDS), re.IGNORECASE)
            split_idx = -1

            for i, line in enumerate(raw_lines):
                if pattern.search(line):
                    split_idx = i
                    break

            if split_idx != -1:
                end_idx = min(split_idx + 11, len(raw_lines))
                if split_idx>=15:
                    poc_output_lines = raw_lines[:10]+raw_lines[split_idx-5:end_idx]
                else:
                    poc_output_lines = raw_lines[:end_idx]
            else:
                poc_output_lines = raw_lines[:50]

            temp = [line for line in poc_output_lines if line.strip()]
            poc_output=temp[:2]
            for i in range(2, len(temp)):
                if temp[i]!=temp[i-2]:
                    poc_output.append(temp[i])

            poc_output_str = "\n".join(poc_output)
            command_success = True

        except Exception as e:
            print(f"[Stage 3] [ERROR] Exception: {e}")
            import traceback
            traceback.print_exc()
            poc_output_str = f"Execution exception: {str(e)}"
            command_success = False
            qemu_boot_time = -1
        finally:
            try:
                if qemu_process:
                    qemu_process.stdin.close()
                    qemu_process.terminate()
                    qemu_process.kill()
            except:
                pass
            self.kill_qemu_processes()

        return command_success, poc_output_str, qemu_boot_time


    def extract_configs(self, config_file_path: str) -> List[str]:

        configs = []
        try:
            with open(config_file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('CONFIG_') and (line.endswith('=y') or line.endswith('=m')):
                        configs.append(line.split('=')[0].strip())
        except Exception as e:
            print(f"[Stage 3] Failed to extract configuration items: {str(e)}")
        return configs

    def patch_kernel(self, cve: str, patch_path: str):
        """
        Batch patch function
        
        Parameters:
        patch_path: str - Path to patch folder
        
        Functionality:
        - Traverse all patch files in the patch_path folder
        - Execute patch commands one by one in the current directory
        - Skip on patch failure and continue to the next
        
        Returns:
        dict - Contains statistics of successful and failed patches
        """
        if not os.path.exists(patch_path):
            print(f"[Stage 3] [ERROR] Patch folder does not exist: {patch_path}")
            return {"success": 0, "failed": 0, "total": 0}
        
        patch_files = glob.glob(os.path.join(patch_path, "*.patch"))
        
        if not patch_files:
            print(f"[Stage 3] [WARNING] No patch files found: {patch_path}")
            return {"success": 0, "failed": 0, "total": 0}
        
        patch_files.sort()
        success_count = 0
        failed_count = 0
        failed_patches = []
        
        for patch_file in patch_files:
            patch_name = os.path.basename(patch_file)
            print(f"[Stage 3] [INFO] Applying patch: {patch_name}")
            
            try:
                result = subprocess.run(
                    ["patch", "-p1", "-N", "-f", "-i", patch_file],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if result.returncode == 0:
                    if "Reversed (or previously applied) patch detected" in result.stdout or \
                    "Assume -R" in result.stdout:
                        print(f"[Stage 3] [INFO] Patch already applied, skipping: {patch_name}")
                        success_count += 1
                    else:
                        print(f"[Stage 3] [SUCCESS] Patch applied successfully: {patch_name}")
                        success_count += 1
                else:
                    print(f"[Stage 3] [FAILED] Patch application failed: {patch_name}")
                    failed_count += 1
                    failed_patches.append(patch_name)
            except subprocess.TimeoutExpired:
                print(f"[Stage 3] [FAILED] Patch application timeout: {patch_name}")
                failed_count += 1
                failed_patches.append(patch_name)
            except Exception as e:
                print(f"[Stage 3] [FAILED] Patch application exception: {patch_name}, Error: {str(e)}")
                failed_count += 1
                failed_patches.append(patch_name)
        
        if cve=="CVE-2021-42008":
            run_shell_command(f"patch -p1 -R -f -i {os.path.join(patch_path, 'CVE-2021-42008-patch2.txt')}")
            run_shell_command(f"patch -p1 -R -f -i {os.path.join(patch_path, 'CVE-2021-42008-patch1.txt')}")

        sh_files = glob.glob(os.path.join(patch_path, "*.sh"))
        if sh_files:
            for sh_file in sh_files:
                sh_name = os.path.basename(sh_file)
                print(f"[Stage 3] [INFO] Executing sh file: {sh_name}")
                try:
                    subprocess.run(["sh", sh_file], check=True, timeout=60)
                    print(f"[Stage 3] [SUCCESS] sh file executed successfully: {sh_name}")
                except subprocess.CalledProcessError as e:
                    print(f"[Stage 3] [FAILED] sh file execution failed: {sh_name}, Error: {e}")
                except subprocess.TimeoutExpired:
                    print(f"[Stage 3] [FAILED] sh file execution timeout: {sh_name}")
                except Exception as e:
                    print(f"[Stage 3] [ERROR] sh file execution exception: {sh_name}, Error: {str(e)}")
        print(f"[Stage 3] \n[INFO] Patch application completed")
        print(f"[Stage 3] [INFO] Total: {len(patch_files)} patches, Success: {success_count}, Failed: {failed_count}")
        
        if failed_patches:
            print(f"[Stage 3] [INFO] Failed patches list:")
            for patch in failed_patches:
                print(f"[Stage 3]   - {patch}")
        
        return {
            "success": success_count,
            "failed": failed_count,
            "total": len(patch_files),
            "failed_patches": failed_patches
        }

    def is_arch_valid_config(self, config_name: str, config_file: str = "./.config") -> bool:
        """
        Determine if a CONFIG_ item is actually valid/exists under the current architecture
        return: True=valid and needs testing  False=architecture-independent invalid configuration, skip and delete directly
        """
        if not os.path.exists(config_file):
            return False
        valid_set = set()
        with open(config_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("CONFIG_") and ("=y" in line or "=m" in line):
                    key = line.split("=")[0].strip()
                    valid_set.add(key)
        return config_name in valid_set

    def dfs_enable(self, config: str, dependency_graph: dict):
        """
        Recursively enable config items related to the given config in the dependency graph
        """
        if config not in dependency_graph:
            if (not config.startswith("None")) and (not "DEBUG_INFO_BTF" in config):
                run_shell_command(f"./scripts/config --enable {config}")
            return
        for neighbor in dependency_graph[config]:
            if neighbor.startswith("None"):
                continue
            self.dfs_enable(neighbor, dependency_graph)
        run_shell_command(f"./scripts/config --enable {config}")

    def config_mini(self,cve_list=[]):
        df = pd.read_excel("Stage2_cve_configs.xlsx")
        test_dict={}
        for index, row in df.iterrows():
            start_time = time.time()
            cve = row["cve"]
            test_dict[cve]={}
            version = str(row["version"])
            if "poc_time" in row and not pd.isna(row["poc_time"]):
                poc_time = float(row["poc_time"])
            else:
                poc_time = -1
            kernel_dir = row.get("kernel_dir", "") if "kernel_dir" in row else ""
            if pd.isna(kernel_dir):
                kernel_dir = ""
            kernel_dir = str(kernel_dir).strip() if kernel_dir else ""
            if cve_list and cve not in cve_list:
                continue
            if isinstance(row["init_configs"], str):
                initial_configs = [config.strip() for config in row["init_configs"].split(",")]
            else:
                initial_configs = row["init_configs"]
                if isinstance(initial_configs, list):
                    initial_configs = [str(config).strip() for config in initial_configs]
                else:
                    print(f"[Stage 3] Data error: {cve}, version: {version}, original config items: {initial_configs}")
                    continue

            test_dict[cve]["compile_times"] = []
            test_dict[cve]["other"]=[]
            test_dict[cve]["exec_order"]=[]
            test_dict[cve]["config_order"]=[]
            with open(f"./{cve}_dependency_graph.txt", "r", encoding="utf-8") as f:
                lines = f.readlines()
            dependency_graph = {}
            edge_set = set()
            
            for config in initial_configs:
                config=config.strip()
                dependency_graph[config] = []
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                config = line.split("→")[0]
                config = config.strip()
                deps = line.split(":")[-1]
                if (not deps.strip().startswith("None")) and not deps.strip().startswith("CONFIG"):
                    continue
                deps = deps.strip().split(",")
                for dep in deps:
                    dep = dep.strip()
                    edge_set.add((config, dep))
                dependency_graph[config] = deps
            num_nodes_ours = len(dependency_graph)
            num_edges_ours = len(edge_set)
            print(f"[Stage 3] Number of nodes in ours: {num_nodes_ours}")
            print(f"[Stage 3] Number of edges in ours: {num_edges_ours}")
            test_dict[cve]["num_nodes_ours"]=num_nodes_ours
            test_dict[cve]["num_edges_ours"]=num_edges_ours
            
            exp_name = row["exp_name"]
            
            print(f"[Stage 3] Starting to process CVE: {cve}, version: {version}")
            if kernel_dir:
                if not os.path.exists(kernel_dir):
                    print(f"[Stage 3] Specified kernel_dir does not exist: {kernel_dir}")
                    continue
                kernel_dir = os.path.abspath(kernel_dir)
                print(f"[Stage 3] Using existing kernel directory: {kernel_dir}")
            else:
                if not download_source_code(cve, version,self.source_code_url):
                    print(f"[Stage 3] Failed to download source code: {cve}, version: {version}")
                    continue
                kernel_dir = f"./{cve}-linux-{version}"
            patch_path=os.path.abspath("./patches")
            try:
                total_tokens=0
                os.chdir(kernel_dir)
                self.patch_kernel(cve, patch_path)
                init_time=time.time()
                print(f"[Stage 3] Executing make defconfig to generate default configuration...")
                defconfig_result = run_shell_command(f"make defconfig", timeout=300)
                if defconfig_result["returncode"] != 0:
                    print(f"[Stage 3] make defconfig failed, skipping subsequent tests")
                    continue


                for config in self.DEF_ENABLED_CONS:
                    run_shell_command(f"./scripts/config --enable  {config}")
                run_shell_command(f"make olddefconfig")
                print(f"[Stage 3] Extracting default configuration items...")
                default_configs = self.extract_configs("./.config")
                print(f"[Stage 3] Number of default configuration items: {len(default_configs)}")
                default_configs_set = set(default_configs)

                print(f"[Stage 3] Enabling initial configuration items: {initial_configs}")
                for config in initial_configs:
                    self.dfs_enable(config,dependency_graph)

                run_shell_command(f"make olddefconfig")
                run_shell_command(f"cp .config ../{cve}-{version}.config.bak")
                
                test_dict[cve]["init_time"]=time.time()-init_time
                print(f"[Stage 3] Compiling initial full configuration kernel as reference...")
                compile_start=time.time()
                compile_result = run_shell_command(f"make -j$(nproc)", timeout=500)
                compile_time=time.time()-compile_start
                test_dict[cve]["initial_compile_times"]=compile_time
                print(f"[Stage 3] Initial kernel compilation time: {compile_time:.2f} seconds")
                
                if compile_result["returncode"] != 0:
                    print("Initial kernel compilation failed, skipping subsequent tests")
                    print(compile_result["stdout"]+compile_result["stderr"])
                    test_dict[cve]["other"].append("Initial kernel compilation failed")
                    run_shell_command("make clean")
                    run_shell_command("make mrproper")
                    continue

                for config in initial_configs:
                    if not config in default_configs_set:
                        verify_result = verify_config(config, ".")
                        if not verify_result["verified"]:
                            print(f"[Stage 3] {config} is not enabled in the kernel configuration")
                            test_dict[cve]["other"].append(f"Compile_check: {config} is not enabled in the kernel configuration")
                            continue

                run_shell_command(f"cp arch/x86/boot/bzImage ../{cve}-{version}-reference.bzImage")

                exp_dir = f"../{cve}"
                os.chdir(exp_dir)
                
                try:
                    run_shell_command(f"cp ../{cve}-{version}-reference.bzImage ./bzImage")
                    
                    print(f"[Stage 3] Executing initial reference POC test...")
                    status,reference_poc_output,qemu_boot_time = self.run_poc_test(cve,".", exp_name, poc_time)
                    if not status:
                        if reference_poc_output=="Failed to boot QEMU":
                            test_dict[cve]["other"].append(f"Initial reference POC test failed, QEMU boot time: {qemu_boot_time:.2f} seconds, Failed to boot QEMU")
                        else:
                            test_dict[cve]["other"].append(f"Initial reference POC test failed, QEMU boot time: {qemu_boot_time:.2f} seconds, {reference_poc_output}")
                        print(f"[Stage 3] Initial reference POC test failed, skipping subsequent tests")
                        continue
                    with open(f"./reference_poc_output.txt", "w+") as f:
                        f.write(reference_poc_output)
                    test_dict[cve]["other"].append(f"Initial reference POC test completed, QEMU boot time: {qemu_boot_time:.2f} seconds")
                        
                    print(f"[Stage 3] Initial reference test completed, results saved")
                finally:
                    os.chdir("..")
                    os.chdir(kernel_dir)
                
                visited = set()
                
                print(f"[Stage 3] Starting to traverse configuration item dependency graph...")
                
                for config in dependency_graph:
                    if config in default_configs_set:
                        visited.add(config)
                
                in_degree = {}
                for node in dependency_graph:
                    in_degree[node] = 0
                
                for node in dependency_graph:
                    for neighbor in dependency_graph[node]:
                        if neighbor in in_degree:
                            if neighbor.startswith("None"):
                                continue
                            in_degree[neighbor] += 1
                
                zero_in_degree_nodes = [node for node in in_degree if in_degree[node] == 0]
                

                TEST_COUNT = 5
                count=0
                for config in zero_in_degree_nodes:
                    count+=1
                    run_shell_command(f"cp ../{cve}-{version}.config.bak .config")
                    run_shell_command(f"make olddefconfig")
                    print(f"[Stage 3] Current test count: {count}")
                    test_dict[cve]["config_order"].append(config)
                    if config in visited or config.startswith("None"):
                        if config in default_configs_set:
                            if config in dependency_graph:
                                for neighbor in dependency_graph[config]:
                                    if neighbor in in_degree:
                                        if neighbor.startswith("None"):
                                            continue
                                        in_degree[neighbor] -= 1
                                        if neighbor not in visited and in_degree[neighbor] == 0:
                                            zero_in_degree_nodes.append(neighbor)
                                del dependency_graph[config]
                        print(f"[Stage 3] [SKIP] Configuration item {config} is visited, skip test")
                        continue
                    test_dict[cve]["exec_order"].append(config)
                    test_dict[cve][f"test_{count}"]={}
                    count_tokens=0
                    if not self.is_arch_valid_config(config):
                        print(f"[Stage 3] [SKIP] Configuration item {config} is invalid, no kernel impact, remove it")
                        if config in dependency_graph:
                            for neighbor in dependency_graph[config]:
                                if neighbor in in_degree:
                                    if neighbor.startswith("None"):
                                        continue
                                    in_degree[neighbor] -= 1
                                    if neighbor not in visited and in_degree[neighbor] == 0:
                                        zero_in_degree_nodes.append(neighbor)
                            del dependency_graph[config]
                        test_dict[cve]["compile_times"].append(-1)
                        test_dict[cve][f"test_{count}"]["total_test_time"]=-1
                        test_dict[cve][f"test_{count}"]["test_times"]=[]
                        test_dict[cve][f"test_{count}"]["qemu_boot_times"]=[]
                        test_dict[cve][f"test_{count}"]["token"]=-1
                        test_dict[cve]["other"].append(f"Invalid config: {config}")
                        continue
                    
                    print(f"[Stage 3] Disabling configuration item: {config}")

                    run_shell_command(f"./scripts/config --disable {config}")
                    run_shell_command(f"make olddefconfig")
                    count_time=time.time()
                    print(f"[Stage 3] Compiling kernel...")
                    compile_start = time.time()
                    compile_result = run_shell_command(f"make -j$(nproc)", timeout=3600)
                    compile_time = time.time() - compile_start
                    test_dict[cve]["compile_times"].append(compile_time)
                    print(f"[Stage 3] Kernel compilation time for disabled config {config}: {compile_time:.2f} seconds")
                    
                    if compile_result["returncode"] != 0:
                        print(f"[Stage 3] Compilation failed after disabling configuration item {config}, skipping test")
                        test_dict[cve]["other"].append(f"Compilation failed after disabling configuration item {config}")
                        run_shell_command(f"make clean")
                        run_shell_command(f"make mrproper")
                        continue
                    
                    run_shell_command(f"cp arch/x86/boot/bzImage ../{cve}-{version}-{config}.bzImage")
                    
                    exp_dir = f"../{self.qemu_dir}"
                    os.chdir(exp_dir)
                    
                    try:
                        run_shell_command(f"cp ../{cve}-{version}-{config}.bzImage ./bzImage")
                        
                        vulnerability_triggered = False
                        test_times = []
                        qemu_boot_times = []
                        for test_iteration in range(TEST_COUNT):
                            print(f"[Stage 3] \n===== Starting test {test_iteration + 1}/{TEST_COUNT} =====")
                            test_start = time.time()
                            status,test_output,qemu_boot_time = self.run_poc_test(cve, ".", exp_name, poc_time)
                            test_time = time.time() - test_start

                            test_times.append(test_time)
                            qemu_boot_times.append(qemu_boot_time)
                            print(f"[Stage 3] Test {test_iteration + 1} execution time: {test_time:.2f} seconds, QEMU boot time: {qemu_boot_time:.2f} seconds")
                            if not status:
                                print(f"[Stage 3] POC test failed, skipping subsequent tests")
                                if test_output=="Failed to boot QEMU":
                                    test_dict[cve]["other"].append(f"POC test failed when test {test_iteration + 1} after disabling configuration item {config}, Failed to boot QEMU")
                                else:
                                    test_dict[cve]["other"].append(f"POC test failed when test {test_iteration + 1} after disabling configuration item {config}, {test_output}")
                                continue
                            is_vulnerable,tokens_used = self.check_vulnerability_with_llm(reference_poc_output, test_output, cve, config)
                            total_tokens+=tokens_used
                            count_tokens+=tokens_used
                            if is_vulnerable:
                                print(f"[Stage 3] Test {test_iteration + 1}: Vulnerability triggered")
                                vulnerability_triggered = True
                            else:
                                print(f"[Stage 3] Test {test_iteration + 1}: Vulnerability not triggered")
                        
                        print(f"[Stage 3] \n===== Configuration item {config} test completed =====")
                        
                        if not vulnerability_triggered:
                            print(f"[Stage 3] Configuration item {config} is important, all tests did not trigger vulnerability, needs to be kept")
                            
                            self.dfs(config, dependency_graph, visited)
                        else:
                            print(f"[Stage 3] Configuration item {config} is not important, at least one test triggered vulnerability, can be deleted")
                            
                            run_shell_command(f"cp .config ../{cve}-{version}.config.bak")
                            
                            if config in dependency_graph:
                                for neighbor in dependency_graph[config]:
                                    if (not neighbor.startswith("None")) and neighbor in in_degree:
                                        in_degree[neighbor] -= 1
                                        if neighbor not in visited and in_degree[neighbor] == 0:
                                            zero_in_degree_nodes.append(neighbor)
                                del dependency_graph[config]
                                
                    finally:
                        os.chdir("..")
                        os.chdir(kernel_dir)
                        test_dict[cve][f"test_{count}"]["total_test_time"]=time.time()-count_time
                        test_dict[cve][f"test_{count}"]["test_times"]=test_times
                        test_dict[cve][f"test_{count}"]["qemu_boot_times"]=qemu_boot_times
                        test_dict[cve][f"test_{count}"]["token"]=count_tokens


                configs_to_remove = []
                for config, deps in dependency_graph.items():
                    if config in default_configs_set:
                        configs_to_remove.append(config)
                for config in configs_to_remove:
                    if config in dependency_graph:
                        for neighbor in dependency_graph[config]:
                            if neighbor.startswith("None"):
                                continue
                            if neighbor in in_degree:
                                in_degree[neighbor] -= 1
                        del dependency_graph[config]
                minimal_configs = set()
                for config in dependency_graph:
                        if config not in minimal_configs:
                            minimal_configs.add(config)
                minimal_configs = list(minimal_configs)

                final_nodes = len(dependency_graph)
                final_edges = sum(len(deps) for deps in dependency_graph.values())
            
                print(f"[Stage 3] \n=== CVE {cve} Analysis Results ===")
                print(f"[Stage 3] Initial configuration item set: {initial_configs}")
                print(f"[Stage 3] Minimal configuration item set: {minimal_configs}")
                print(f"[Stage 3] Deletable configuration items: {list(set(initial_configs) - set(minimal_configs))}")
                print(f"[Stage 3] Initial nodes: {num_nodes_ours}, Initial edges: {num_edges_ours}")
                print(f"[Stage 3] Final nodes: {final_nodes}, Final edges: {final_edges}")
                print(f"[Stage 3] Removed nodes: {num_nodes_ours - final_nodes}, Removed edges: {num_edges_ours - final_edges}")
                test_dict[cve]["dependency_graph"]=dependency_graph
                test_dict[cve]["final_nodes"] = final_nodes
                test_dict[cve]["final_edges"] = final_edges
                test_dict[cve]["total_test_time"]=time.time()-start_time
                test_dict[cve]["total_token"]=total_tokens
                test_dict[cve]["iteration_counts"] = count
                valid_compile_times = [t for t in test_dict[cve]["compile_times"] if t > 0]
                if valid_compile_times:
                    avg_compile_time = sum(valid_compile_times) / len(valid_compile_times)
                    print(f"[Stage 3] Average compilation time: {avg_compile_time:.2f} seconds (based on {len(valid_compile_times)} valid compilations)")
                    test_dict[cve]["avg_compile_time"] = avg_compile_time
                else:
                    print(f"[Stage 3] No valid compilation times available")
                    test_dict[cve]["avg_compile_time"] = -1
                
                all_qemu_boot_times = []
                for test_key in test_dict[cve]:
                    if test_key.startswith("test_") and isinstance(test_dict[cve][test_key], dict):
                        qemu_times = test_dict[cve][test_key].get("qemu_boot_times", [])
                        all_qemu_boot_times.extend([t for t in qemu_times if t > 0])
                
                if all_qemu_boot_times:
                    avg_qemu_boot_time = sum(all_qemu_boot_times) / len(all_qemu_boot_times)
                    print(f"[Stage 3] Average QEMU boot time: {avg_qemu_boot_time:.2f} seconds (based on {len(all_qemu_boot_times)} valid boots)")
                    test_dict[cve]["avg_qemu_boot_time"] = avg_qemu_boot_time
                else:
                    print(f"[Stage 3] No valid QEMU boot times available")
                    test_dict[cve]["avg_qemu_boot_time"] = -1
                with open(f"../Stage3_{cve}-{version}-minimal-configs.json", "w+") as f:
                    json.dump({
                        "cve": cve,
                        "version": version,
                        "exp_name": exp_name,
                        "kernel_dir": kernel_dir,
                        "initial_configs": initial_configs,
                        "minimal_configs": minimal_configs,
                        "removed_configs": list(set(initial_configs) - set(minimal_configs)),
                        "reference_poc_output": reference_poc_output
                    }, f, indent=2)
                    
            finally:
                os.chdir("..")
            print("*"*50)
            if kernel_dir == f"./{cve}-linux-{version}":
                delete_source_code(cve, version)
            run_shell_command(f"rm -rf ./{cve}-{version}.config.bak")
            run_shell_command('for f in CVE*.bzImage; do rm "$f"; done')
            with open(f"./S3-test-results.json", "a+") as f:
                json.dump({
                    "cve": cve,
                    "version": version,
                    "exp_name": exp_name,
                    "kernel_dir": kernel_dir,
                    "test_dict": test_dict[cve],
                    "minimized_configs": minimal_configs,
                }, f, indent=2)


def Stage3_main(cve_list=[], qemu_dir="", source_code_url="", api_key="", base_url="", model=""):
    Stage3 = Config_Minimization(api_key, base_url, model,source_code_url,qemu_dir)
    Stage3.config_mini(cve_list)