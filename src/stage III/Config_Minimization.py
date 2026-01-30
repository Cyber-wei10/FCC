import os
import yaml
import json
import pandas as pd
from typing import Dict, List, Set, Tuple
from shell_exec import run_shell_command
import requests

def dfs(config: str, graph: Dict[str, List[str]], visited: Set[str]):

    if config not in graph or config in visited:
        return
    
    visited.add(config)
    
    for neighbor in graph[config]:
        if neighbor not in visited:
            visited.add(neighbor)
            dfs(neighbor, graph, visited)

def call_llm_api(prompt: str) -> list:
    API_KEY = "your_api_key_placeholder"
    BASE_URL = "your_api_endpoint_placeholder"
    if not API_KEY or API_KEY.strip() == "your_api_key_placeholder":
        raise ValueError("Please replace with a valid API Key")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}"
    }
    data = {
        "model": "model_name",
        "messages": [
            {"role": "system", "content": "You are a professional Linux kernel configuration analyst, strictly follow the output requirements."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.0,
        "max_tokens": 500,
        "stream": False
    }
    
    try:
        response = requests.post(
            url=BASE_URL,
            headers=headers,
            data=json.dumps(data),
            timeout=300,
            verify=False
        )
        print(f"Status code: {response.status_code}")
        response_json = response.json()
        print(f"Response content: {json.dumps(response_json, ensure_ascii=False)}")
        
        content = response_json["choices"][0]["message"]["content"].strip()

        return content

    except requests.exceptions.RequestException as e:
        raise Exception(f"HTTP request failed: {str(e)}")
    except KeyError as e:
        raise Exception(f"Response format parsing failed: missing field {e}")
    except Exception as e:
        raise Exception(f"API call failed: {str(e)}")

def check_vulnerability_with_llm(reference_output: str, test_output: str, cve: str, config: str) -> bool:

    prompt = f"""
    I am testing Linux kernel CVE-{cve} vulnerability, need your help to determine if the vulnerability is triggered.
    
    [Reference Result] This is the output of POC execution under the initial full configuration (should trigger vulnerability):
    {reference_output}
    
    [Current Test Result] This is the output of POC execution after disabling configuration item {config}:
    {test_output}
    
    Please analyze whether the current test result still triggers CVE-{cve} vulnerability.
    Analysis points:
    1. Compare differences with reference result
    2. Check for any vulnerability-related error messages
    3. Consider typical vulnerability triggering characteristics
    
    Please only output "Vulnerability confirmed" or "Vulnerability not triggered".
    """
    
    llm_result = call_llm_api(prompt)
    return True if "Vulnerability confirmed" in llm_result else False

def run_poc_test(exp_dir: str, exp_name: str) -> tuple:

    print(f"Starting QEMU test...")
    run_shell_command(f"./start.sh", timeout=60)
    print(f"Executing POC: {exp_name}")
    exp_result = run_shell_command(f"./{exp_name}", timeout=60)
    if exp_result["returncode"] != 0:
        return False , exp_result["stdout"] + exp_result["stderr"]
    return True, exp_result["stdout"] + exp_result["stderr"]

def extract_configs(config_file_path: str) -> List[str]:

    configs = []
    try:
        with open(config_file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('CONFIG_') and (line.endswith('=y') or line.endswith('=m')):
                    configs.append(line.split('=')[0].strip())
    except Exception as e:
        print(f"Failed to extract configuration items: {str(e)}")
    return configs

def main():

    df = pd.read_excel("cve_configs.xlsx")
    
    for index, row in df.iterrows():
        cve = row["CVE"]
        version = row["VERSION"]
        df2=pd.read_excel("./FCC_KJCdata/added_configs_time.xlsx")
        with open(f"./FCC_KJCdata/{cve}_dependency_graph.txt", "r", encoding="utf-8") as f:
            lines = f.readlines()
        dependency_graph = {}
        edge_set = set()
        cve_init_configs=df2[df2["cve"] == cve]["init_configs"].values[0]
        cve_init_configs = cve_init_configs.split(",")
        
        for config in cve_init_configs:
            config=config.strip()
            dependency_graph[config] = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            config = line.split("→")[0]
            config = config.strip()
            deps = line.split(":")[-1]
            deps = deps.strip().split(",")
            for dep in deps:
                dep = dep.strip()
                edge_set.add((config, dep))
            dependency_graph[config] = deps
        num_nodes_ours = len(dependency_graph)
        num_edges_ours = len(edge_set)
        print(f"Number of nodes in ours: {num_nodes_ours}")
        print(f"Number of edges in ours: {num_edges_ours}")
        if isinstance(row["CONFIGS"], str):
            initial_configs = [config.strip() for config in row["CONFIGS"].split(",")]
        else:
            initial_configs = row["CONFIGS"]
            if isinstance(initial_configs, list):
                initial_configs = [str(config).strip() for config in initial_configs]
            else:
                print(f"Data error: {cve}, version: {version}, original config items: {initial_configs}")
                continue
        
        exp_name = row["exp_name"]
        
        print(f"Starting to process CVE: {cve}, version: {version}")
        kernel_dir = f"./{cve}-linux-{version}"
        
        try:
            os.chdir(kernel_dir)
            print(f"Executing make defconfig to generate default configuration...")
            defconfig_result = run_shell_command(f"make defconfig", timeout=3600)
            if defconfig_result["returncode"] != 0:
                print(f"make defconfig failed, skipping subsequent tests")
                continue
            DEF_ENABLED_CONS=["CONFIG_DEBUG_INFO_BTF","CONFIG_FRAME_POINTER","CONFIG_KALLSYMS","CONFIG_KALLSYMS_ALL","CONFIG_DEBUG_INFO","CONFIG_BINFMT_MISC","CONFIG_USER_NS","CONFIG_NET_NS","CONFIG_E1000","CONFIG_E1000E","CONFIG_SYSVIPC","CONFIG_DEBUG_INFO_DWARF4","CONFIG_CONFIGFS_FS","CONFIG_SECURITYFS","CONFIG_KCOV","CONFIG_KASAN","CONFIG_KASAN_INLINE","CONFIG_USERFAULTFD","CONFIG_KEY_DH_OPERATIONS"]
            for config in DEF_ENABLED_CONS:
                run_shell_command(f"./scripts/config --enable  {config}")
            run_shell_command(f"make olddefconfig")
            print(f"Extracting default configuration items...")
            default_configs = extract_configs("./.config")
            print(f"Number of default configuration items: {len(default_configs)}")
            
            print(f"Enabling initial configuration items: {initial_configs}")
            for config in initial_configs:
                run_shell_command(f"./scripts/config --enable {config}")
            run_shell_command(f"make olddefconfig")
            run_shell_command(f"cp .config ../{cve}-{version}.config.bak")
            
            print(f"Compiling initial full configuration kernel as reference...")
            compile_result = run_shell_command(f"make -j$(nproc)", timeout=3600)
            if compile_result["returncode"] != 0:
                print(f"Initial kernel compilation failed, skipping subsequent tests")
                continue
            
            run_shell_command(f"cp arch/x86/boot/bzImage ../{cve}-{version}-reference.bzImage")
            
            exp_dir = f"../{cve}"
            os.chdir(exp_dir)
            
            try:
                run_shell_command(f"cp ../{cve}-{version}-reference.bzImage ./bzImage")
                
                print(f"Executing initial reference POC test...")
                status,reference_poc_output = run_poc_test(exp_dir, exp_name)
                if not status:
                    print(f"Initial reference POC test failed, skipping subsequent tests")
                    continue
                with open(f"./reference_poc_output.txt", "w") as f:
                    f.write(reference_poc_output)
                    
                print(f"Initial reference test completed, results saved")
            finally:
                os.chdir(kernel_dir)
            
            visited = set()
            
            print(f"Starting to traverse configuration item dependency graph...")
            
            in_degree = {}
            for node in dependency_graph:
                in_degree[node] = 0
            
            for node in dependency_graph:
                for neighbor in dependency_graph[node]:
                    if neighbor in in_degree:
                        in_degree[neighbor] += 1
            
            zero_in_degree_nodes = [node for node in in_degree if in_degree[node] == 0]
            
            TEST_COUNT = 5
            count=0
            for config in zero_in_degree_nodes:
                if config in visited:
                    continue
                count+=1
                if config in default_configs:
                    if config in dependency_graph:
                        for neighbor in dependency_graph[config]:
                            if neighbor in in_degree:
                                in_degree[neighbor] -= 1
                                if neighbor not in visited and in_degree[neighbor] == 0:
                                    zero_in_degree_nodes.append(neighbor)
                        del dependency_graph[config]
                run_shell_command(f"cp ../{cve}-{version}.config.bak .config")
                
                print(f"Disabling configuration item: {config}")
                run_shell_command(f"./scripts/config --disable {config}")
                
                run_shell_command(f"make olddefconfig")
                
                print(f"Compiling kernel...")
                compile_result = run_shell_command(f"make -j$(nproc)", timeout=3600)
                
                if compile_result["returncode"] != 0:
                    print(f"Compilation failed after disabling configuration item {config}, skipping test")
                    continue
                
                run_shell_command(f"cp arch/x86/boot/bzImage ../{cve}-{version}-{config}.bzImage")
                
                exp_dir = f"../{cve}"
                os.chdir(exp_dir)
                
                try:
                    run_shell_command(f"cp ../{cve}-{version}-{config}.bzImage ./bzImage")
                    
                    vulnerability_triggered = False
                    
                    for test_iteration in range(TEST_COUNT):
                        print(f"\n===== Starting test {test_iteration + 1}/{TEST_COUNT} =====")
                        
                        status,test_output = run_poc_test(exp_dir, exp_name)
                        if not status:
                            print(f"POC test failed, skipping subsequent")
                            continue
                        
                        is_vulnerable = check_vulnerability_with_llm(reference_poc_output, test_output, cve, config)
                        
                        if is_vulnerable:
                            print(f"Test {test_iteration + 1}: Vulnerability triggered")
                            vulnerability_triggered = True
                        else:
                            print(f"Test {test_iteration + 1}: Vulnerability not triggered")
                    
                    print(f"\n===== Configuration item {config} test completed =====")
                    
                    if vulnerability_triggered:
                        print(f"Configuration item {config} is important, at least one test triggered vulnerability, needs to be kept")
                        
                        dfs(config, dependency_graph, visited)
                    else:
                        print(f"Configuration item {config} is not important, all tests did not trigger vulnerability, can be deleted")
                        
                        run_shell_command(f"cp .config ../{cve}-{version}.config.bak")
                        
                        if config in dependency_graph:
                            for neighbor in dependency_graph[config]:
                                if neighbor in in_degree:
                                    in_degree[neighbor] -= 1
                                    if neighbor not in visited and in_degree[neighbor] == 0:
                                        zero_in_degree_nodes.append(neighbor)
                            del dependency_graph[config]
                            
                finally:
                    os.chdir(kernel_dir)
            minimal_configs = list(visited)
            print(f"\n=== CVE {cve} Analysis Results ===")
            print(f"Initial configuration item set: {initial_configs}")
            print(f"Minimal configuration item set: {minimal_configs}")
            print(f"Deletable configuration items: {list(set(initial_configs) - set(minimal_configs))}")
            print(f"Current test count: {count}")
            with open(f"../{cve}-{version}-minimal-configs.json", "w+") as f:
                json.dump({
                    "cve": cve,
                    "version": version,
                    "initial_configs": initial_configs,
                    "minimal_configs": minimal_configs,
                    "removed_configs": list(set(initial_configs) - set(minimal_configs)),
                    "reference_poc_output": reference_poc_output
                }, f, indent=2)
                
        finally:
            os.chdir("..")

if __name__ == "__main__":
    main()
