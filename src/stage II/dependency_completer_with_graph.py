import os
import re
from typing import List, Set, Dict, Any
from dependency_finder import find_dependencies
from shell_exec import run_shell_command
import csv
import pandas as pd
import sys
import datetime

recursion_records: List[Dict[str, Any]] = []

dependency_graph: Dict[str, Set[str]] = {}

def get_enabled_configs(config_path: str) -> Set[str]:

    enabled = set()
    if not os.path.exists(config_path):
        print(f"[Completer] Config file {config_path} does not exist, returning empty set")
        return enabled
    
    try:
        with open(config_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    cfg, val = line.split("=", 1)
                    cfg = cfg.strip()
                    val = val.strip()
                    if val != "n":
                        enabled.add(cfg)
        print(f"[Completer] Number of enabled configuration items: {len(enabled)}")
        return enabled
    except Exception as e:
        print(f"[Completer] Error reading config file: {str(e)}")
        return enabled

def ordered_deduplication(config_list: List[str]) -> List[str]:

    seen = set()
    result = []
    for cfg in config_list:
        if cfg not in seen:
            seen.add(cfg)
            result.append(cfg)
    return result

def update_config_file(config_path: str, configs_to_enable: List[str]):

    root_dir = os.path.dirname(config_path)
    if not os.path.exists(config_path):
        print(f"[Completer] Config file does not exist, executing make defconfig to generate default config")
        result = run_shell_command(
            command="make defconfig",
            cwd=root_dir,
            shell=True,
            timeout=300
        )
        if result["returncode"] != 0:
            print(f"[Completer] make defconfig execution failed: {result['stderr']}")
            return
    
    try:
        with open(config_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.readlines()
    except Exception as e:
        print(f"[Completer] Failed to read config file: {str(e)}")
        return
    
    cfg_dict = {}
    new_content = []
    for line in content:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            new_content.append(line)
            continue
        if "=" in stripped:
            cfg, val = stripped.split("=", 1)
            cfg = cfg.strip()
            val = val.strip()
            cfg_dict[cfg] = val
    
    enabled_lines = set()
    for cfg in configs_to_enable:
        cfg_dict[cfg] = "y"
        enabled_lines.add(cfg)
    
    final_content = []
    cfg_written = set()
    for line in content:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            final_content.append(line)
            continue
        if "=" in stripped:
            cfg, _ = stripped.split("=", 1)
            cfg = cfg.strip()
            if cfg in cfg_dict:
                final_content.append(f"{cfg}={cfg_dict[cfg]}\n")
                cfg_written.add(cfg)
            else:
                final_content.append(line)
    
    for cfg in configs_to_enable:
        if cfg not in cfg_written:
            final_content.append(f"{cfg}=y\n")
            cfg_written.add(cfg)
    
    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            f.writelines(final_content)
        print(f"[Completer] Config file updated sequentially, enabled {len(enabled_lines)} configuration items")
        print(f"[Completer] Enable order: {configs_to_enable}")
    except Exception as e:
        print(f"[Completer] Failed to write config file: {str(e)}")

def extract_dependency_relations(model_response: str) -> Dict[str, List[str]]:

    dependency_relations = {}
    lines = model_response.split('\n')
    
    dep_pattern = re.compile(r'^(CONFIG_[A-Z0-9_]+)\s*→\s*Dependencies:\s*(.*)$')
    
    for line in lines:
        line = line.strip()
        match = dep_pattern.match(line)
        if match:
            config = match.group(1)
            deps_str = match.group(2).strip()
            if deps_str:
                deps = [dep.strip() for dep in deps_str.split(',') if dep.strip().startswith('CONFIG_')]
                dependency_relations[config] = deps
            else:
                dependency_relations[config] = []
    
    return dependency_relations

def build_dependency_graph(dependency_relations: Dict[str, List[str]], default_enabled: Set[str]):

    global dependency_graph
    
    for config, deps in dependency_relations.items():
        if config not in default_enabled:
            if config not in dependency_graph:
                dependency_graph[config] = set()
            
            for dep in deps:
                dependency_graph[config].add(dep)
                if dep not in dependency_graph:
                    dependency_graph[dep] = set()

def complete_dependencies_recursive(root_dir: str, 
                                   target_configs: List[str],
                                   default_enabled: Set[str],
                                   max_depth: int = 10,
                                   current_depth: int = 1) -> List[str]:

    start_time = datetime.datetime.now()
    
    if current_depth > max_depth:
        print(f"[Completer] Reached maximum recursion depth ({max_depth}), stopping completion")
        return target_configs
    
    config_path = os.path.join(root_dir, ".config")
    
    print(f"\n[Completer] === Recursion depth {current_depth}/{max_depth} - Starting to update config file ===")
    update_config_file(config_path, target_configs)
    print(f"[Completer] Executing make olddefconfig to verify config...")
    
    olddefconfig_result = run_shell_command(
        command="make olddefconfig",
        cwd=root_dir,
        shell=True,
        timeout=300
    )
    if olddefconfig_result["returncode"] != 0:
        print(f"[Completer] make olddefconfig execution failed: {olddefconfig_result['stderr']}")
    
    enabled_configs = get_enabled_configs(config_path)
    missing_configs = [cfg for cfg in target_configs if cfg not in enabled_configs]
    success_configs = [cfg for cfg in target_configs if cfg in enabled_configs]
    
    current_record = {
        "depth": current_depth,
        "target_configs": target_configs.copy(),
        "success_configs": success_configs.copy(),
        "missing_configs": missing_configs.copy(),
        "new_dependencies_list": [],
        "new_dependencies_details": [],
        "dependency_relations": {},
        "status": "ongoing",
        "prompt": "",
        "start_time": start_time.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    }
    
    if not missing_configs:
        print(f"[Completer] Recursion depth {current_depth}/{max_depth} - All configuration items enabled")
        current_record["status"] = "completed"
        end_time = datetime.datetime.now()
        current_record["end_time"] = end_time.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        current_record["duration"] = (end_time - start_time).total_seconds()
        recursion_records.append(current_record)
        return target_configs
    
    print(f"[Completer] Recursion depth {current_depth}/{max_depth} - Target configs: {target_configs}")
    print(f"[Completer] Recursion depth {current_depth}/{max_depth} - Success configs: {success_configs}")
    print(f"[Completer] Recursion depth {current_depth}/{max_depth} - Missing configs: {missing_configs}")
    
    new_dependencies = []
    all_prompts = []
    all_dependency_relations = {}
    
    round_visited = set()
    
    for missing_cfg in missing_configs:
        if missing_cfg in round_visited:
            print(f"[Completer] {missing_cfg} already processed, skipping (prevent circular dependency)")
            continue
        round_visited.add(missing_cfg)
        
        deps, prompt, dependencies_relation = find_dependencies(
            kernel_root=root_dir,
            target_config_full=missing_cfg
        )
        
        if prompt:
            all_prompts.append(prompt)
        
        if dependencies_relation:
            relations = extract_dependency_relations(dependencies_relation)
            print(relations)
            if relations:
                all_dependency_relations.update(relations)
                print(all_dependency_relations)
                build_dependency_graph(relations, default_enabled)
        
        if deps:
            filtered_deps = [dep for dep in deps if dep not in default_enabled]
            
            if filtered_deps or missing_cfg not in default_enabled:
                if filtered_deps:
                    new_dependencies.extend(filtered_deps)
                    
                if missing_cfg not in default_enabled:
                    new_dependencies.append(missing_cfg)
                    
                print(f"[Completer] Completing dependencies for {missing_cfg}: {filtered_deps} (Order: {filtered_deps} -> {missing_cfg})")
                
                current_record["new_dependencies_details"].append({
                    "missing_cfg": missing_cfg,
                    "dependencies": filtered_deps
                })
                
                current_record["new_dependencies_list"].extend(filtered_deps)
                if missing_cfg not in default_enabled:
                    current_record["new_dependencies_list"].append(missing_cfg)
        else:
            if missing_cfg not in default_enabled:
                new_dependencies.append(missing_cfg)
                current_record["new_dependencies_list"].append(missing_cfg)
    current_record["new_dependencies_list"] = list(set(current_record["new_dependencies_list"]))
    
    all_configs = success_configs + new_dependencies
    all_configs = ordered_deduplication(all_configs)
    
    current_record["all_configs"] = all_configs.copy()
    current_record["status"] = "continue"
    current_record["prompt"] = ".".join(all_prompts) if all_prompts else ""
    current_record["dependency_relations"] = all_dependency_relations
    
    end_time = datetime.datetime.now()
    current_record["end_time"] = end_time.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    current_record["duration"] = (end_time - start_time).total_seconds()
    
    if len(recursion_records)>=1 and current_record["missing_configs"]==recursion_records[-1]["missing_configs"] and current_record["target_configs"]==recursion_records[-1]["target_configs"]:
        current_record["status"]="failed"
        recursion_records.append(current_record)
        return target_configs
    recursion_records.append(current_record)

    return complete_dependencies_recursive(
        root_dir=root_dir,
        target_configs=all_configs,
        default_enabled=default_enabled,
        max_depth=max_depth,
        current_depth=current_depth + 1
    )
def completer(CVE, ROOT_DIR, INITIAL_CONFIGS, MAX_RECURSION_DEPTH=10):

    global recursion_records
    global dependency_graph
    recursion_records = []
    dependency_graph = {}
    
    config_path = os.path.join(ROOT_DIR, ".config")
    
    original_config = None
    if os.path.exists(config_path):
        with open(config_path, 'r', encoding='utf-8', errors='ignore') as f:
            original_config = f.read()
    
    print(f"[Completer] Generating default config to get default enabled items...")
    result = run_shell_command(
        command="make defconfig",
        cwd=ROOT_DIR,
        shell=True,
        timeout=300
    )
    if result["returncode"] != 0:
        print(f"[Completer] make defconfig execution failed: {result['stderr']}")
        return [], [], {}, set()
    
    default_enabled = get_enabled_configs(config_path)
    print(f"[Completer] Number of default enabled configuration items: {len(default_enabled)}")
    
    if original_config is not None:
        with open(config_path, 'w', encoding='utf-8') as f:
            f.write(original_config)
        print(f"[Completer] Original config restored")
    
    filtered_initial_configs = [cfg for cfg in INITIAL_CONFIGS if cfg not in default_enabled]
    print(f"[Completer] Initial configs: {INITIAL_CONFIGS}")
    print(f"[Completer] Filtered initial configs (excluding default enabled): {filtered_initial_configs}")
    
    print("[Completer] Starting recursive configuration completion...")
    final_configs = complete_dependencies_recursive(
        root_dir=ROOT_DIR,
        target_configs=filtered_initial_configs,
        default_enabled=default_enabled,
        max_depth=MAX_RECURSION_DEPTH,
        current_depth=1
    )
    
    print("\n" + "="*100)
    print("[Completer] === Recursive Completion Detailed Records ===")
    print("="*100)
    for idx, record in enumerate(recursion_records, 1):
        print(f"\n[Round {idx} (Depth {record['depth']})]")
        print(f"  Status: {record['status']}")
        print(f"  Start Time: {record['start_time']}")
        print(f"  End Time: {record['end_time']}")
        print(f"  Duration: {record['duration']:.2f}s")
        print(f"  Target configs this round: {record['target_configs']}")
        print(f"  Success configs this round: {record['success_configs']}")
        print(f"  Missing configs this round: {record['missing_configs']}")
        if record["new_dependencies_details"]:
            print(f"  Dependencies completed this round:")
            for dep_info in record["new_dependencies_details"]:
                print(f"    {dep_info['missing_cfg']} -> Depends: {dep_info['dependencies']}")
        if "all_configs" in record:
            print(f"  Final target configs this round (ordered): {record['all_configs']}")
        if record["dependency_relations"]:
            print(f"  Dependency relations extracted this round:")
            for config, deps in record["dependency_relations"].items():
                if deps:
                    print(f"    {config} -> Depends: {', '.join(deps)}")
                else:
                    print(f"    {config} -> Depends: None")
    
    print("\n" + "="*100)
    print("[Completer] === Final Dependency Graph ===")
    print("="*100)
    for config, deps in dependency_graph.items():
        if deps:
            print(f"{config} -> Depends: {', '.join(deps)}")
        else:
            print(f"{config} -> Depends: None")
    
    xlsx_path = "./CVE_configs.xlsx"
    print(f"\n[Completer] Writing recursion records to XLSX file: {xlsx_path}")
    
    header = ["CVE ID", "Round", "Depth", "Start Time", "End Time", "Duration(s)", "Target Configs", "Missing Configs", "LLM Prompt", "Dependency Configs", "Status", "Dependency Relations"]
    
    rows = []
    for idx, record in enumerate(recursion_records, 1):
        dep_relations_str = ""
        if record["dependency_relations"]:
            rel_lines = []
            for config, deps in record["dependency_relations"].items():
                if deps:
                    rel_lines.append(f"{config} -> Depends: {', '.join(deps)}")
                else:
                    rel_lines.append(f"{config} -> Depends: None")
            dep_relations_str = "\n".join(rel_lines)
        
        row = [
            CVE,
            str(idx),
            str(record['depth']),
            record['start_time'],
            record['end_time'],
            f"{record['duration']:.2f}",
            "\n".join(record['target_configs']),
            "\n".join(record['missing_configs']),
            record['prompt'],
            "\n".join(record['new_dependencies_list']),
            record['status'],
            dep_relations_str
        ]
        rows.append(row)
    
    df_new = pd.DataFrame(rows, columns=header)
    
    try:
        df_existing = pd.read_excel(xlsx_path)
        df_combined = pd.concat([df_existing, df_new], ignore_index=True)
    except FileNotFoundError:
        df_combined = df_new
    
    df_combined.to_excel(xlsx_path, index=False)
    print(f"[Completer] XLSX file writing completed")
    
    graph_path = f"./{CVE}_dependency_graph.txt"
    print(f"\n[Completer] Writing dependency graph to file: {graph_path}")
    
    with open(graph_path, "a+", encoding="utf-8") as f:
        f.write("# Configuration Item Dependency Graph\n")
        f.write("# Format: Config Item -> Depends: Dependency1, Dependency2, ...\n\n")
        
        for config, deps in dependency_graph.items():
            if deps:
                f.write(f"{config} -> Depends: {', '.join(deps)}\n")
            else:
                f.write(f"{config} -> Depends: None\n")
    
    print(f"[Completer] Dependency graph file writing completed")
    
    print("\n" + "="*100)
    print("[Completer] === Final Minimal Config Increment (Ordered) ===")
    print("="*100)
    for idx, cfg in enumerate(final_configs, 1):
        print(f"  {idx}. {cfg}")
    
    added_configs = set(final_configs)
    print(f"\n[Completer] Total number of added configuration items: {len(added_configs)}")
    print(f"[Completer] Total set of added configuration items: {added_configs}")
    
    return final_configs, recursion_records, dependency_graph, added_configs


if __name__ == "__main__":
    CVE = "CVE-2021-26708"
    ROOT_DIR = "./linux-5.10.12"
    INITIAL_CONFIGS = ["CONFIG_VIRTIO_VSOCKETS", "CONFIG_USERFAULTFD"]
    MAX_RECURSION_DEPTH = 10
    
    CVE=sys.argv[1]
    VERSION=sys.argv[2]
    ROOT_DIR = f"./{CVE}-linux-{VERSION}"
    INITIAL_CONFIGS=sys.argv[3].split(",")
    
    final_configs, records, graph, added_configs = completer(CVE, ROOT_DIR, INITIAL_CONFIGS, MAX_RECURSION_DEPTH)
