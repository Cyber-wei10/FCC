import os
import re
from typing import List, Set, Dict, Any
from Stage2.dependency_finder_with_source import Dependency_Finder
from utils.shell_exec import run_shell_command
import pandas as pd
import sys
import datetime
class Dependency_Completer:
    def __init__(self, api_key: str, base_url: str,model: str):
        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self.recursion_records = []
        self.dependency_graph = {}

    def get_enabled_configs(self, config_path: str) -> Set[str]:
        """
        Read .config file and get enabled config items (value=y)
        Parameters:
            config_path: Path to .config file
        Returns:
            Set of enabled config items
        """
        enabled = set()
        if not os.path.exists(config_path):
            print(f"[Stage2 Completer] Config file {config_path} does not exist, return empty set")
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
            print(f"[Stage2 Completer] Number of enabled configs: {len(enabled)}")
            return enabled
        except Exception as e:
            print(f"[Stage2 Completer] Error reading config file: {str(e)}")
            return enabled

    def ordered_deduplication(self, config_list: List[str]) -> List[str]:
        """
        Ordered deduplication: preserve list order while removing duplicates (ensure dependencies come first)
        """
        seen = set()
        result = []
        for cfg in config_list:
            if cfg not in seen:
                seen.add(cfg)
                result.append(cfg)
        return result

    def update_config_file(self, config_path: str, configs_to_enable: List[str]):
        """
        Update .config file in order, enable specified configs (dependencies first)
        Parameters:
            config_path: Path to .config file
            configs_to_enable: List of configs to enable (ordered, dependencies first)
        Returns:
            None
        """
        root_dir = os.path.dirname(config_path)
        if not os.path.exists(config_path):
            print(f"[Stage2 Completer] Config file {config_path} does not exist, execute make defconfig to generate default config file")
            result = run_shell_command(
                command="make defconfig",
                cwd=root_dir,
                shell=True,
                timeout=300
            )
            if result["returncode"] != 0:
                print(f"[Stage2 Completer] Error executing make defconfig command: {result['stderr']}")
                return
        
        try:
            with open(config_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.readlines()
        except Exception as e:
            print(f"[Stage2 Completer] Error reading config file: {str(e)}")
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
            print(f"[Stage2 Completer] Updated config file sequentially, enabled {len(enabled_lines)} config items")
            print(f"[Stage2 Completer] Enable order: {configs_to_enable}")
        except Exception as e:
            print(f"[Stage2 Completer] Failed to write config file: {str(e)}")

    def extract_dependency_relations(self, model_response: str) -> Dict[str, List[str]]:
        """
        Extract dependency relationships from large model responses
        Format example:
        ConfigItem1 → Depends on: ConfigItem2, ConfigItem3
        ConfigItem2 → Depends on: ConfigItem4
        ConfigItem3 → Depends on: ConfigItem4
        """
        dependency_relations = {}
        lines = model_response.split('\n')
        
        dep_pattern = re.compile(r'^(CONFIG_[A-Z0-9_]+)\s*→\s*Dependency:\s*(.*)$')
        
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

    def build_dependency_graph(self, dependency_relations: Dict[str, List[str]], default_enabled: Set[str]):
        """
        Build a directed graph from extracted dependency relationships
        """
        
        for config, deps in dependency_relations.items():
            if config not in default_enabled:
                if config not in self.dependency_graph:
                    self.dependency_graph[config] = set()
                
                for dep in deps:
                    if dep not in default_enabled:
                        self.dependency_graph[config].add(dep)
                        if dep not in self.dependency_graph:
                            self.dependency_graph[dep] = set()

    def complete_dependencies_recursive(self, root_dir: str, 
                                    target_configs: List[str],
                                    default_enabled: Set[str],
                                    max_depth: int = 10,
                                    current_depth: int = 1) -> List[str]:
        """
        Recursively complete config item dependencies (remove vulnerability description parameter, focus only on config items)
        New additions:
        1. Record items to enable and failed items for each recursion round
        2. Ensure config item order (dependencies first, target items last)
        3. Record config item dependencies and build directed graph
        4. Record start time, end time, and duration for each round
        Parameters:
            root_dir: Kernel root directory
            target_configs: List of config items to enable (ordered)
            default_enabled: Set of default enabled config items
            max_depth: Maximum recursion depth
            current_depth: Current recursion depth
        Returns:
            Final minimal list of config items to enable (ordered)
        """
        start_time = datetime.datetime.now()
        
        if current_depth > max_depth:
            print(f"[Stage2 Completer] Reached max recursion depth ({max_depth}), stop completion")

            return target_configs
        
        config_path = os.path.join(root_dir, ".config")
        
        print(f"\n[Stage2 Completer] --- Recursion depth {current_depth}/{max_depth} - Start config file update ---")
        self.update_config_file(config_path, target_configs)
        print(f"[Stage2 Completer] Execute make olddefconfig to verify config...")
        
        olddefconfig_result = run_shell_command(
            command="make olddefconfig",
            cwd=root_dir,
            shell=True,
            timeout=300
        )
        if olddefconfig_result["returncode"] != 0:
            print(f"[Stage2 Completer] make olddefconfig Execute failed: {olddefconfig_result['stderr']}")
        
        enabled_configs = self.get_enabled_configs(config_path)
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
            "tokens": 0, 
            "prompt": "", 
            "start_time": start_time.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        }
        
        if not missing_configs:
            print(f"[Stage2 Completer] Recursion depth {current_depth}/{max_depth} - All configs enabled successfully")
            current_record["status"] = "completed"
            end_time = datetime.datetime.now()
            current_record["end_time"] = end_time.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            current_record["duration"] = (end_time - start_time).total_seconds()
            self.recursion_records.append(current_record)
            return target_configs
        
        print(f"[Stage2 Completer] Recursion depth {current_depth}/{max_depth} - Pending configs to enable: {target_configs}")
        print(f"[Stage2 Completer] Recursion depth {current_depth}/{max_depth} - Enabled configs successfully: {success_configs}")
        print(f"[Stage2 Completer] Recursion depth {current_depth}/{max_depth} - Failed configs to enable: {missing_configs}")
        
        new_dependencies = []
        all_prompts = []
        all_dependency_relations = {}
        
        round_visited = set()
        
        for missing_cfg in missing_configs:
            if missing_cfg in round_visited:
                print(f"[Stage2 Completer] {missing_cfg} already processed, skipping (preventing circular dependencies)")
                continue
            round_visited.add(missing_cfg)
            
            Stage2_Finder=Dependency_Finder(api_key=self.api_key,base_url=self.base_url,model=self.model)
            deps, prompt, dependencies_relation,tokens = Stage2_Finder.find_dependencies(
                kernel_root=root_dir,
                target_config_full=missing_cfg,
            )
            current_record["tokens"] += tokens
            
            if prompt:
                all_prompts.append(prompt)
            
            if dependencies_relation:
                relations = self.extract_dependency_relations(dependencies_relation)
                print(relations)
                if relations:
                    all_dependency_relations.update(relations)
                    print(all_dependency_relations)
                    self.build_dependency_graph(relations, default_enabled)
            
            if deps:
                filtered_deps = [dep for dep in deps if dep not in default_enabled]
                
                if filtered_deps or missing_cfg not in default_enabled:

                    if filtered_deps:
                        new_dependencies.extend(filtered_deps)
                        
                    if missing_cfg not in default_enabled:
                        new_dependencies.append(missing_cfg)
                        
                    print(f"[Stage2 Completer] Completing dependencies for {missing_cfg} with {filtered_deps} (Order: {filtered_deps} → {missing_cfg})")
                    
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
        all_configs = self.ordered_deduplication(all_configs)
        
        current_record["all_configs"] = all_configs.copy()
        current_record["status"] = "continue"
        current_record["prompt"] = ".".join(all_prompts) if all_prompts else ""
        current_record["dependency_relations"] = all_dependency_relations
        
        end_time = datetime.datetime.now()
        current_record["end_time"] = end_time.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        current_record["duration"] = (end_time - start_time).total_seconds()
        if len(self.recursion_records)>=1 and current_record["missing_configs"]==self.recursion_records[-1]["missing_configs"] and current_record["target_configs"]==self.recursion_records[-1]["target_configs"] and current_record["new_dependencies_list"]==self.recursion_records[-1]["new_dependencies_list"]:
            current_record["status"]="failed"
            self.recursion_records.append(current_record)
            return target_configs
        if current_depth == max_depth:
            current_record["status"]="failed"
            self.recursion_records.append(current_record)
            return target_configs
        
        ARCH_EXCLUSIVE_PREFIXES = {
            'CONFIG_ARM', 'CONFIG_RISCV', 'CONFIG_MIPS', 'CONFIG_PPC', 
            'CONFIG_S390', 'CONFIG_SPARC', 'CONFIG_PARISC', 'CONFIG_XTENSA',
            'CONFIG_HEXAGON', 'CONFIG_LOONGARCH'
        }
        arch_configs = [x for x in all_configs if x in ARCH_EXCLUSIVE_PREFIXES]
        if len(arch_configs)>2:
            current_record["status"]="failed"
            self.recursion_records.append(current_record)
            return target_configs
        
        self.recursion_records.append(current_record)
        return self.complete_dependencies_recursive(
            root_dir=root_dir,
            target_configs=all_configs,
            default_enabled=default_enabled,
            max_depth=max_depth,
            current_depth=current_depth + 1
        )

    def completer(self, CVE, ROOT_DIR, INITIAL_CONFIGS, MAX_RECURSION_DEPTH=10):
        total_tokens = 0
        
        config_path = os.path.join(ROOT_DIR, ".config")
        
        original_config = None
        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8', errors='ignore') as f:
                original_config = f.read()
        
        print(f"[Stage2 Completer] Generating default configuration to get default enabled items...")
        result = run_shell_command(
            command="make defconfig",
            cwd=ROOT_DIR,
            shell=True,
            timeout=300
        )
        if result["returncode"] != 0:
            print(f"[Stage2 Completer] make defconfig failed: {result['stderr']}")
            return [], [], {}, set()
        
        default_enabled = self.get_enabled_configs(config_path)
        print(f"[Stage2 Completer] Default enabled items count: {len(default_enabled)}")
        
        if original_config is not None:
            with open(config_path, 'w', encoding='utf-8') as f:
                f.write(original_config)
            print(f"[Stage2 Completer] Restored original configuration")
        
        filtered_initial_configs = [cfg for cfg in INITIAL_CONFIGS if cfg not in default_enabled]
        print(f"[Stage2 Completer] Initial config items: {INITIAL_CONFIGS}")
        print(f"[Stage2 Completer] Filtered initial config items (excluding default enabled): {filtered_initial_configs}")
        
        print("[Stage2 Completer] Starting recursive configuration completion...")
        final_configs = self.complete_dependencies_recursive(
            root_dir=ROOT_DIR,
            target_configs=filtered_initial_configs,
            default_enabled=default_enabled,
            max_depth=MAX_RECURSION_DEPTH,
            current_depth=1
        )
        
        print("\n" + "="*100)
        print("[Stage2 Completer] === Recursive configuration completion records ===")
        print("="*100)
        for idx, record in enumerate(self.recursion_records, 1):
            print(f"\n[round {idx} recursive completion (Depth{record['depth']})]")
            print(f"  Status: {record['status']}")
            print(f"  Start time: {record['start_time']}")
            print(f"  End time: {record['end_time']}")
            print(f"  Duration: {record['duration']:.2f} seconds")
            print(f"  Target configs: {record['target_configs']}")
            print(f"  Success configs: {record['success_configs']}")
            print(f"  Failed configs: {record['missing_configs']}")
            print(f"  Tokens: {record['tokens']}")
            total_tokens += record["tokens"]
            if record["new_dependencies_details"]:
                print(f"  New dependencies completed:")
                for dep_info in record["new_dependencies_details"]:
                    print(f"    {dep_info['missing_cfg']} → Dependency: {dep_info['dependencies']}")
            if "all_configs" in record:
                print(f"  All configs (ordered): {record['all_configs']}")
            if record["dependency_relations"]:
                print(f"  Dependency relations:")
                for config, deps in record["dependency_relations"].items():
                    if deps:
                        print(f"    {config} → Dependency: {', '.join(deps)}")
                    else:
                        print(f"    {config} → Dependency: None")
        
        print("\n" + "="*100)
        print("[Stage2 Completer] === Final dependency graph ===")
        print("="*100)
        for config, deps in self.dependency_graph.items():
            if deps:
                print(f"{config} → Dependency: {', '.join(deps)}")
            else:
                print(f"{config} → Dependency: None")
        
        xlsx_path = "./Stage2_round_CVE_configs.xlsx"
        print(f"\n[Stage2 Completer] Recursive configuration completion records saved to XLSX file: {xlsx_path}")
        
        header = ["CVE", "Round", "Depth", "Start Time", "End Time", "Duration (seconds)", "target_configs","missing_configs","Prompt","tokens","Dependencies Completed", "Status", "Dependencies"]
        
        rows = []
        for idx, record in enumerate(self.recursion_records, 1):
            dep_relations_str = ""
            if record["dependency_relations"]:
                rel_lines = []
                for config, deps in record["dependency_relations"].items():
                    if deps:
                        rel_lines.append(f"{config} → Dependency: {', '.join(deps)}")
                    else:
                        rel_lines.append(f"{config} → Dependency: None")
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
                record['tokens'],
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
        print(f"[Stage2 Completer] XLSX file written successfully")
        
        graph_path = f"./{CVE}_dependency_graph.txt"
        print(f"\n[Stage2 Completer] Writing dependency graph to file: {graph_path}")
        
        with open(graph_path, "w+", encoding="utf-8") as f:
            f.write("# Configuration dependency graph\n")
            f.write("# Format: Config → Dependency: Dependency1, Dependency2, ...\n\n")
            
            for config, deps in self.dependency_graph.items():
                if deps:
                    f.write(f"{config} → Dependency: {', '.join(deps)}\n")
                else:
                    f.write(f"{config} → Dependency: None\n")
        
        print(f"[Stage2 Completer] Dependency graph file written successfully")
        
        print("\n" + "-"*100)
        print("[Stage2 Completer] --- Final minimum configuration increment (ordered) ---")
        print("-"*100)
        for idx, cfg in enumerate(final_configs, 1):
            print(f"  {idx}. {cfg}")
        
        added_configs = set(final_configs)
        print(f"\n[Stage2 Completer] Total number of newly added config items: {len(added_configs)}")
        print(f"[Stage2 Completer] Set of newly added config items: {added_configs}")
        
        return final_configs, self.recursion_records, self.dependency_graph, added_configs ,total_tokens
