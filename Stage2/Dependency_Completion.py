#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import csv
import time
import pandas as pd
from utils.source_code import download_source_code,delete_source_code
from utils.shell_exec_simple import run_shell_command
from Stage2.dependency_completer_with_graph import Dependency_Completer
import re
def Stage2_main(cve_list=[],api_key=None, base_url=None, model=None,source_code_url=None,clear=False):
    results=[]
    df = pd.read_excel("Stage1_CVE_IDENTIFY_CONFIG.xlsx")
    config_dict = df.set_index('cve')['configs'].to_dict()
    version_dict = df.set_index('cve')['version'].to_dict()

    for cve in cve_list:
        config_str = config_dict.get(cve, "")
        config_items = config_str.split(",")
        config_list=[]
        for item in config_items:
            item=item.strip()
            if item.startswith("CONFIG_"):
                config_list.append(item)
        config_dict[cve]=list(set(config_list))
        config_list=list(set(config_list))
        version = version_dict.get(cve, None)
        if version:
            version=str(version).strip()
        else:
            continue
        
        new_dir = f"{cve}-linux-{version}"
        start_time = time.time()
        download_source_code(cve, version, source_code_url)
        download_time=time.time()-start_time
        start_time = time.time()
        res6=run_shell_command(f"cd {new_dir} && make defconfig")
        if res6["returncode"] != 0:
            results.append({
                "cve": cve,
                "version": version,
                "status": "make_defconfig_failed"
            })
            continue
        flag=0
        CONS=["CONFIG_DEBUG_INFO_BTF","FRAME_POINTER","KALLSYMS","CONFIG_KALLSYMS_ALL","CONFIG_DEBUG_INFO","CONFIG_BINFMT_MISC","CONFIG_USER_NS","CONFIG_NET_NS","CONFIG_E1000","CONFIG_E1000E","CONFIG_SYSVIPC","CONFIG_DEBUG_INFO_DWARF4","CONFIG_CONFIGFS_FS","CONFIG_SECURITYFS","CONFIG_KCOV","CONFIG_KASAN","CONFIG_KASAN_INLINE","CONFIG_USERFAULTFD","CONFIG_KEY_DH_OPERATIONS"]
        for  con in CONS :
            res6=run_shell_command(f"cd {new_dir} && ./scripts/config --enable {con}")
            if res6["returncode"] != 0:
                flag=1
                results.append({
                    "cve": cve,
                    "version": version,
                    "status": f"enable_{con}_failed"
                })
        if flag==1:
            continue
        res6=run_shell_command(f"cd {new_dir} && make olddefconfig")
        if res6["returncode"] != 0:
            results.append({
                "cve": cve,
                "version": version,
                "status": "make_first_olddefconfig_failed"
            })
            continue
        
        info={
            "cve": cve,
            "version": version,
            "status": "round_0_failed"
        }
        end_time = time.time()
        init_time=end_time-start_time
        temp_config_list = config_list.copy()
        for config in temp_config_list:
            temp_config = str(config).strip()[7:]
            res7 = run_shell_command(f'grep -R "config {temp_config}" {new_dir}')
            
            find_exact_config = False
            stdout_lines = res7["stdout"].split("\n")
            pattern = rf"config {re.escape(temp_config)}\b"
            
            for line in stdout_lines:
                line_stripped = line.strip()
                if re.search(pattern, line_stripped):
                    find_exact_config = True
                    break
            
            if not find_exact_config:
                config_list.remove(config)
        flag=0
        for config in config_list:
            res7=run_shell_command(f"cd {new_dir} && ./scripts/config --enable {config}")
            if res7["returncode"] != 0:
                flag=1
                break
        if flag ==1 :
            results.append(info)
            continue
        res7=run_shell_command(f"cd {new_dir} && make olddefconfig")
        if res7["returncode"] != 0:
            results.append(info)
            continue
        unenabled_configs=[]
        temp=[]
        with open(f"{new_dir}/.config", "r") as f:
            lines = f.readlines()
            for line in lines:
                if line.startswith("#") or line.strip() == "":
                    continue
                if line.startswith("CONFIG_") and "=y" in line:
                    config_name = line.strip().split("=")[0]
                    temp.append(config_name)
        for config in config_list:
            if config not in temp:
                unenabled_configs.append(config)
        print(unenabled_configs)
        start_time = time.time()
        Stage2_Completer=Dependency_Completer(api_key=api_key,base_url=base_url,model=model)
        final_configs, recursion_records, dependency_graph, added_configs,tokens =Stage2_Completer.completer(
            ROOT_DIR=new_dir,
            INITIAL_CONFIGS=unenabled_configs,
            CVE=cve
        )
        end_time = time.time()
        total_time=end_time-start_time
        
        info={}
        for config in final_configs:
            for idx, record in enumerate(recursion_records, 1):
                if config in record['target_configs'] and (config in record['success_configs'] and config not in record['missing_configs']):
                    info[config]=idx
                    break
        df = pd.DataFrame({
            "cve": [cve],
            "version": [version],
            "exp_name": [''],
            "kernel_dir": [''],
            "init_configs":[",".join(config_list)],
            "first_enable_failed":[",".join(unenabled_configs)],
            "added_configs": [",".join(added_configs)],
            "init_time":[init_time],
            "time": [total_time],
            "tokens":[tokens],
            "download_time":[download_time],
            "poc_time":[""]
        })

        excel_file = "Stage2_cve_configs.xlsx"

        if os.path.exists(excel_file):
            existing_df = pd.read_excel(excel_file)
            final_df = pd.concat([existing_df, df], ignore_index=True, axis=0)
        else:
            final_df = df
        final_df.to_excel(excel_file, index=False, header=True)
        
        if clear:
            delete_source_code(cve, version)