import os
import json
import csv
import time
import logging
import requests
import tarfile
from typing import List, Dict, Tuple, Optional
import pandas as pd
from shell_exec import run_shell_command
from dependency_completer_with_graph import completer
import re
def main(cve_list, dataset_name):
    results=[]
    df = pd.read_excel(f"{dataset_name}.xlsx")
    config_dict = df.set_index('CVE')['CONFIGS'].to_dict()
    version_dict = df.set_index('CVE')['VERSION'].to_dict()

    for cve in cve_list:
        print(cve)
        config_str = config_dict.get(cve, "")
        print(config_str)
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
        if not os.path.exists(f"./{cve}-linux-{version}"):
            if os.path.exists(f"./temp/linux-{version}.tar.xz"):
                pass
            else :
                res1=run_shell_command(f"wget https://mirrors.tuna.tsinghua.edu.cn/kernel/v{version[0]}.x/linux-{version}.tar.xz")
                if res1["returncode"] != 0:
                    results.append({
                        "cve": cve,
                        "version": version,
                        "status": "download_failed"
                    })
                    continue
            temp_dir = "./temp"
            res2=run_shell_command(f"mkdir -p {temp_dir}")
            if res2["returncode"] != 0:
                results.append({
                    "cve": cve,
                    "version": version,
                    "status": "mkdir_failed"
                })
                continue
            res3=run_shell_command(f"tar -xvf linux-{version}.tar.xz -C {temp_dir}")
            if res3["returncode"] != 0:
                results.append({
                    "cve": cve,
                    "version": version,
                    "status": "tar_failed"
                })
                continue
            original_dir = f"{temp_dir}/linux-{version}"
            res4=run_shell_command(f"mv {original_dir} {new_dir}")
            if res4["returncode"] != 0:
                results.append({
                    "cve": cve,
                    "version": version,
                    "status": "mv_failed"
                })
                continue
            res5=run_shell_command(f"rm -rf {temp_dir} linux-{version}.tar.xz")
            if res5["returncode"] != 0:
                results.append({
                    "cve": cve,
                    "version": version,
                    "status": "rm_failed"
                })
                continue

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
        print(config_list)
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
        final_configs, recursion_records, dependency_graph, added_configs =completer(
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
        round_info={}
        for config, round_num in info.items():
            if round_num not in round_info:
                round_info[round_num]=0
            round_info[round_num]+=1
        with open("round_info.csv", "a+", newline="") as f:
            writer = csv.writer(f)
            for round_num,num in round_info.items():
                writer.writerow([cve, version, round_num, num])

        df = pd.DataFrame({
            "cve": [cve],
            "version": [version],
            "init_configs":[",".join(config_list)],
            "first_enable_failed":[",".join(unenabled_configs)],
            "added_configs": [",".join(added_configs)],
            "time": [total_time]
        })

        excel_file = f"added_configs_time-{dataset_name}.xlsx"

        if os.path.exists(excel_file):
            existing_df = pd.read_excel(excel_file)
            final_df = pd.concat([existing_df, df], ignore_index=True, axis=0)
        else:
            final_df = df

        final_df.to_excel(excel_file, index=False, header=True)

        res8=run_shell_command(f"rm -rf {new_dir}")
        if res8["returncode"] != 0:
            results.append({
                "cve": cve,
                "version": version,
                "status": "rm_failed"
            })
            continue

if __name__ == "__main__":
    cve_list = ["CVE-2016-10150","CVE-2016-4557","CVE-2016-6187","CVE-2017-16995","CVE-2017-18344","CVE-2017-2636","CVE-2017-6074","CVE-2017-8824","CVE-2018-12233","CVE-2018-5333","CVE-2018-6555","CVE-2019-6974","CVE-2020-16119","CVE-2020-25669","CVE-2020-27194","CVE-2020-27830","CVE-2020-28941","CVE-2020-8835","CVE-2021-22555","CVE-2021-26708","CVE-2021-27365","CVE-2021-34866","CVE-2021-3490","CVE-2021-3573","CVE-2021-42008","CVE-2021-43267","CVE-2022-0995","CVE-2022-1015","CVE-2022-25636","CVE-2022-32250","CVE-2022-34918","CVE-2023-32233"]
    main(cve_list,"CVE_IDENTIFY_CONFIG-KJCdata")
    cve_list = ['CVE-2025-21700', 'CVE-2023-31436', 'CVE-2023-4004', 'CVE-2024-26808', 'CVE-2024-26925', 'CVE-2024-1086', 'CVE-2023-52925', 'CVE-2024-0193', 'CVE-2023-3611', 'CVE-2024-0582', 'CVE-2024-36972', 'CVE-2024-58240', 'CVE-2024-27397', 'CVE-2024-39503', 'CVE-2023-52924', 'CVE-2025-21701',  'CVE-2023-4244', 'CVE-2023-3390', 'CVE-2024-53141', 'CVE-2023-4207', 'CVE-2023-4623', 'CVE-2025-21702', 'CVE-2023-4208', 'CVE-2025-40364', 'CVE-2024-1085', 'CVE-2023-52447', 'CVE-2023-4622', 'CVE-2024-26809', 'CVE-2023-3776', 'CVE-2024-53164', 'CVE-2024-26582', 'CVE-2023-3609', 'CVE-2023-6560', 'CVE-2023-4147', 'CVE-2023-52620', 'CVE-2023-3777', 'CVE-2023-6111', 'CVE-2023-5345', 'CVE-2024-41009', 'CVE-2023-5197', 'CVE-2023-6931', 'CVE-2023-0461', 'CVE-2023-6817', 'CVE-2025-21836', 'CVE-2024-49861', 'CVE-2024-53125', 'CVE-2025-21756', 'CVE-2024-41010', 'CVE-2023-4569', 'CVE-2023-4015', 'CVE-2024-26642', 'CVE-2023-4206', 'CVE-2023-6932', 'CVE-2024-26581', 'CVE-2024-57947', 'CVE-2023-4921']
    main(cve_list,"CVE_IDENTIFY_CONFIG-KernelCTFdata")
