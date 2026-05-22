#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CVE Automation Tool
Supports processing single or multiple CVE IDs via command line arguments

Usage Examples:
  # Single CVE mode (required parameters: -t CVE ID, --exp-name POC_CMD --version KERNEL_VERSION)
  python main.py -t CVE-2021-22555 --exp-name poc
  python main.py -t CVE-2021-22555 --exp-name poc --version 5.10
  
  # File mode (Excel file must contain cve, version, exp_name columns)
  python main.py -f cve_list.xlsx
  python main.py -f cve_list.xlsx --threads 8
"""
import argparse
import sys
import os
os.environ["USER_AGENT"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List
import threading
import pandas as pd
from utils.load_config import *
from utils.file import *
from utils.API import *
from Stage1.Configuration_Identification import Stage1_main
from Stage2.Dependency_Completion import Stage2_main
from Stage3.Config_Minimization import Stage3_main
import warnings
warnings.filterwarnings("ignore")
print_lock = threading.Lock()

class FCC:
    def __init__(self, config_file: str = "./config.json"):
        self.config = load_config(config_file)
        self.base_url=self.config.get("base_url")
        self.model=self.config.get("model")
        self.source_code_url=self.config.get("source_code_url")
        self.max_threads = self.config.get("max_threads", 1)
        self.api_key_file = self.config.get("api_key_file")
        self.api_key_pool = initialize_api_pool(self.api_key_file, self.max_threads)
        self.nvdlib_api_key = self.config.get("nvdlib_api_key")

    def process_single_cve(self, cve: str, exp_name: str = None, qemu_dir: str = None, kernel_dir: str = None, version: str = None, api_key: str = None):
        """
        Process single CVE mode
        
        Args:
            cve: CVE ID string
            exp_name: POC executable file name
            qemu_dir: QEMU environment directory
            kernel_dir: Kernel source directory
            version: Kernel version string
            input_file: Input configuration
            
        Returns:
            tuple: (cve, success, error_message)
        """
        cve = cve.strip()
        if not cve:
            return (cve, False, "Empty CVE ID")
        
        with print_lock:
            print(f"\n{'='*60}")
            print(f"Processing CVE: {cve}")
            if api_key:
                masked_key = api_key[:8] + "..." + api_key[-4:] if len(api_key) > 12 else "***"
                print(f"Using API_KEY: {masked_key}")
        
        success = True
        error_msg = ""
        
        # Stage 1: Configuration item identification
        with print_lock:
            print(f"[FCC] Stage 1: Configuration item identification...")
        
        try:
            #  Stage1 needs to obtain version from external sources (if not provided, it needs to be added manually)
            if not version:
                print(f"[FCC] WARNING: version is required after Stage1 completion")
                return (cve, False, "version required after Stage1 completion")
            Stage1_main([cve], version=version, api_key=api_key if api_key else None, base_url=self.base_url, model=self.model,source_code_url=self.source_code_url, nvdlib_api_key=self.nvdlib_api_key, craw=True)
            with print_lock:
                print(f"[FCC] Stage 1: Configuration item identification completed")
                print(f"[FCC] Output file: Stage1_CVE_IDENTIFY_CONFIG.xlsx")
            
            # Update fields in the Stage1 output file
            step1_output = "Stage1_CVE_IDENTIFY_CONFIG.xlsx"
            if os.path.exists(step1_output):
                try:
                    df_step1 = pd.read_excel(step1_output)
                    # Find the corresponding row for the CVE and update fields
                    if 'cve' in df_step1.columns:
                        # Ensure version and exp_name columns are strings
                        if 'version' in df_step1.columns:
                            df_step1['version'] = df_step1['version'].astype(str).replace('nan', '')
                        if 'exp_name' in df_step1.columns:
                            df_step1['exp_name'] = df_step1['exp_name'].astype(str).replace('nan', '')
                        if 'kernel_dir' in df_step1.columns:
                            df_step1['kernel_dir'] = df_step1['kernel_dir'].astype(str).replace('nan', '')
                        
                        # Update version field
                        if 'version' in df_step1.columns and version:
                            df_step1.loc[df_step1['cve'] == cve, 'version'] = str(version)
                        # Update exp_name field
                        if 'exp_name' in df_step1.columns and exp_name:
                            df_step1.loc[df_step1['cve'] == cve, 'exp_name'] = str(exp_name)
                        # Update kernel_dir field
                        if 'kernel_dir' in df_step1.columns and kernel_dir:
                            df_step1.loc[df_step1['cve'] == cve, 'kernel_dir'] = str(kernel_dir)
                        # Save the updated file back
                        df_step1.to_excel(step1_output, index=False)
                        with print_lock:
                            print(f"[FCC] Updated Stage1 output file with exp_name={str(exp_name)}, version={str(version)}, kernel_dir={str(kernel_dir)}")
                except Exception as e:
                    with print_lock:
                        print(f"[FCC] Updating Stage1 output file failed: {str(e)}")
        except Exception as e:
            success = False
            error_msg = f"Stage1 failed: {str(e)}"
            with print_lock:
                print(f"[FCC] Stage 1 execution failed: {error_msg}")
            return (cve, success, error_msg)
        
        # Check Stage 1 output and prepare Stage 2 data
        step1_output = "Stage1_CVE_IDENTIFY_CONFIG.xlsx"
        if not os.path.exists(step1_output):
            return (cve, False, f"Stage1 output file not found - {step1_output}")
        
        # Read version information from Stage1 output if not provided
        try:
            df_step1 = pd.read_excel(step1_output)
            cve_row = df_step1[df_step1['cve'] == cve]
            if not cve_row.empty:
                if not version:
                    # Try to get version from Stage1 output
                    if 'version' in cve_row.columns:
                        version = cve_row['version'].values[0]
        except Exception as e:
            print(f"[FCC] Reading Stage1 output file failed: {str(e)}")
        
        # Stage 2: Record processing
        with print_lock:
            print(f"[FCC] Stage 2: Record processing started...")
            if version:
                print(f"[FCC] Using kernel version: {version}")
        try:
            Stage2_main([cve],api_key=api_key if api_key else None, base_url=self.base_url, model=self.model,source_code_url=self.source_code_url)
            with print_lock:
                print(f"[FCC] Stage 2: Record processing completed")
                print(f"[FCC] Output file: Stage2_cve_configs.xlsx")
            # Update fields in the Stage2 output file
            step2_output = "Stage2_cve_configs.xlsx"
            if os.path.exists(step2_output):
                try:
                    df = pd.read_excel(step2_output)
                    if 'cve' in df.columns:
                        # Ensure version and exp_name columns are strings
                        if 'version' in df.columns:
                            df['version'] = df['version'].astype(str).replace('nan', '')
                        if 'exp_name' in df.columns:
                            df['exp_name'] = df['exp_name'].astype(str).replace('nan', '')
                        if 'kernel_dir' in df.columns:
                            df['kernel_dir'] = df['kernel_dir'].astype(str).replace('nan', '')
                        if exp_name and 'exp_name' in df.columns:
                            df.loc[df['cve'] == cve, 'exp_name'] = str(exp_name)
                        if kernel_dir and 'kernel_dir' in df.columns:
                            df.loc[df['cve'] == cve, 'kernel_dir'] = str(kernel_dir)
                        df.to_excel(step2_output, index=False)
                except: pass
        except Exception as e:
            success = False
            error_msg = f"Stage2 failed: {str(e)}"
            with print_lock:
                print(f"[FCC] Stage 2 execution failed: {error_msg}")
            return (cve, success, error_msg)
        
        # Stage 3: Configuration minimization
        with print_lock:
            print(f"[FCC] Stage 3: Configuration minimization started...")
        
        try:
            Stage3_main([cve], qemu_dir=qemu_dir,source_code_url=self.source_code_url,api_key=api_key if api_key else None, base_url=self.base_url, model=self.model)
            with print_lock:
                print(f"[FCC] Stage 3: Configuration minimization completed")
                print(f"[FCC] Output file: Stage3_{cve}-{version}-minimal-configs.json")
        except Exception as e:
            success = False
            error_msg = f"Stage3 failed: {str(e)}"
            with print_lock:
                print(f"[FCC] Stage 3 execution failed: {error_msg}")
            return (cve, success, error_msg)
        
        with print_lock:
            print(f"[FCC] {cve} All 3 steps completed successfully")
        print("="*60)
        return (cve, success, error_msg)

    def process_with_api_key(self,cve: str, metadata: dict):
        """get API_KEY and process single CVE"""
        api_key = None
        try:
            api_key = self.api_key_pool.acquire()
            if api_key is None:
                return (cve, False, "No available API_KEY available")
            
            result = self.process_single_cve(
                cve,
                exp_name=str(metadata.get('exp_name', '')),
                qemu_dir=str(metadata.get('qemu_dir', '')),
                kernel_dir=str(metadata.get('kernel_dir', '')),
                version=str(metadata.get('version', '')),
                api_key=api_key
            )
            return result
        finally:
            if api_key:
                self.api_key_pool.release(api_key)

    def process_cves_multithreaded(self,cve_list: List[str], max_workers: int = -1, input_file: str = None):
        """
        Process multiple CVEs using multi-threading
        """
        
        if self.api_key_pool is None:
            raise RuntimeError("API_KEY pool is not initialized, please call initialize_api_pool() first")
        if max_workers == -1:
            max_workers = self.max_threads

        print(f"[FCC] Start multi-threading processing {len(cve_list)} CVEs, max_workers: {max_workers}")
        print(f"[FCC] API_KEY pool status: Available {self.api_key_pool.available_count()}/{self.api_key_pool.size()}")
        
        if self.api_key_pool.size() < max_workers:
            print(f"Warning: Number of API_KEY count({self.api_key_pool.size()}) is less than max_workers({max_workers}")
        
        cve_metadata = {}
        if input_file and os.path.exists(input_file):
            df = pd.read_excel(input_file)
            for _, row in df.iterrows():
                cve_id = row['cve']
                cve_metadata[cve_id] = {
                    'version': row.get('version', ''),
                    'exp_name': row.get('exp_name', ''),
                    'kernel_dir': row.get('kernel_dir', ''),
                    'qemu_dir': row.get('qemu_dir', '')
                }
        
        results = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for cve in cve_list:
                metadata = cve_metadata.get(cve, {})
                future = executor.submit(self.process_with_api_key, cve, metadata)
                futures[future] = cve
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    cve = futures[future]
                    results.append((cve, False, str(e)))
        
        print("\n" + "="*60)
        print("[FCC] Processing results summary:")
        
        success_count = sum(1 for _, success, _ in results if success)
        fail_count = len(results) - success_count
        
        print(f"[FCC] Total: {len(results)} CVEs")
        print(f"[FCC] Success: {success_count} CVEs")
        print(f"[FCC] Fail: {fail_count} CVEs")
        
        if fail_count > 0:
            print("[FCC] Failed CVEs:")
            for cve, success, error_msg in results:
                if not success:
                    print(f"[FCC]  - {cve}: {error_msg}")
        print("="*60)


def main():
    """
    Main function, handle command-line arguments
    """
    parser = argparse.ArgumentParser(
        description='CVE Automation Tool - configuration identification, dependency completion, and minimization',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '-t', '--target',
        type=str,
        help='Specify single CVE ID (Use with --exp-name)'
    )
    # Single CVE required parameters
    parser.add_argument(
        '--exp-name',
        type=str,
        default='',
        help='Execute POC file command (Required for single CVE mode)'
    )
    parser.add_argument(
        '--qemu-dir',
        type=str,
        default='.',
        help='QEMU environment directory (Default: Current directory)'
    )
    parser.add_argument(
        '--version',
        type=str,
        default=None,
        help='linux kernel version (Required for single CVE mode, can download kernel source code automatically)'
    )
    parser.add_argument(
        '--kernel-dir',
        type=str,
        default=None,
        help='linux kernel source code directory (Optional, for Stage2/Stage3)'
    )
    group.add_argument(
        '-f', '--file',
        type=str,
        help='Specify the path to the Excel file containing the CVE list (Must contain cve, version, exp_name, kernel_dir, qemu_dir columns)'
    )
    parser.add_argument(
        '--threads',
        type=int,
        default=-1,
        help='Maximum number of threads to use'
    )

    args = parser.parse_args()
    fcc=FCC()
    
    # Single CVE mode validation
    if args.target:
        if not args.target.upper().startswith('CVE-'):
            print(f"ERROR: CVE ID format error: {args.target} (should be CVE-XXXX-XXXXX)")
            sys.exit(1)
        if not args.exp_name:
            print(f"ERROR: When using -t, --exp-name is required")
            sys.exit(1)
        if not args.version:
            print(f"ERROR: When using -t, --version is required")
            sys.exit(1)
        if not args.qemu_dir:
            print(f"ERROR: When using -t, --qemu-dir is required")
            sys.exit(1)
        print(f"Processing single CVE mode: {args.target}")
        print(f"  - exp_name: {args.exp_name}")
        print(f"  - kernel_dir: {args.kernel_dir if args.kernel_dir else 'Current directory'}")
        print(f"  - version: {args.version if args.version else 'Manual addition required'}")
    # File mode validation
    if args.file:
        if not os.path.exists(args.file):
            print(f"ERROR: Input file not found: {args.file}")
            sys.exit(1)
        required_columns = ['cve', 'version', 'exp_name', 'qemu_dir']
        if not check_input_file(args.file, required_columns):
            sys.exit(1)
        try:
            df = pd.read_excel(args.file)
            print(f"Reading CVE list from file: {args.file}")
            print(f"Total {len(df)} CVEs")
        except Exception as e:
            print(f"ERROR: Failed to read Excel file: {str(e)}")
            sys.exit(1)
    
    if args.target:
        cve_list = [args.target]
        api_key = fcc.api_key_pool.acquire()
        try:
            result = fcc.process_single_cve(
                cve=cve_list[0], 
                exp_name=args.exp_name, 
                qemu_dir=args.qemu_dir,
                kernel_dir=args.kernel_dir,
                version=args.version,
                api_key=api_key
            )
        finally:
            if api_key:
                fcc.api_key_pool.release(api_key)
        if result[1]:
            print(f"Processing {result[0]} completed")
        else:
            print(f"Processing {result[0]} failed: {result[2]}")
    else:
        df = pd.read_excel(args.file)
        cve_list = df['cve'].tolist()
        fcc.process_cves_multithreaded(
            cve_list=cve_list, 
            max_workers=args.threads,
            input_file=args.file
        )
    print("All processing tasks completed.")

if __name__ == "__main__":
    main()