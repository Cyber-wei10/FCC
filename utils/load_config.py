import json
import os
from typing import List
import json


def load_config(CONFIG_FILE: str = "config.json"):
    """Load global configuration file"""
    if not os.path.exists(CONFIG_FILE):
        default_config = {
            "api_key_file": "api_key.json",
            "max_threads": 4,
            "qemu_dir": ".",
            "default_kernel_dir": None
        }
        with open(CONFIG_FILE, 'w+', encoding='utf-8') as f:
            json.dump(default_config, f, indent=2, ensure_ascii=False)
        return default_config
    
    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

