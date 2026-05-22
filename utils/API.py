import queue
from threading import Lock
from typing import List, Optional
import sys
import os
import json
class APIKeyPool:
    """API_KEY pool manager"""
    
    def __init__(self, api_keys: List[str]):
        self.available_keys = queue.Queue()
        self.used_keys = set()
        self.lock = Lock()
        
        for key in api_keys:
            self.available_keys.put(key)
    
    def acquire(self) -> Optional[str]:
        """Acquire an available API_KEY from pool"""
        try:
            key = self.available_keys.get(block=False)
            with self.lock:
                self.used_keys.add(key)
            return key
        except queue.Empty:
            return None
    
    def release(self, key: str):
        """Release API_KEY back to pool"""
        with self.lock:
            if key in self.used_keys:
                self.used_keys.remove(key)
                self.available_keys.put(key)
    
    def size(self) -> int:
        return self.available_keys.qsize() + len(self.used_keys)
    
    def available_count(self) -> int:
        return self.available_keys.qsize()

def load_api_keys(api_key_file: str) -> List[str]:
    """Load all available API keys from API_KEY file"""
    if not os.path.exists(api_key_file):
        raise FileNotFoundError(f"API_KEY file not found: {api_key_file}")
    
    with open(api_key_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    if isinstance(data, list):
        return data
    elif isinstance(data, dict) and 'api_keys' in data:
        return data['api_keys']
    else:
        raise ValueError(f"API_KEY file format error: {api_key_file} must be a list or a dict with 'api_keys' key")

def initialize_api_pool(api_key_file: str, max_threads: int) -> APIKeyPool:
    """Initialize API_KEY pool"""
    
    if api_key_file=="":
        print("Error: api_key_file is not specified in config.json")
        sys.exit(1)
    
    try:
        api_keys = load_api_keys(api_key_file)
        
        if len(api_keys) < max_threads:
            print(f"Warning: API_KEY count({len(api_keys)}) is less than max threads({max_threads})")
            print(f"Add at least {max_threads} API_KEYS to {api_key_file}")
        
        api_key_pool = APIKeyPool(api_keys)
        print(f"Initialized API_KEY pool with {len(api_keys)} keys")
        
        return api_key_pool
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print(f"Please create a file named {api_key_file} and add API_KEY list to it.")
        print(f"Example format: [\"key1\", \"key2\", \"key3\"]")
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)