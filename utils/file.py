import os
import pandas as pd
from typing import List
def check_input_file(file_path: str, required_columns: List[str]) -> bool:
    """
    Check if input file exists and contains required columns
    """
    if not os.path.exists(file_path):
        print(f"Error: Input file not found - {file_path}")
        return False
    
    try:
        df = pd.read_excel(file_path)
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            print(f"Error: Input file is required columns: {missing_columns}")
            print(f"File existing columns: {list(df.columns)}")
            return False
        return True
    except Exception as e:
        print(f"Error: Reading input file failed - {file_path}: {str(e)}")
        return False


def update_excel_field(file_path: str, cve: str, field_name: str, field_value: str):
    """
    Update Excel field for specified CVE in Excel file
    """
    if not os.path.exists(file_path):
        return
    try:
        df = pd.read_excel(file_path)
        cve_column = None
        for col in df.columns:
            if col.upper() in ['CVE', 'CVE_ID']:
                cve_column = col
                break
        
        if cve_column is None:
            return
        
        if field_name in df.columns:
            df.loc[df[cve_column] == cve, field_name] = field_value
            df.to_excel(file_path, index=False)
    except Exception as e:
        print(f"Updating Excel field failed: {str(e)}")
