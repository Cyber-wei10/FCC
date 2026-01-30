import requests
from bs4 import BeautifulSoup
import json
import random
import time
import warnings
from typing import List, Optional
import nvdlib
from langchain_community.chat_models import ChatOpenAI
from langchain_community.document_loaders import WebBaseLoader
from langchain.output_parsers.openai_functions import JsonOutputFunctionsParser
from langchain.prompts import ChatPromptTemplate
from langchain.utils.openai_functions import convert_pydantic_to_openai_function
from pydantic import BaseModel, Field
import openpyxl
import pandas as pd
import os
from requests.exceptions import RequestException, SSLError, HTTPError, ConnectionError, Timeout
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import re
warnings.filterwarnings("ignore", category=DeprecationWarning)

def prompt_build_1(CVE_ID, type, content):
    prompt1 = f"""
You are a cybersecurity expert. Consider the Relevant Informationprovided below and answer the Query.Content type of Relevant Information: [Content from NVD Relevant Refs/CWE Description/CVE Description/PoC code]
----------------------------------------
{type}: 
{content}
----------------------------------------

Query:{CVE_ID}

Given the specified CVE-ID, please extract and normalize vulnerability clues for configuration identification. Organize the clues into two types:
1.[semantic clues] that describe the triggering mechanism, involved components, and triggering conditions;
2.[build-evidence_clues] that describe concrete code and build-level evidence in the kernel source tree and configuration system, such as Kconfig options, affected files/directories, module names,function names, and key macros/constants.

For each information, produce a structured output with the following columns:
{{CVE_ID: [CVE_ID]
Content_type:[Content_type]
semantic clues:[semantic_clues]
build-evidence clues:[build-evidence_clues]}},
"""
    return prompt1

def prompt_build_2(CVE_ID, CWE_description, CVE_description, semantic_clues, build_evidence_clues,Makefile):
    prompt2 = f"""
Given the specified CVE-ID, use the [CVE description] and [CWE description] to semantically complete the normalized clues [semantic_clues] and [build-evidence clues] necessary, and then.taking the normalized clues together with the provided [Makefile], infer the kernel configurationoptions related to triggering the vulnerability.

Output format (JSON or table only):
[CONFIG_XXX, CONFIG_YYY,CONFIG_ZZZ,...]

----------------------------------------
CVE description
{CVE_description}
----------------------------------------
CWE description
{CWE_description}
----------------------------------------
semantic clues
{semantic_clues}
----------------------------------------
build-evidence clues
{build_evidence_clues}
----------------------------------------
Makefile
{Makefile}
"""
    return prompt2


def get_CVE_description(CVE):
    
    vuln_descriptions  = CVE.descriptions
    description = ""
    if vuln_descriptions != 'None':
        for item in vuln_descriptions:
            if item.lang == 'en':
                description = item.value
                break
    return description

def get_cwe_details(cwe_id):
    cwe_id = cwe_id.replace("CWE-", "")
    url = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
    try:
        response = requests.get(url)
        response.raise_for_status()
    except Exception as e:
        print(f"failed to get {cwe_id} details: {e}, skip the CWE")
        return None
    soup = BeautifulSoup(response.text, 'html.parser')
    details = {}
    
    description_div = soup.find('div', id='Description')
    if description_div:
        detail_div = description_div.find('div', class_='detail')
        if detail_div:
            indent_div = detail_div.find('div', class_='indent')
            if indent_div:
                details['description'] = indent_div.get_text(strip=True)
            else:
                details['description'] = detail_div.get_text(strip=True)
        else:
            details['description'] = "None"
    else:
        details['description'] = "None"
    
    return details

def get_CWE_description(cve_id):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }
    url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    time.sleep(1)
    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
    except Exception as e:
        print(f"failed to get {cve_id} details: {e}, skipping the CVE")
        return None
    soup = BeautifulSoup(response.text, 'html.parser')
    
    
    cwe_table = soup.find('table', {'data-testid': 'vuln-CWEs-table'})

    cwe_list = []

    if cwe_table:
        rows = cwe_table.find('tbody').find_all('tr')
        
        for row in rows:
            try:
                tds = row.find_all('td')
                
                if len(tds) < 3:
                    print(f"invalid CWE row structure for {cve_id}, skip this row")
                    continue
                a_tag = tds[0].find('a')
                if not a_tag:
                    print(f"no link found for {cve_id} in CWE row, skip this row")
                    continue
                cwe_id = a_tag.text.strip()
                
                cwe_name = tds[1].text.strip()
                
                source_span = tds[2].find('span')
                cwe_source = source_span.text.strip() if source_span else ""
                
                cwe_list.append({
                    'cwe_id': cwe_id,
                    'name': cwe_name,
                    'source': cwe_source,
                    'description': ""
                })
            except Exception as e:
                print(f"error processing CWE info for {cve_id}: {e}, skip this row")
                continue

    for item in cwe_list:
        print(f"{item['cwe_id']}: {item['name']}")
        details = get_cwe_details(item['cwe_id'])
        if details:
            item['description'] = details['description']
            print(item['description'])
    return cwe_list

def get_nvd_references(CVE) -> List[str]:
    
    refs = CVE.references
    if refs != []:
        references = []
        for ref in refs:
            url = ref.url
            if url != '' :
                references.append(url)
        return references
    else:
        return []

class ReproductionEnvAnalysis(BaseModel):

    url: str = Field(description="The URL of the analyzed page.")
    relevancy: str = Field(description="Is this page useful for setting up a reproduction environment? (Yes/No)")
    summary: str = Field(description="If Yes, summarize the specific environment details (e.g., vulnerable versions, docker setup, POC code, dependency requirements). If No, output 'NONE'.")

def get_Content_from_NVD_Relevant_Refs(content: str):
    API_KEY = "sk-zk2193623590c74fc1102dd01d236d518ec694a2b57f2605"
    BASE_URL = "https://api.zhizengzeng.com/v1/chat/completions"
    if not API_KEY or API_KEY.strip() == "your_LLM_api_key_here":
        raise ValueError("Replace with a valid LLM API Key")
    
    llm = ChatOpenAI(api_key=API_KEY, base_url=BASE_URL, model="model name", temperature=0.0, request_timeout=60)
    
    prompt = ChatPromptTemplate.from_template(
    """
You are a cybersecurity researcher specializing in Linux kernel vulnerability reproduction. 
Analyze the content from the URL below to determine if it helps in BUILDING A LINUX KERNEL VULNERABILITY REPRODUCTION ENVIRONMENT. 

Content: {content} 

Please return the result in the following JSON format exactly: 
{{
  "relevancy": "Yes/No",
  "summary": "If Yes, summarize the specific environment details. If No, output 'NONE'."
}}

Step 1: Assess Relevancy for Kernel Environment Setup
- Does the content provide specific technical details needed to reproduce the Linux kernel vulnerability?
- Look for: 
    - Affected Linux kernel versions (exact version numbers).
    - Kernel source code snippets or POC (Proof of Concept) code targeting the kernel.
    - Kernel configuration options (CONFIG_XXX).
    - Build flags or compilation parameters for kernel building.
    - Module loading/unloading commands or kernel command line parameters.
    - Specific kernel subsystems or modules affected.
- Answer: [Yes/No]

Step 2: Summarize Kernel Environment Details
- If "Yes":
    - Extract and summarize the specific details needed to set up the kernel environment (e.g., "Use Linux kernel version 5.10.100", "Enable CONFIG_XYZ kernel option", "Apply patch X before building").
- If "No":
    - Summary: NONE
"""
)
    
    chain = prompt | llm
    try:

        print(f"  -> Calling LLM for analysis...")
        llm_response = chain.invoke({
            "content": content
        })
        
        import json
        try:
            if hasattr(llm_response, 'content'):
                content = llm_response.content
            else:
                content = str(llm_response)
            
            result = json.loads(content)
        except json.JSONDecodeError:
            import re
            json_pattern = r'\{.*?\}'
            matches = re.findall(json_pattern, content, re.DOTALL)
            if matches:
                try:
                    result = json.loads(matches[-1])
                except json.JSONDecodeError:
                    print(f"  -> [ERROR] Failed to parse LLM response as JSON")
                    return None
            else:
                print(f"  -> [ERROR] No JSON found in LLM response")
                return None
        
        if result.get('relevancy') == 'Yes':
            print(f"  -> [USEFUL] Found reproduction info.")
            return result
        else:
            print(f"  -> [SKIP] Not relevant for environment setup.")
        
        time.sleep(random.uniform(1, 3))
        
    except SSLError as e:
        print(f"  -> [ERROR] SSL error occurred: {e}")
        return None
    except Timeout as e:
        print(f"  -> [ERROR] Timeout occurred: {e}")
        return None
    except HTTPError as e:
        print(f"  -> [ERROR] HTTP error occurred: {e}")
        return None
    except ConnectionError as e:
        print(f"  -> [ERROR] Connection error occurred: {e}")
        return None
    except RequestException as e:
        print(f"  -> [ERROR] Request error occurred: {e}")
        return None
    except Exception as e:
        print(f"  -> [ERROR] Unexpected error occurred: {e}")
        return None

def get_CVE_detail(CVE_ID, max_retries=3):
    retries = 0
    while retries < max_retries:
        try:
            print(f"trying to get detail of {CVE_ID} {retries+1}/{max_retries}...")
            r = nvdlib.searchCVE(cveId=CVE_ID, key='016d4763-d049-4531-9bc1-6f62e9d7fa12', delay=1) 
            if r:
                return r[0]
            else:
                print(f"No detailed information found for CVE {CVE_ID}")
                return None
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 503:
                print(f"NVD API service unavailable (503), retrying after {retries+1} seconds...")
                time.sleep(retries+1)
                retries += 1
            else:
                print(f"HTTP error when getting CVE details: {e}")
                return None
        except Exception as e:
            print(f"Error when getting CVE details: {e}")
            return None
    print(f"Reached maximum retries ({max_retries}) for CVE {CVE_ID}, cannot get detailed information")
    return None

def call_LLM_api(prompt: str):
    API_KEY = "sk-zk2193623590c74fc1102dd01d236d518ec694a2b57f2605"
    BASE_URL = "https://api.zhizengzeng.com/v1/chat/completions"
    if not API_KEY or API_KEY.strip() == "your_LLM_api_key_here":
        raise ValueError("Replace with a valid LLM API Key")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}"
    }
    data = {
        "model": "model name",
        "messages": [
            {"role": "system", "content": "You are a professional Linux kernel configuration analyst, strictly follow the output requirements."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.0,
        "max_tokens": 15000,
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
        print(f"HTTP response status code: {response.status_code}")
        response_json = response.json()
        print(f"LLM API response content: {json.dumps(response_json, ensure_ascii=False)}")
        
        content = response_json["choices"][0]["message"]["content"].strip()

        return content

    except requests.exceptions.RequestException as e:
        print(f"HTTP request failed: {str(e)}")
        return ""
    except KeyError as e:
        print(f"Response format parse failed: missing field {e}")
        return ""
    except Exception as e:
        print(f"LLM API call failed: {str(e)}")
        return ""

def parse_response1(response):
    all_results = []
    
    try:
        response = response.strip()
        
        if "{" not in response:
            print(f"Warning: Response format does not match expectations, cannot parse: {response[:100]}...")
            return all_results
        
        start_pos = 0
        while start_pos < len(response):
            start_pos = response.find("{", start_pos)
            if start_pos == -1:
                break
            
            bracket_count = 1
            end_pos = start_pos + 1
            while end_pos < len(response) and bracket_count > 0:
                if response[end_pos] == "{":
                    bracket_count += 1
                elif response[end_pos] == "}":
                    bracket_count -= 1
                end_pos += 1
            
            info_block = response[start_pos:end_pos]
            
            CVE_ID = ""
            Content_type = ""
            semantic_clues = ""
            build_evidence_clues = ""
            
            lines = info_block.split("\n")
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                line = line.strip("{},").strip()
                
                if ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if value.startswith("[") and value.endswith("]"):
                        value = value[1:-1].strip()
                    
                    if key == "CVE_ID":
                        CVE_ID = value
                    elif key == "Content_type":
                        Content_type = value
                    elif key == "semantic clues":
                        semantic_clues = value
                    elif key == "build-evidence clues":
                        build_evidence_clues = value
            all_results.append({
                "CVE_ID": CVE_ID,
                "Content_type": Content_type,
                "semantic_clues": semantic_clues,
                "build_evidence_clues": build_evidence_clues
            })
            
            start_pos = end_pos
    
    except Exception as e:
        print(f"failed to parse response: {e}")
    
    return all_results

def save_to_excel_1(res,OUTPUT):
    semantic_clues=[]
    build_evidence_clues=[]
    data1 = []
    for result in res:
        data1.append({
            'CVE_ID': result["CVE_ID"],
            'Content_type': result["Content_type"],
            'semantic_clues': result["semantic_clues"],
            'build_evidence_clues': result["build_evidence_clues"]
        })
        semantic_clues.append(result["semantic_clues"])
        build_evidence_clues.append(result["build_evidence_clues"])

    df1 = pd.DataFrame(data1)

    excel_file1 = f"CVE_IDENTIFY-{OUTPUT}.xlsx"
    if os.path.exists(excel_file1):
        existing_df1 = pd.read_excel(excel_file1)
        df1 = pd.concat([existing_df1, df1], ignore_index=True)

    with pd.ExcelWriter(excel_file1, engine='openpyxl') as writer:
        df1.to_excel(writer, index=False, sheet_name='Sheet1')

    print(f"Excel file saved as {excel_file1}, total written/appended {len(data1)} records")
    return semantic_clues, build_evidence_clues

def prompt_normalization(CVE_ID, PoC_FILES, data_dir='cve_data',OUTPUT=''):
    import os
    import json
    
    cve_data_dir = os.path.join(data_dir, CVE_ID)
    cve_info_file = os.path.join(cve_data_dir, 'cve_info.json')
    refs_dir = os.path.join(cve_data_dir, 'references')
    
    if not os.path.exists(cve_info_file):
        print(f"the data file of CVE {CVE_ID} does not exist, start to crawl")
        craw(CVE_ID, data_dir)
    semantic_clues = []
    build_evidence_clues = []
    with open(cve_info_file, 'r', encoding='utf-8') as f:
        cve_info = json.load(f)
    
    for ref in cve_info['references']:
        with open(ref['filepath'], 'r', encoding='utf-8') as f:
            ref_content = f.read()
            temp = get_Content_from_NVD_Relevant_Refs(ref['filepath']+"\n"+ref_content)
            if temp:
                prompt1 = prompt_build_1(CVE_ID, "Content_from_NVD_Relevant_Refs", temp)
                response1 = call_LLM_api(prompt1)
                results1 = parse_response1(response1)
                semantic_clue, build_evidence_clue = save_to_excel_1(results1,OUTPUT)
                semantic_clues.extend(semantic_clue)
                build_evidence_clues.extend(build_evidence_clue)
    
    CVE_description = cve_info['description']
    prompt1 = prompt_build_1(CVE_ID, "CVE Description", CVE_description)
    response1 = call_LLM_api(prompt1)
    results1 = parse_response1(response1)
    semantic_clue, build_evidence_clue = save_to_excel_1(results1,OUTPUT)
    semantic_clues.extend(semantic_clue)
    build_evidence_clues.extend(build_evidence_clue)
    
    CWE_description = ""
    if cve_info['cwe_list']:
        for cwe in cve_info['cwe_list']:
            CWE_description += f"\n{cwe['cwe_id']}: {cwe['name']}\n{cwe['description']}\n"
    prompt1 = prompt_build_1(CVE_ID, "CWE Description", CWE_description)

    response1 = call_LLM_api(prompt1)

    results1 = parse_response1(response1)
    semantic_clue, build_evidence_clue = save_to_excel_1(results1,OUTPUT)
    semantic_clues.extend(semantic_clue)
    build_evidence_clues.extend(build_evidence_clue)

    PoC_code = ""
    for PoC_FILE in PoC_FILES:
        with open(os.path.join(data_dir, CVE_ID, "PoC", PoC_FILE), 'r', encoding='utf-8') as f:
            PoC_code += PoC_FILE + "\n" + f.read() + "\n\n"
            prompt1 = prompt_build_1(CVE_ID, "PoC code", PoC_code)
            response1 = call_LLM_api(prompt1)
            results1 = parse_response1(response1)
            semantic_clue, build_evidence_clue = save_to_excel_1(results1,OUTPUT)
            semantic_clues.extend(semantic_clue)
            build_evidence_clues.extend(build_evidence_clue)
    init_configs = []
    if results1 !=[]:
        s_end=False
        b_end=False
        for i in range(0, max(len(semantic_clues), len(build_evidence_clues), 10), 1):
            response2="" 
            semantic_clues_batch=[]
            if i>=len(semantic_clues):
                semantic_clues_batch=[]
            else:
                if i+10>len(semantic_clues):
                    s_end=True
                semantic_clues_batch = semantic_clues[i:i+10] if not s_end else semantic_clues[i:]
            
            build_evidence_clues_batch=[]
            if i>=len(build_evidence_clues):
                build_evidence_clues_batch=[]
            else:
                if i+10>len(build_evidence_clues):
                    b_end=True
                build_evidence_clues_batch = build_evidence_clues[i:i+10] if not b_end else build_evidence_clues[i:]

            semantic_clues_batch = "\n".join(semantic_clues_batch)
            build_evidence_clues_batch = "\n".join(build_evidence_clues_batch)
            Makefile=""
            with open(os.path.join(data_dir, CVE_ID, "Makefile"), 'r', encoding='utf-8') as f:
                Makefile=f.read()
            prompt2 = prompt_build_2(
                CVE_ID,
                CWE_description, 
                CVE_description, 
                semantic_clues_batch,
                build_evidence_clues_batch,
                Makefile
            )
            print(f"calling LLM API 2")
            response2 = call_LLM_api(prompt2)
    
            if response2:
                configs=response2.strip('[]').split(',')
                configs=[config.strip() for config in configs]
    init_configs = list(set(init_configs))
    init_configs = "\n".join(init_configs)
    data2 = {
        'CVE': [CVE_ID],
        'CONFIGS': [init_configs]
    }
    df2 = pd.DataFrame(data2)

    excel_file2 = f"CVE_IDENTIFY_CONFIG-{OUTPUT}.xlsx"
    if os.path.exists(excel_file2):
        existing_df2 = pd.read_excel(excel_file2)
        df2 = pd.concat([existing_df2, df2], ignore_index=True)

    with pd.ExcelWriter(excel_file2, engine='openpyxl') as writer:
        df2.to_excel(writer, index=False, sheet_name='Sheet1')

    print(f"Excel saved: {excel_file2}")
    return response2

def craw(CVE_ID, save_dir='cve_data'):
    
    cve_save_dir = os.path.join(save_dir, CVE_ID)
    refs_save_dir = os.path.join(cve_save_dir, 'references')
    os.makedirs(refs_save_dir, exist_ok=True)
    
    
    cve = get_CVE_detail(CVE_ID)
    if not cve:
        print(f"Failed to get CVE details: {CVE_ID}")
        return None
    
    cve_description = get_CVE_description(cve)
    
    cwe_list = get_CWE_description(CVE_ID)
    
    references = get_nvd_references(cve)
    
    saved_refs = []
    for url in references:
        print(f"  Fetching: {url}")
        
        filename = re.sub(r'^https?://', '', url)
        filename = re.sub(r'[\\/:*?"<>|]', '_', filename)
        filename = filename[:255]
        filepath = os.path.join(refs_save_dir, f"{filename}.txt")
        
        if os.path.exists(filepath):
            print(f"  -> File already exists, skipping: {filepath}")
            saved_refs.append({
                'url': url,
                'filepath': filepath
            })
            continue
        
        try:
            loader = WebBaseLoader(url)
            documents = loader.load()
            page_content = documents[0].page_content
            
            if not page_content:
                print(f"  -> Content is empty, skipping: {url}")
                continue
            
            with open(filepath, 'w+', encoding='utf-8') as f:
                f.write(f"{url}\n")
                f.write(page_content)
            
            print(f"  -> Saved successfully: {filepath}")
            saved_refs.append({
                'url': url,
                'filepath': filepath
            })
            
            time.sleep(random.uniform(1, 3))
            
        except SSLError as e:
            print(f"  -> [ERROR] SSLError: {e}")
            continue
        except Timeout as e:
            print(f"  -> [ERROR] Timeout: {e}")
            continue
        except HTTPError as e:
            print(f"  -> [ERROR] HTTPError: {e}")
            continue
        except ConnectionError as e:
            print(f"  -> [ERROR] ConnectionError: {e}")
            continue
        except RequestException as e:
            print(f"  -> [ERROR] RequestException: {e}")
            continue
        except Exception as e:
            print(f"  -> [ERROR] Exception: {e}")
            continue
    
    cve_info = {
        'CVE_ID': CVE_ID,
        'description': cve_description,
        'cwe_list': cwe_list,
        'references': saved_refs
    }
    
    json_filepath = os.path.join(cve_save_dir, 'cve_info.json')
    with open(json_filepath, 'w+', encoding='utf-8') as f:
        json.dump(cve_info, f, ensure_ascii=False, indent=2)
    
    return cve_info

def main(cve_list,OUTPUT=""):
    for cve in cve_list:
        craw(cve)
    save_dir='cve_data'
    for cve in cve_list:
        poc_dir = os.path.join(save_dir, cve, "PoC")
        poc_files = os.listdir(poc_dir)
        print(poc_files)
        prompt_normalization(cve, poc_files, save_dir,OUTPUT)

if __name__ == "__main__":
    cve_list = ["CVE-2016-10150","CVE-2016-4557","CVE-2016-6187","CVE-2017-16995","CVE-2017-18344","CVE-2017-2636","CVE-2017-6074","CVE-2017-8824","CVE-2018-12233","CVE-2018-5333","CVE-2018-6555","CVE-2019-6974","CVE-2020-16119","CVE-2020-25669","CVE-2020-27194","CVE-2020-27830","CVE-2020-28941","CVE-2020-8835","CVE-2021-22555","CVE-2021-26708","CVE-2021-27365","CVE-2021-34866","CVE-2021-3490","CVE-2021-3573","CVE-2021-42008","CVE-2021-43267","CVE-2022-0995","CVE-2022-1015","CVE-2022-25636","CVE-2022-32250","CVE-2022-34918","CVE-2023-32233"]
    main(cve_list,OUTPUT="KJCdata")
    cve_list = ['CVE-2025-21700', 'CVE-2023-31436', 'CVE-2023-4004', 'CVE-2024-26808', 'CVE-2024-26925', 'CVE-2024-1086', 'CVE-2023-52925', 'CVE-2024-0193', 'CVE-2023-3611', 'CVE-2024-0582', 'CVE-2024-36972', 'CVE-2024-58240', 'CVE-2024-27397', 'CVE-2024-39503', 'CVE-2023-52924', 'CVE-2025-21701',  'CVE-2023-4244', 'CVE-2023-3390', 'CVE-2024-53141', 'CVE-2023-4207', 'CVE-2023-4623', 'CVE-2025-21702', 'CVE-2023-4208', 'CVE-2025-40364', 'CVE-2024-1085', 'CVE-2023-52447', 'CVE-2023-4622', 'CVE-2024-26809', 'CVE-2023-3776', 'CVE-2024-53164', 'CVE-2024-26582', 'CVE-2023-3609', 'CVE-2023-6560', 'CVE-2023-4147', 'CVE-2023-52620', 'CVE-2023-3777', 'CVE-2023-6111', 'CVE-2023-5345', 'CVE-2024-41009', 'CVE-2023-5197', 'CVE-2023-6931', 'CVE-2023-0461', 'CVE-2023-6817', 'CVE-2025-21836', 'CVE-2024-49861', 'CVE-2024-53125', 'CVE-2025-21756', 'CVE-2024-41010', 'CVE-2023-4569', 'CVE-2023-4015', 'CVE-2024-26642', 'CVE-2023-4206', 'CVE-2023-6932', 'CVE-2024-26581', 'CVE-2024-57947', 'CVE-2023-4921']
    main(cve_list,OUTPUT="KernelCTFdata")