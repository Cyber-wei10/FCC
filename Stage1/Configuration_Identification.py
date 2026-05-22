import os
import requests
from bs4 import BeautifulSoup
import json
import random
import time
from typing import List
import nvdlib
from langchain_community.document_loaders import WebBaseLoader
import pandas as pd
from requests.exceptions import RequestException, SSLError, HTTPError, ConnectionError, Timeout
import re
import tiktoken
from utils.source_code import download_source_code, delete_source_code
class Configuration_Identification:
    def __init__(self, api_key: str, base_url: str, model: str, clear: bool = False, source_code_url: str = None):
        self.api_key = api_key
        self.base_url = base_url
        self.model=model
        self.clear=clear
        self.source_code_url=source_code_url
    def prompt_build(self, CVE_ID, CWE_description, CVE_description, semantic_summary, evidence_summary,makefile_content):
        prompt = f"""
    Given the specified [CVE-ID], use the [CVE description], [CWE description] to semantically complete [semantic clues summary], [build-evidence clues summary], then taking the clues together with the provided [Makefile content] to identify the kernel configuration options related to triggering the vulnerability.

    Please output the result in the following JSON format exactly without any extra characters:
    {{
    "CVE_ID": "{CVE_ID}",
    "CONFIGURATIONS": [
        {{
        "config": "CONFIG_XXX",
        "reason": "Why this configuration is related to the vulnerability.What content did this configuration item originate from based on what I provided?"
        }},
        {{
        "config": "CONFIG_YYY",
        "reason": "Why this configuration is related to the vulnerability.What content did this configuration item originate from based on what I provided?"
        }}
    ]
    }}

    ----------------------------------------
    CVE description
    {CVE_description}
    ----------------------------------------
    CWE description
    {CWE_description}
    ----------------------------------------
    Semantic summary
    {semantic_summary}
    ----------------------------------------
    Evidence summary
    {evidence_summary}
    ----------------------------------------
    Makefile content
    {makefile_content}
    """
        return prompt

    def analyze_vulnerability_content(self, content: str, content_type: str, CVE_ID: str,  max_chars: int = 15000):
        """Analyze whether the content is related to building a vulnerability reproduction environment and triggering vulnerabilities, and determine its relevance to semantic clues or evidence-side clues.
        
        Parameters:
        content: str - The content to be analyzed (reference link or PoC code)
        content_type: str - The type of content ("reference" or "poc")
        
        Returns:
        dict - A dictionary containing relevance and relationships with semantic/evidence clues
        """
        
        total_tokens = 0
        encoding = tiktoken.get_encoding("cl100k_base")
        
        content_chunks = self.split_text(content, max_chars)
        
        merged_result = {
            "relevancy": "No",
            "related_to_semantic": "No",
            "related_to_evidence": "No"
        }
        try:
            for i, chunk in enumerate(content_chunks):
                prompt = f"""
    You are a cybersecurity researcher specializing in Linux kernel vulnerability analysis. 
    Analyze the following {content_type} content to determine its relevance to vulnerability reproduction and exploitation, and on this basis, determine its relevance to the following two types of clues:
        - related_to_semantic: Is this content related to semantic clues (vulnerability triggering mechanism, involved components, triggering conditions)? [Yes/No]
        - related_to_evidence: Is this content related to evidence clues (concrete code, affected files/directories, module names, function names, key macros/constants)? [Yes/No]
    
    ----------------------------------------
    CVE ID: 
    {CVE_ID}
    Content: 
    {chunk}
    ----------------------------------------
    
    Please return the result in the following JSON format exactly:
    {{
    "relevancy": "Yes/No",
    "related_to_semantic": "Yes/No",
    "related_to_evidence": "Yes/No"
    }}
    """

                print(f"  Call LLM to analyze {content_type} content relevance...")
                
                try:
                    llm_response, tokens = self.call_llm_api(prompt)
                    total_tokens += tokens
                except Exception as e:
                    print(f"[ERROR] call_llm_api failed: {type(e).__name__}: {str(e)}")
                    import traceback
                    print(f"[DEBUG] Error traceback:\n{traceback.format_exc()}")
                    print(f"[DEBUG] Skip this block, continue to next next block...")
                    continue
                import json
                try:
                    response_content = llm_response
                    
                    if not response_content.startswith('{') :
                        start_index = response_content.index('{')
                        end_index = response_content.rindex('}')
                        response_content = response_content[start_index:end_index+1]
                    result = json.loads(response_content)
                except json.JSONDecodeError:
                    import re
                    json_pattern = r'\{.*?\}'
                    matches = re.findall(json_pattern, response_content, re.DOTALL)
                    if matches:
                        try:
                            res=matches[-1]
                            if not res.startswith('{') :
                                start_index = res.index('{')
                                end_index = res.rindex('}')
                                res = res[start_index:end_index+1]
                            result = json.loads(res)
                        except json.JSONDecodeError:
                            print(f"  -> [ERROR] Failed to parse LLM response as JSON")
                            return None, total_tokens
                    else:
                        print(f"  -> [ERROR] No JSON found in LLM response")
                        return None, total_tokens
                    
                if result.get('relevancy') == 'Yes':
                    merged_result['relevancy'] = 'Yes'
                if result.get('related_to_semantic') == 'Yes':
                    merged_result['related_to_semantic'] = 'Yes'
                if result.get('related_to_evidence') == 'Yes':
                    merged_result['related_to_evidence'] = 'Yes'
                
                time.sleep(random.uniform(1, 3))
            
            if merged_result.get('relevancy') == 'Yes':
                print(f"  -> [USEFUL] Content is relevant to vulnerability reproduction.")
                print(f"  -> Related to semantic: {merged_result.get('related_to_semantic')}, Related to evidence: {merged_result.get('related_to_evidence')}")
                return merged_result, total_tokens
            else:
                print(f"  -> [SKIP] Content is not relevant for vulnerability reproduction.")
                return None, total_tokens
            
        except SSLError as e:
            print(f"  -> [ERROR] SSL error occurred: {e}")
            return None, total_tokens
        except Timeout as e:
            print(f"  -> [ERROR] Timeout occurred: {e}")
            return None, total_tokens
        except HTTPError as e:
            print(f"  -> [ERROR] HTTP error occurred: {e}")
            return None, total_tokens
        except ConnectionError as e:
            print(f"  -> [ERROR] Connection error occurred: {e}")
            return None, total_tokens
        except RequestException as e:
            print(f"  -> [ERROR] Request error occurred: {e}")
            return None, total_tokens
        except Exception as e:
            print(f"  -> [ERROR] Unexpected error occurred: {e}")
            return None, total_tokens

    def split_text(self, text: str, max_chars: int = 15000):
        """Split text into chunks of specified length
        
        Parameters:
        text: str - The text to be split
        max_chars: int - Maximum number of characters per chunk
        
        Returns:
        list - List of split text chunks
        """
        if len(text) <= max_chars:
            return [text]
        
        chunks = []
        current_chunk = ""
        
        paragraphs = text.split('\n\n')
        
        for para in paragraphs:
            if len(current_chunk) + len(para) + 2 <= max_chars:
                current_chunk += para + '\n\n'
            else:
                if current_chunk:
                    chunks.append(current_chunk.strip())
                current_chunk = para + '\n\n'
        
        if current_chunk:
            chunks.append(current_chunk.strip())
        
        return chunks

    def generate_summary(self, content_chunks: list, summary_type: str, CVE_ID: str):
        """Generate content summary
        
        Parameters:
        content_chunks: list - List of content chunks
        summary_type: str - Summary type ("semantic" or "evidence")
        CVE_ID: str - CVE ID for providing context information
        
        Returns:
        str - Generated summary
        """
        if summary_type == "semantic":
            type_desc = "semantic clues (vulnerability triggering mechanism, involved components, triggering conditions)"
        else:
            type_desc = "evidence clues (concrete code, affected files/directories, module names, function names, key macros/constants)"
        
        chunk_summaries = []
        for i, chunk in enumerate(content_chunks):
            print(f"  -> [Stage1 SUMMARY] Generating summary {i+1}/{len(content_chunks)} {summary_type} summary...")
            
            prompt = f"""
    You are a cybersecurity researcher specializing in Linux kernel vulnerability analysis.
    Please summarize the following content, focusing on {type_desc}.

    CVE ID: {CVE_ID}

    Content: {chunk}

    Output a concise summary that captures all key information about {type_desc}.
    """
            
            response , tokens = self.call_llm_api(prompt)
            if response:
                chunk_summaries.append(response.strip())
        
        if len(chunk_summaries) == 1:
            return chunk_summaries[0],tokens
        
        print(f"  -> [Stage1 SUMMARY] Merging {len(chunk_summaries)} {summary_type} summaries...")
        summary_text = "\n\n".join(chunk_summaries)

        combined_prompt = f"""
    You are a cybersecurity researcher specializing in Linux kernel vulnerability analysis.
    Please merge the following summaries into a single, coherent summary that captures all key information about {type_desc}.

    CVE ID: {CVE_ID}

    Summaries:
    {summary_text}

    Output a concise, unified summary that includes all important details.
    """
        
        final_summary, tokens = self.call_llm_api(combined_prompt)
        if final_summary:
            final_summary = final_summary.strip()
        else:
            final_summary = "NONE"
        return final_summary,tokens

    
    def call_llm_api(self, prompt: str, max_retries=3):
        """
        Call LLM API
        """
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        data = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a professional Linux kernel configuration analyst, strictly follow the output requirements."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.0,
            "max_tokens": 25000,
            "stream": False
        }
        
        retry_count = 0
        while retry_count < max_retries:
            try:
                response = requests.post(
                    url=self.base_url,
                    headers=headers,
                    data=json.dumps(data),
                    timeout=300,
                    verify=False
                )
                response_json = response.json()
                
                content = response_json["choices"][0]["message"]["content"].strip()
                tokens = response_json["usage"]["total_tokens"]
                
                return content, tokens

            except requests.exceptions.RequestException as e:
                retry_count += 1
                if retry_count < max_retries:
                    print(f"  -> [Stage1] HTTP request failed (attempt {retry_count+1}/{max_retries}), will retry in 3 seconds...")
                    time.sleep(3)
                else:
                    print(f"  -> [Stage1] Max retries reached ({max_retries}) to call LLM API")
                    return "", 0
            except KeyError as e:
                print(f"  -> [Stage1] Response format error: missing field {e}")
                return "", 0
            except Exception as e:
                retry_count += 1
                if retry_count < max_retries:
                    print(f"  -> [Stage1] LLM API call failed (attempt {retry_count+1}/{max_retries}), will retry in 3 seconds...")
                    time.sleep(3)
                else:
                    print(f"  -> [Stage1] Max retries reached ({max_retries}) to call LLM API")
                    return "", 0

    def extract_content_between_markers(self, content, start_marker='a/', end_marker='b/'):
        results = []
        start = 0
        while True:
            start_pos = content.find(start_marker, start)
            if start_pos == -1:
                break
            end_pos = content.find(end_marker, start_pos + len(start_marker))
            if end_pos == -1:
                break
            extracted = content[start_pos + len(start_marker) : end_pos]
            extracted = extracted.strip()
            
            if extracted:
                results.append(extracted)
            
            start = end_pos + len(end_marker)
        
        return results
    def get_makefile_content(self, makefile_path, CVE_ID, version):
        makefile_content = ""
        makefile_file = list(set([os.path.basename(path).split(".")[0] for path in makefile_path]))
        makefile_path = list(set([os.path.dirname(path) + "/Makefile" for path in makefile_path]))
        
        for file_path in makefile_path:
            if not os.path.exists(file_path):
                continue
            with open(os.path.join(f"./{CVE_ID}-linux-{version}", file_path), 'r', encoding='utf-8') as f:
                content = f.read()
                for file in makefile_file:
                    if file in content:
                        lines = content.split('\n')
                        start_line = -1
                        end_line = -1
                        for i, line in enumerate(lines):
                            if file in line:
                                start_line = i
                                break
                        if start_line != -1:
                            for i in range(start_line, -1, -1):
                                if 'objs' in lines[i]:
                                    end_line = i
                                    break
                        if end_line != -1 and start_line != -1:
                            extracted_lines = lines[end_line:start_line + 1]
                            extracted_content = '\n'.join(extracted_lines)
                            makefile_content += extracted_content + "\n"
                
    def prompt_normalization(self, CVE_ID, version=None, PoC_FILES=None, data_dir='cve_data'):
        """
        Read CVE information from local files, analyze relevance, integrate content to generate summaries, and finally generate configuration items
        """
        global test_dict
        start_time = time.time()
        total_tokens = 0
        total_summary_tokens = 0
        cve_data_dir = os.path.join(data_dir, CVE_ID)
        cve_info_file = os.path.join(cve_data_dir, 'cve_info.json')
        refs_dir = os.path.join(cve_data_dir, 'references')
        if not os.path.exists(cve_info_file):
            print(f"CVE data file does not exist, start to crawl: {CVE_ID}")
            Stage1_craw = Crawler()
            Stage1_craw.craw(CVE_ID)
            
        with open(cve_info_file, 'r', encoding='utf-8') as f:
            cve_info = json.load(f)
        
        semantic_related_content = []
        evidence_related_content = []
        
        makefile_path = []
        for ref in cve_info['references']:
            filepath = ref['filepath']
            filepath = filepath.replace('\\', '/')
            if not os.path.exists(filepath):
                continue
            with open(filepath, 'r', encoding='utf-8') as f:
                ref_content = f.read()

                if "commit" in filepath:
                    makefile_path.extend(self.extract_content_between_markers(ref_content))

                analysis_result , total_tokens_ref = self.analyze_vulnerability_content(ref_content, "reference", CVE_ID)
                total_tokens += total_tokens_ref
                
                if analysis_result:
                    if analysis_result.get('related_to_semantic') == 'Yes':
                        semantic_related_content.append(f"Reference: {ref['url']}\n\n{ref_content}")
                    if analysis_result.get('related_to_evidence') == 'Yes':
                        evidence_related_content.append(f"Reference: {ref['url']}\n\n{ref_content}")   
        for PoC_FILE in PoC_FILES:
            poc_path = os.path.join(data_dir, CVE_ID, "PoC", PoC_FILE)
            poc_path = poc_path.replace('\\', '/')
            if not os.path.exists(poc_path):
                continue
            with open(poc_path, 'r', encoding='utf-8') as f:
                poc_content = f.read()
                analysis_result , total_tokens_poc = self.analyze_vulnerability_content(poc_content, "poc", CVE_ID)
                total_tokens += total_tokens_poc
                
                if analysis_result:
                    if analysis_result.get('related_to_semantic') == 'Yes':
                        semantic_related_content.append(f"PoC File: {PoC_FILE}\n\n{poc_content}")
                    if analysis_result.get('related_to_evidence') == 'Yes':
                        evidence_related_content.append(f"PoC File: {PoC_FILE}\n\n{poc_content}")

        
        CVE_description = cve_info['description']
        CWE_description = ""
        if cve_info['cwe_list']:
            for cwe in cve_info['cwe_list']:
                CWE_description += f"\n{cwe['cwe_id']}: {cwe['name']}\n{cwe['description']}\n"
        
        semantic_summary = "NONE"
        if semantic_related_content:
            print(f"Generate semantic summary...")
            semantic_combined = "\n\n".join(semantic_related_content)
            semantic_chunks = self.split_text(semantic_combined)
            semantic_summary , total_tokens_semantic = self.generate_summary(semantic_chunks, "semantic", CVE_ID)
            total_summary_tokens += total_tokens_semantic
        
        evidence_summary = "NONE"
        if evidence_related_content:
            print(f"Generate evidence summary...")
            evidence_combined = "\n\n".join(evidence_related_content)
            evidence_chunks = self.split_text(evidence_combined)
            evidence_summary , total_tokens_evidence = self.generate_summary(evidence_chunks, "evidence", CVE_ID)
            total_summary_tokens += total_tokens_evidence

        end_time = time.time()
        print(f"Generate feature time cost: {end_time - start_time} seconds")
        print(f"Total analysis tokens: {total_tokens}")
        print(f"Total summary tokens: {total_summary_tokens}")

        test_dict[CVE_ID]["craw_analysis_tokens"] = total_tokens
        test_dict[CVE_ID]["gene_summary_tokens"] = total_summary_tokens
        test_dict[CVE_ID]["feature_time"] = end_time - start_time
        
        data = {
            'CVE_ID': [CVE_ID],
            'VERSION': [''],
            'exp_name': [''],
            'kernel_dir': [''],
            'CVE_description': [CVE_description],
            'CWE_description': [CWE_description],
            'semantic_summary': [semantic_summary],
            'evidence_summary': [evidence_summary],
        }
        df = pd.DataFrame(data)
        
        excel_file = "Stage1_CVE_IDENTIFY.xlsx"
        if os.path.exists(excel_file):
            existing_df = pd.read_excel(excel_file)
            df = pd.concat([existing_df, df], ignore_index=True)
        
        with pd.ExcelWriter(excel_file, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Sheet1')

        status = download_source_code(cve=CVE_ID,version=version,source_code_url=self.source_code_url)
        if not status:
            print(f"[Stage1] Failed to download source code: {CVE_ID}")

        makefile_content = self.get_makefile_content(makefile_path, CVE_ID, version)
        
        start_time = time.time()
        prompt = self.prompt_build(
            CVE_ID,
            CWE_description,
            CVE_description,
            semantic_summary,
            evidence_summary,
            makefile_content
        )
        print(f"[Stage1] Call LLM API to generate configuration...")
        response , tokens = self.call_llm_api(prompt)
        num_tokens = tokens
        print(f"[Stage1] Total configuration tokens cost: {num_tokens}")
        end_time = time.time()
        print(f"[Stage1] Total configuration time cost: {end_time - start_time} seconds")
        test_dict[CVE_ID]["config_tokens"] = num_tokens
        test_dict[CVE_ID]["config_time"] = end_time - start_time
        if self.clear:
            delete_source_code(cve=CVE_ID,version=version)
        if response:
            try:
                if not response.startswith('{') :
                    start_index = response.index('{')
                    end_index = response.rindex('}')
                    response = response[start_index:end_index+1]
                
                config_data = json.loads(response)
                configs = config_data.get('CONFIGURATIONS', [])
                
                config_list = []
                reason_list = []
                for config_item in configs:
                    config_list.append(config_item['config'])
                    reason_list.append(config_item['reason'])
                
                data = {
                    'cve': [CVE_ID],
                    'version': [''],
                    'kernel_dir': [''],
                    'configs': [', '.join(config_list)],
                    'reasons': [', '.join(reason_list)],
                    'exp_name': ['']
                }
                df = pd.DataFrame(data)
                
                excel_file = "Stage1_CVE_IDENTIFY_CONFIG.xlsx"
                if os.path.exists(excel_file):
                    existing_df = pd.read_excel(excel_file)
                    df = pd.concat([existing_df, df], ignore_index=True)
                
                with pd.ExcelWriter(excel_file, engine='openpyxl') as writer:
                    df.to_excel(writer, index=False, sheet_name='Sheet1')
                
                print(f"Excel file saved as: {excel_file}")
                print(f"Generated configurations: {', '.join(config_list)}")
                
            except json.JSONDecodeError:
                print(f"  -> [ERROR] Failed to parse LLM response as JSON")
                print(f"  -> Original response content: {response}")
        
        return response
class Crawler:
    def __init__(self, save_dir='cve_data', nvdlib_api_key=''):
        self.save_dir=save_dir
        self.nvdlib_api_key = nvdlib_api_key
    def get_CVE_description(self, CVE):
        
        vuln_descriptions  = CVE.descriptions
        description = ""
        if vuln_descriptions != 'None':
            for item in vuln_descriptions:
                if item.lang == 'en':
                    description = item.value
                    break
        return description

    def get_cwe_details(self, cwe_id):
        """get details of CWE"""
        cwe_id = cwe_id.replace("CWE-", "")
        url = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
        try:
            response = requests.get(url)
            response.raise_for_status()
        except Exception as e:
            print(f"Failed to fetch {cwe_id} details: {e}")
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

    def get_CWE_description(self, cve_id):
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }
        """get CWE description"""
        url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        print(f"Crawling CWE description for {cve_id}...")
        time.sleep(1)
        try:
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()
        except Exception as e:
            print(f"Failed to fetch CWE description of {cve_id}: {e}")
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
                        print(f"CWE line structure is abnormal for {cve_id}, skipping this line")
                        continue
                    
                    a_tag = tds[0].find('a')
                    if not a_tag:
                        print(f"No link found in the CWE line for {cve_id}, skipping this line")
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
                    print(f"Error processing CWE information for {cve_id}: {e}, skipping this line")
                    continue

        for item in cwe_list:
            print(f"{item['cwe_id']}: {item['name']}")
            details = self.get_cwe_details(item['cwe_id'])
            if details:
                item['description'] = details['description']
                print(item['description'])
        return cwe_list

    def get_nvd_references(self, CVE) -> List[str]:
        
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
        
    def get_CVE_detail(self, CVE_ID, max_retries=3):
        """get CVE detail"""
        retries = 0
        while retries < max_retries:
            try:
                print(f"  -> [Stage1] Trying to get CVE detail for CVE {CVE_ID}... (attempt {retries+1}/{max_retries})...")
                r = nvdlib.searchCVE(cveId=CVE_ID, key=self.nvdlib_api_key, delay=1) 
                if r:
                    return r[0]
                else:
                    print(f"  -> [Stage1] No CVE detail for CVE {CVE_ID}")
                    return None
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 503:
                    print(f"  -> [Stage1] NVD API service is not available (503), retry {retries+1} seconds later...")
                    time.sleep(retries+1)
                    retries += 1
                else:
                    print(f"  -> [Stage1] HTTP error: {e}")
                    return None
            except Exception as e:
                print(f"  -> [Stage1] Error: {e}")
                return None
        print(f"  -> [Stage1] Max retries reached ({max_retries}) to get CVE detail")
        return None
    
    def craw(self, CVE_ID):
        """
        Crawl CVE reference links and vulnerability descriptions, and save this information to files
        
        Parameters:
        CVE_ID: str - CVE identifier, e.g., "CVE-2021-26708"
        save_dir: str - Directory for saving data
        
        Returns:
        dict - Dictionary containing CVE information and reference links
        """
        
        cve_save_dir = os.path.join(self.save_dir, CVE_ID)
        refs_save_dir = os.path.join(cve_save_dir, 'references')
        os.makedirs(refs_save_dir, exist_ok=True)
        
        print(f"Starting to crawl CVE: {CVE_ID}")
        
        cve = self.get_CVE_detail(CVE_ID)
        if not cve:
            print(f"Failed to fetch CVE detail: {CVE_ID}")
            return None
        
        cve_description = self.get_CVE_description(cve)
        
        cwe_list = self.get_CWE_description(CVE_ID)
        
        references = self.get_nvd_references(cve)
        
        saved_refs = []
        for url in references:
            print(f"  Crawl reference links: {url}")
            
            filename = re.sub(r'^https?://', '', url)
            filename = re.sub(r'[\\/:*?"<>|]', '_', filename)
            filename = filename[:255]
            filepath = os.path.join(refs_save_dir, f"{filename}.txt")
            
            if os.path.exists(filepath):
                print(f"  -> File already exists, skip: {filepath}")
                saved_refs.append({
                    'url': url,
                    'filepath': filepath
                })
                continue
            
            try:
                loader = WebBaseLoader(url,  requests_kwargs={"timeout": 30})
                documents = loader.load()
                page_content = documents[0].page_content
                
                if not page_content:
                    print(f"  -> Content is empty, skip: {url}")
                    continue
                
                with open(filepath, 'w+', encoding='utf-8') as f:
                    f.write(f"{url}\n")
                    f.write(page_content)
                
                print(f"  -> Save success: {filepath}")
                saved_refs.append({
                    'url': url,
                    'filepath': filepath
                })
                
                time.sleep(random.uniform(1, 3))
                
            except SSLError as e:
                print(f"  -> [ERROR] SSL error: {e}")
                continue
            except Timeout as e:
                print(f"  -> [ERROR] Timeout: {e}")
                continue
            except HTTPError as e:
                print(f"  -> [ERROR] HTTP error: {e}")
                continue
            except ConnectionError as e:
                print(f"  -> [ERROR] Connection error: {e}")
                continue
            except RequestException as e:
                print(f"  -> [ERROR] Request error: {e}")
                continue
            except Exception as e:
                print(f"  -> [ERROR] Unknown error: {e}")
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
        
        print(f"\nCVE data saved to: {cve_save_dir}")
        print(f"  - CVE info: {json_filepath}")
        print(f"  - References: {refs_save_dir}")
        
        return cve_info

    
def Stage1_main(cve_list=[],version=None,api_key=None,base_url=None,model=None,source_code_url=None,nvdlib_api_key=None,craw=False):
    global test_dict
    test_dict={}
    if craw:
        for cve in cve_list:
            start_time = time.time()
            Stage1_craw = Crawler(nvdlib_api_key=nvdlib_api_key)
            Stage1_craw.craw(cve)
            end_time = time.time()
            print(f"[Craw] Processing CVE_ID: {cve} took {end_time - start_time} seconds")

    data_dir='cve_data'
    for cve in cve_list:
        test_dict[cve]={}
        print(f"[Stage 1] process CVE_ID: {cve}")
        poc_dir = os.path.join(data_dir, cve, "PoC")
        poc_files = os.listdir(poc_dir)
        print("-"*50)
        Stage1=Configuration_Identification(api_key=api_key,base_url=base_url,model=model,source_code_url=source_code_url)
        Stage1.prompt_normalization(CVE_ID=cve, version=version, PoC_FILES=poc_files, data_dir=data_dir)
        print("-"*50)

    df = pd.DataFrame(test_dict).T
    if os.path.exists('Stage1_token_time.xlsx'):
        try:
            existing_df = pd.read_excel('Stage1_token_time.xlsx', index_col=0)  
            df = pd.concat([existing_df, df], axis=0)
            df = df[~df.index.duplicated(keep='last')]
        except Exception as e:
            print(f"[Stage 1] Merging existing file failed: {e}")
    if not df.empty:
        with pd.ExcelWriter('Stage1_token_time.xlsx', engine='openpyxl') as writer:
            df.to_excel(writer, index=True)