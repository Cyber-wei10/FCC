import re
import os
from typing import List, Tuple, Optional, Dict

def split_kconfig_into_blocks(kconfig_content: str, file_path: Optional[str] = None) -> List[dict]:

    lines = [line.rstrip('\n') for line in kconfig_content.split('\n')]
    blocks = []
    current_block = None
    block_type = None
    start_line = 0

    config_pattern = re.compile(r'^(config|menuconfig)\s+([A-Z0-9_]+)')
    if_pattern = re.compile(r'^if\s+([A-Z0-9_]+)')
    endif_pattern = re.compile(r'^endif')
    comment_pattern = re.compile(r'^comment')
    source_pattern = re.compile(r'^source\s+"([^"]+)"')

    for idx, line in enumerate(lines):
        line_stripped = line.strip()
        if not line_stripped:
            continue

        if config_pattern.match(line_stripped):
            if current_block:
                blocks.append({
                    'type': block_type,
                    'content': '\n'.join(current_block),
                    'start': start_line,
                    'end': idx-1,
                    'file_path': file_path
                })
            if line_stripped.startswith('menuconfig'):
                block_type = 'menuconfig'
            else:
                block_type = 'config'
            current_block = [line]
            start_line = idx
        elif if_pattern.match(line_stripped):
            if current_block:
                blocks.append({
                    'type': block_type,
                    'content': '\n'.join(current_block),
                    'start': start_line,
                    'end': idx-1,
                    'file_path': file_path
                })
            block_type = 'if'
            current_block = [line]
            start_line = idx
        elif endif_pattern.match(line_stripped):
            if current_block:
                blocks.append({
                    'type': block_type,
                    'content': '\n'.join(current_block),
                    'start': start_line,
                    'end': idx-1,
                    'file_path': file_path
                })
            block_type = 'endif'
            current_block = [line]
            start_line = idx
        elif comment_pattern.match(line_stripped):
            if current_block:
                blocks.append({
                    'type': block_type,
                    'content': '\n'.join(current_block),
                    'start': start_line,
                    'end': idx-1,
                    'file_path': file_path
                })
            block_type = 'comment'
            current_block = [line]
            start_line = idx
        elif source_pattern.match(line_stripped):
            if current_block:
                blocks.append({
                    'type': block_type,
                    'content': '\n'.join(current_block),
                    'start': start_line,
                    'end': idx-1,
                    'file_path': file_path
                })
            block_type = 'source'
            current_block = [line]
            start_line = idx
        else:
            if current_block is None:
                current_block = [line]
                start_line = idx
                block_type = 'other'
            else:
                current_block.append(line)

    if current_block:
        block_data = {
            'type': block_type,
            'content': '\n'.join(current_block),
            'start': start_line,
            'end': len(lines)-1
        }
        if file_path:
            block_data['file_path'] = file_path
        blocks.append(block_data)

    return blocks

def find_target_config_blocks(target_config: str, blocks: List[dict]) -> List[dict]:

    target_config_block = None
    for block in blocks:
        if block['type'] in ['config', 'menuconfig']:
            config_match = re.search(r'^(config|menuconfig)\s+([A-Z0-9_]+)', block['content'], re.MULTILINE)
            if config_match and config_match.group(2) == target_config:
                target_config_block = block
                break
    
    if_stack = []
    all_if_blocks = []
    
    for block in blocks:
        if block['type'] == 'if':
            if_match = re.search(r'^if\s+([A-Z0-9_]+)', block['content'], re.MULTILINE)
            if if_match:
                if_info = {
                    'name': if_match.group(1),
                    'start': block['start'],
                    'end': None,
                    'if_block': block,
                    'endif_block': None
                }
                if_stack.append(if_info)
                all_if_blocks.append(if_info)
        elif block['type'] == 'endif':
            if if_stack:
                last_if = if_stack[-1]
                last_if['end'] = block['start']
                last_if['endif_block'] = block
                if_stack.pop()
    
    related_blocks = []
    unique_containing_ifs = []
    
    if target_config_block:
        target_start = target_config_block['start']
        target_end = target_config_block['end']
        related_blocks = [target_config_block]
        
        containing_ifs = []
        for if_info in all_if_blocks:
            if if_info['end'] and (if_info['start'] < target_start) and (if_info['end'] > target_end):
                containing_ifs.append(if_info)
        
        def find_outer_if(if_info, all_if_infos):
            outer_ifs = []
            for info in all_if_infos:
                if info['end'] and (info['start'] < if_info['start']) and (info['end'] > if_info['end']):
                    outer_ifs.append(info)
                    outer_ifs.extend(find_outer_if(info, all_if_infos))
            return outer_ifs
        
        all_containing_ifs = []
        for if_info in containing_ifs:
            all_containing_ifs.append(if_info)
            all_containing_ifs.extend(find_outer_if(if_info, all_if_blocks))
        
        seen_if_starts = set()
        for if_info in sorted(all_containing_ifs, key=lambda x: x['start']):
            if if_info['start'] not in seen_if_starts:
                seen_if_starts.add(if_info['start'])
                unique_containing_ifs.append(if_info)
        
        for if_info in unique_containing_ifs:
            related_blocks.append(if_info['if_block'])
            if if_info['endif_block']:
                related_blocks.append(if_info['endif_block'])
        
        target_content = target_config_block['content']
        select_matches = re.findall(r'select\s+([A-Z0-9_]+)\b', target_content, re.IGNORECASE)
        for select_target in select_matches:
            for block in blocks:
                if block['type'] in ['config', 'menuconfig']:
                    config_match = re.search(r'^(config|menuconfig)\s+([A-Z0-9_]+)', block['content'], re.MULTILINE)
                    if config_match and config_match.group(2) == select_target and block not in related_blocks:
                        related_blocks.append(block)
    
    target_if_range = (0, max([x['end'] for x in blocks]))
    if unique_containing_ifs:
        innermost_if = sorted(unique_containing_ifs, key=lambda x: x['start'], reverse=True)[0]
        target_if_range = (innermost_if['start'], innermost_if['end'])
    
    select_blocks = []
    for block in blocks:
        if block['type'] == 'config' and block not in related_blocks:
            if (block['start'] > target_if_range[0]) and (block['end'] < target_if_range[1]):
                block_content = block['content']
                if re.search(r'select\s+' + re.escape(target_config) + r'\b', block_content, re.IGNORECASE):
                    select_blocks.append(block)
                elif re.search(r'depends on\s+.+' + re.escape(target_config) + r'\b', block_content, re.IGNORECASE):
                    continue
    
    for select_block in select_blocks:
        related_blocks.append(select_block)
        
        select_start = select_block['start']
        select_end = select_block['end']
        select_containing_ifs = []
        
        for if_info in all_if_blocks:
            if if_info['end'] and (if_info['start'] < select_start) and (if_info['end'] > select_end):
                select_containing_ifs.append(if_info)
        
        def find_outer_if(if_info, all_if_infos):
            outer_ifs = []
            for info in all_if_infos:
                if info['end'] and (info['start'] < if_info['start']) and (info['end'] > if_info['end']):
                    outer_ifs.append(info)
                    outer_ifs.extend(find_outer_if(info, all_if_infos))
            return outer_ifs
        
        all_select_containing_ifs = []
        for if_info in select_containing_ifs:
            all_select_containing_ifs.append(if_info)
            all_select_containing_ifs.extend(find_outer_if(if_info, all_if_blocks))
        
        seen_if_starts = set()
        for if_info in sorted(all_select_containing_ifs, key=lambda x: x['start']):
            if if_info['start'] not in seen_if_starts:
                seen_if_starts.add(if_info['start'])
                if if_info['if_block'] not in related_blocks:
                    related_blocks.append(if_info['if_block'])
                if if_info['endif_block'] and if_info['endif_block'] not in related_blocks:
                    related_blocks.append(if_info['endif_block'])
    
    related_blocks_sorted = sorted(related_blocks, key=lambda x: x['start'])
    return related_blocks_sorted

def extract_precise_kconfig_snippet(kconfig_path: str, target_config_full: str) -> Optional[str]:

    try:
        target_config = target_config_full.replace('CONFIG_', '')
        with open(kconfig_path, 'r', encoding='utf-8', errors='ignore') as f:
            kconfig_content = f.read()
        
        kernel_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../..'))
        rel_path = os.path.relpath(kconfig_path, kernel_root).replace("\\", "/")
        blocks = split_kconfig_into_blocks(kconfig_content, file_path=rel_path)
        related_blocks = find_target_config_blocks(target_config, blocks)
        if not related_blocks:
            return None

        snippet_lines = []
        for block in related_blocks:
            block_lines = block['content'].split('\n')
            for line in block_lines:
                stripped = line.strip()
                if stripped.startswith('#'):
                    continue
                if stripped or (snippet_lines and snippet_lines[-1].strip()):
                    snippet_lines.append(line)

        snippet = '\n'.join(snippet_lines).strip()
        return snippet
    except Exception as e:
        print(f"[Error] Failed to extract Kconfig snippet {kconfig_path}: {str(e)}")
        return None

def grep_kconfig_files(kernel_root: str, target_config_full: str) -> List[str]:

    target_config = target_config_full.replace('CONFIG_', '')
    match_pattern = re.compile(r'\b' + re.escape(target_config) + r'\s', re.IGNORECASE)
    kconfig_files = []

    for root, dirs, files in os.walk(kernel_root):
        for file in files:
            if file == 'Kconfig' or file.startswith('Kconfig.'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read().replace('CONFIG_', '')
                        if match_pattern.search(content):
                            kconfig_files.append(file_path)
                except Exception as e:
                    print(f"[Warning] Failed to read Kconfig file {file_path}: {str(e)}")
                    continue

    return kconfig_files
def is_config_enabled(config_name: str, kernel_root: str) -> bool:

    config_files = [os.path.join(kernel_root, '.config')]
    
    for config_file in config_files:
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    pattern = r'^CONFIG_' + re.escape(config_name) + r'=[^n]$'
                    if re.search(pattern, content, re.MULTILINE):
                        return True
            except Exception as e:
                print(f"[Warning] Failed to read config file {config_file}: {str(e)}")
                continue
    
    return False

def find_source_references(kernel_root: str, kconfig_path: str) -> List[dict]:

    source_blocks = []
    current_kconfig_path = os.path.normpath(kconfig_path)
    
    search_kconfig_path = current_kconfig_path
    current_rel_path = os.path.relpath(current_kconfig_path, kernel_root).replace("\\", "/")
    visited_dirs = set()
    while True:
        current_dir = os.path.dirname(current_rel_path)
        parent_dir = os.path.dirname(current_dir)
        
        if not parent_dir or parent_dir == current_dir or parent_dir in visited_dirs:
            break
        visited_dirs.add(parent_dir)
        parent_kconfig_rel = os.path.join(parent_dir, 'Kconfig')
        parent_kconfig_path = os.path.normpath(os.path.join(kernel_root, parent_kconfig_rel))
        
        if not os.path.exists(parent_kconfig_path):
            current_rel_path = parent_kconfig_rel
            current_kconfig_path = parent_kconfig_path
            continue
        
        try:
            with open(parent_kconfig_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            rel_parent_path = os.path.relpath(parent_kconfig_path, kernel_root).replace("\\", "/")
            blocks = split_kconfig_into_blocks(content, file_path=rel_parent_path)
            
            if_stack = []
            all_if_blocks = []
            
            for block in blocks:
                if block['type'] == 'if':
                    if_match = re.search(r'^if\s+([A-Z0-9_]+)', block['content'], re.MULTILINE)
                    if if_match:
                        if_info = {
                            'name': if_match.group(1),
                            'start': block['start'],
                            'end': None,
                            'if_block': block,
                            'endif_block': None,
                            'file_path': block['file_path']
                        }
                        if_stack.append(if_info)
                        all_if_blocks.append(if_info)
                elif block['type'] == 'endif':
                    if if_stack:
                        last_if = if_stack[-1]
                        last_if['end'] = block['start']
                        last_if['endif_block'] = block
                        if_stack.pop()
            
            for block in blocks:
                if block['type'] == 'source':
                    source_match = re.search(r'^source\s+"([^"]+)"', block['content'], re.MULTILINE)
                    if source_match:
                        source_path = source_match.group(1)
                        source_abs_path = os.path.normpath(os.path.join(kernel_root, source_path))
                        
                        if source_abs_path == search_kconfig_path:
                            containing_ifs = []
                            for if_info in all_if_blocks:
                                if if_info['start'] < block['start'] and if_info['end'] > block['start']:
                                    containing_ifs.append(if_info)
                            
                            context_blocks = []
                            
                            for if_info in containing_ifs:
                                context_blocks.append(if_info['if_block'])
                            
                            context_blocks.append(block)
                            
                            for if_info in containing_ifs:
                                if if_info['endif_block']:
                                    context_blocks.append(if_info['endif_block'])
                            
                            source_blocks.extend(context_blocks)
                            
                            condition_enabled = False
                            if containing_ifs:
                                last_if = containing_ifs[-1]
                                if is_config_enabled(last_if['name'], kernel_root):
                                    condition_enabled = True
                                    break
                            else:
                                condition_enabled = True
                                break
            
            if not source_blocks:
                current_rel_path = parent_kconfig_rel
                current_kconfig_path = parent_kconfig_path
                continue
                
            if source_blocks and not condition_enabled:
                current_rel_path = parent_kconfig_rel
                current_kconfig_path = parent_kconfig_path
                search_kconfig_path = parent_kconfig_path
                continue
        
        except Exception as e:
            print(f"[Warning] Failed to read parent Kconfig file {parent_kconfig_path}: {str(e)}")
            current_rel_path = parent_kconfig_rel
            current_kconfig_path = parent_kconfig_path
            continue
    
    return source_blocks

def extract_precise_makefile_snippet(kernel_root: str, file_path: str, target_config_full: str) -> Optional[str]:

    try:
        rel_path = os.path.relpath(file_path, kernel_root).replace("\\", "/")
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [line.rstrip('\n') for line in f.readlines()]

        config_core = target_config_full.replace("CONFIG_", "").upper()
        target_config = target_config_full
        
        obj_pattern = re.compile(r"obj-\$\((CONFIG_[A-Z0-9_]+)\)\s*\+=\s*(\w+)(/|\.o)?", re.MULTILINE)
        conditional_start_pattern = re.compile(r'^(ifeq|ifneq|ifdef|ifndef)\s+', re.MULTILINE)
        conditional_end_pattern = re.compile(r'^endif', re.MULTILINE)
        
        relevant_line_nums = set()
        conditional_stack = []
        target_line_num = None
        
        for i, line in enumerate(lines):
            line_strip = line.strip()
            if not line_strip or line_strip.startswith('#'):
                continue
            
            if conditional_start_pattern.match(line_strip):
                conditional_stack.append(i)
                continue
            
            if conditional_end_pattern.match(line_strip):
                if conditional_stack:
                    conditional_stack.pop()
                continue
            
            matches = obj_pattern.findall(line)
            found_target = False
            for config, obj_base, suffix in matches:
                if config == target_config or obj_base.upper() == config_core:
                    found_target = True
                    break
            
            if found_target:
                target_line_num = i
                relevant_line_nums.add(i)
                for j in conditional_stack:
                    relevant_line_nums.add(j)
        
        if not target_line_num:
            return None
        
        conditional_stack = []
        relevant_conditional_starts = {line_num: False for line_num in relevant_line_nums if conditional_start_pattern.match(lines[line_num].strip())}
        
        for i, line in enumerate(lines):
            line_strip = line.strip()
            if not line_strip or line_strip.startswith('#'):
                continue
            
            if conditional_start_pattern.match(line_strip):
                conditional_stack.append(i)
                continue
            
            if conditional_end_pattern.match(line_strip):
                if not conditional_stack:
                    continue
                
                start_line = conditional_stack.pop()
                if start_line in relevant_conditional_starts:
                    relevant_line_nums.add(i)
        
        relevant_lines = []
        for line_num in sorted(relevant_line_nums):
            line_content = lines[line_num].rstrip('\n')
            if line_content.strip() and not line_content.strip().startswith('#'):
                relevant_lines.append(f"Line{line_num+1}: {line_content}")
        
        if not relevant_lines:
            return None
        
        snippet = f"Makefile file: {rel_path}\nRelated config lines:\n" + "\n".join(relevant_lines)
        return snippet
    except Exception as e:
        print(f"[Error] Error processing Makefile file {file_path}: {str(e)}")
        return None
def grep_makefile_files(kernel_root: str, target_config_full: str) -> List[str]:

    target_config = target_config_full.replace('CONFIG_', '')
    match_pattern = re.compile(
        r'obj-\$\((CONFIG_)?' + re.escape(target_config) + r'\)\s*\+=', 
        re.IGNORECASE
    )
    makefile_files = []

    for root, dirs, files in os.walk(kernel_root):
        for file in files:
            if file == 'Makefile':
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        if match_pattern.search(content):
                            makefile_files.append(file_path)
                except Exception as e:
                    print(f"[Warning] Failed to read Makefile file {file_path}: {str(e)}")
                    continue

    return makefile_files

def find_dependencies(kernel_root: str, target_config_full: str):

    print(f"[INFO] Finding Kconfig files for {target_config_full}...")
    kconfig_files = grep_kconfig_files(kernel_root, target_config_full)
    print(f"[INFO] Found Kconfig files: {kconfig_files}")

    kconfig_snippets = []
    all_source_blocks = []
    
    for kconfig_path in kconfig_files:
        snippet = extract_precise_kconfig_snippet(kconfig_path, target_config_full)
        if snippet:

            rel_path = os.path.relpath(kconfig_path, kernel_root)
            kconfig_snippets.append(f"\n=== From file: {rel_path} ===\n{snippet}")
            
            source_refs = find_source_references(kernel_root, kconfig_path)
            all_source_blocks.extend(source_refs)

    print(f"\n[INFO] Finding Makefile files for {target_config_full}...")
    makefile_files = grep_makefile_files(kernel_root, target_config_full)
    print(f"[INFO] Found Makefile files: {makefile_files}")

    makefile_snippets = []
    for makefile_path in makefile_files:
        snippet = extract_precise_makefile_snippet(kernel_root, makefile_path, target_config_full)
        if snippet:
            makefile_snippets.append(snippet)
    
    if all_source_blocks:
        source_blocks_by_file = {}
        for block in all_source_blocks:
            file_path = block.get('file_path', 'unknown')
            if file_path not in source_blocks_by_file:
                source_blocks_by_file[file_path] = []
            source_blocks_by_file[file_path].append(block)
        
        source_references = []
        for file_path, blocks in source_blocks_by_file.items():
            sorted_blocks = sorted(blocks, key=lambda x: x['start'])
            
            unique_blocks = []
            seen_start_lines = set()
            for block in sorted_blocks:
                if block['start'] not in seen_start_lines:
                    seen_start_lines.add(block['start'])
                    unique_blocks.append(block)
            
            all_lines = []
            for block in unique_blocks:
                content_lines = block['content'].split('\n')
                filtered_content = []
                for line in content_lines:
                    stripped_line = line.strip()
                    if stripped_line and not stripped_line.startswith('#'):
                        filtered_content.append(line)
                
                if filtered_content:
                    all_lines.append('\n'.join(filtered_content))
                    all_lines.append('')
            
            cleaned_lines = []
            last_empty = False
            for line in all_lines:
                if line.strip():
                    cleaned_lines.append(line)
                    last_empty = False
                else:
                    if not last_empty:
                        cleaned_lines.append(line)
                        last_empty = True
            
            while cleaned_lines and not cleaned_lines[-1].strip():
                cleaned_lines.pop()
            
            if cleaned_lines:
                source_references.append(f"=== From file: {file_path} ===\n" + '\n'.join(cleaned_lines))
        
        if source_references:
            kconfig_snippets.append("\n=== Source Reference Information ===\n" + "\n\n".join(source_references))
    
    try:
        from prompt_GPT import build_prompt, call_LLM_api
        
        prompt = build_prompt(
            kconfig_snippets=kconfig_snippets,
            makefile_snippets=makefile_snippets,
            target_config=target_config_full
        )
        
        print("\n[Finder] === Generated Analysis Prompt ===")
        print(prompt)
        print("\n[Finder] === Calling LLM API to Analyze Dependencies ===")
        
        dependencies=""
        dependencies_relation=""
        dependencies = call_LLM_api(prompt=prompt, target_config=target_config_full)
        
        temp=[]
        for cfg in dependencies:
            if cfg.strip().startswith("CONFIG_") and "→" in cfg.strip():
                temp.append(cfg.strip())
        dependencies_relation = "\n".join(temp)
        temp=[]
        for cfg in dependencies:
            if cfg.strip().startswith("CONFIG_") and "→" not in cfg.strip():
                temp.append(cfg.strip())
        dependencies = list(set(temp))
        
        print(f"\n[Finder] Dependency analysis result for {target_config_full}: {dependencies}")
        return dependencies, prompt, dependencies_relation
    except ImportError:
        print("[Finder] Note: prompt_GPT module not found, returning empty dependencies")
        return [], "[Finder] Note: prompt_GPT module not found, returning empty dependencies" ,""
    except Exception as e:
        print(f"[Finder] Error analyzing dependencies: {str(e)}"),""
        return [], f"[Finder] Error analyzing dependencies: {str(e)}",""

if __name__ == '__main__':
    TARGET_CONFIG = "CONFIG_XFRM_OFFLOAD"
    KERNEL_ROOT = r"./linux-4.16.18"

    dependencies, prompt, dependencies_relation = find_dependencies(KERNEL_ROOT, TARGET_CONFIG)
