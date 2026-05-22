import requests
import json
import time
def build_prompt(kconfig_snippets: list, makefile_snippets: list, target_config: str) -> str:
    """
    Build semantic analysis prompt template
    """
    target_core = target_config.replace("CONFIG_", "")
    prompt_template = """
## Task Objective
Analyze the **minimum set of configuration items** required to successfully enable the target kernel configuration `{target_config}` (starting with `CONFIG_`). The output must strictly follow the rules below and include two parts: dependency relationship analysis and the minimum configuration list.

## Core Semantic Explanations of Kconfig Configurations
1. **depends on**: Hard dependency. The current configuration item can only be enabled if **all** dependent items are satisfied.
2. **select**: Implicit selection dependency. When the current configuration item is enabled, the selected items are **automatically enabled**. This forms a reverse dependency: the selected item depends on the selecting item.
3. **source**: Imports other Kconfig files. When wrapped by a conditional block (e.g., `if CONFIG_A` ... `source "path/Kconfig"` ... `endif`), the condition acts as a gate: config items in the sourced file are only configurable when the condition is satisfied. For example, to enable `CONFIG_B` defined in `"path/Kconfig"`, you must first enable `CONFIG_A`; only then can `CONFIG_B` be enabled. Therefore, a dependency relationship exists between them.

## Strict Analysis Rules
### 1. Hard Dependency Rules (`depends on`)
- `depends on X && Y`: Keep **all** dependent items (missing either X or Y will make `{target_config}` unconfigurable).
- `depends on X || Y`: Select **only 1 most universal** dependent item (simplify to the most compatible option).
- Nested conditions (`if X` ... `if Y` ... `source` ...): The sourced items implicitly `depends on X && Y`.
### 2. Select Rule (`select`)
- `{target_config} select X`: X is automatically enabled → **do not add X to the minimum configuration list**.
- Multiple configuration items select `{target_config}`: Select **only 1 most universal** selecting item (ignore others).
- `A select B`: Reverse dependency is established → `B` depends on `A` (must be reflected in dependency relationship output).

### 3. Soft Dependency Rules (Help Text)
- If the help text of a config item you need to enable mentions that other items should or must be enabled (phrases like "must enable", "requires", "needs", "you need to enable"), or gives examples using "e.g.", "such as", "for example": Extract the referenced items and treat them as soft dependencies **only for this item**.
- For driver items with multiple example options: Select **only 1 most commonly used** item.
- For mandatory requirements ("must enable", "requires"): Include the referenced item in the dependency analysis and minimum configuration list.
- When extracting config names from help text: Match words in all-caps like `CONFIG_FOO` or `FOO` when the context implies `CONFIG_` prefix.

### 4. Ignored Items
- If any configuration item selects `{target_config}`: **Ignore `{target_config}` itself** (no manual addition needed).
- If no configuration item selects `{target_config}`: **Must retain `{target_config}` itself** (add to the minimum list manually).
- Ignore: Duplicate items, comments, empty lines, and non-`CONFIG_` prefixed lines (all excluded from output).

## Additional Constraints
- Do NOT infer or add any extra kernel configurations beyond what is logically required.
- Do NOT explain, summarize, or add notes outside the required format.
- Follow only the dependencies in the given Kconfig; do not rely on external kernel knowledge.

## Input Materials
- Kconfig file content: `{kconfig_content}`
- Makefile file content: `{makefile_content}` (Makefile does not affect Kconfig configuration logic; only used for supplementary verification of compilation dependencies)

## Mandatory Output Format Requirements
### Part 1: Dependency Relationship Analysis
Output **all configuration items and their dependencies** in a fixed line format:
`Configuration Item → Dependency: Dependent Item 1, Dependent Item 2, ...`
- If there is no direct dependency: `Configuration Item → Dependency: ` (leave blank after colon)
- Special note for `select` reverse dependency: If `A select B`, and B is the target_config being analyzed, display as CONFIG_B → Dependency: CONFIG_A. If B is NOT the target_config (i.e., B is only brought in as a side effect of select by other items), DO NOT output any dependency relationship for B, and DO NOT include B in any output.

### Part 2: Minimum Configuration Item List
1. Only return `CONFIG_` prefixed items (one per line).
2. No extra characters (no comments, notes, symbols, extra spaces or blank lines).
3. **Strict order**: Prerequisite dependencies first, dependent items later (follow enablement logic order).
4. No duplicate items (each configuration item appears only once).
5. Do not sort alphabetically (only follow logical dependency order).

## Example Reference
### Part 1 Example
CONFIG_A → Dependency: CONFIG_B

### Part 2 Example
CONFIG_A
CONFIG_B
"""
    kconfig_content = "\n".join(kconfig_snippets) if kconfig_snippets else "None"
    makefile_content = "\n".join(makefile_snippets) if makefile_snippets else "None"
    prompt = prompt_template.format(
        target_config=target_config,
        target_core=target_core,
        kconfig_content=kconfig_content,
        makefile_content=makefile_content
    )
    return prompt

def call_llm_api(prompt: str, api_key: str, base_url: str, model: str, max_retries: int = 3) -> list:
    """
    Call LLM API
    """
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    data = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a professional Linux kernel configuration analyst, strictly follow the output requirements."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.0,
        "max_tokens": 5000,
        "stream": False
    }
    retry_count = 0
    while retry_count < max_retries:
        try:
            response = requests.post(
                url=base_url,
                headers=headers,
                data=json.dumps(data),
                timeout=300,
                verify=False
            )
            response_json = response.json()
        
            content = response_json["choices"][0]["message"]["content"].strip()
            tokens = response_json["usage"]["total_tokens"]
            
            dependencies = []
            for line in content.split("\n"):
                line = line.strip()
                if line.startswith("CONFIG_"):
                    dependencies.append(line)

            return dependencies,tokens

        except requests.exceptions.RequestException as e:
            retry_count += 1
            if retry_count < max_retries:
                print(f"HTTP Request Failed ({retry_count}/{max_retries}): {str(e)}, retrying in 3 seconds..")
                time.sleep(3)
            else:
                raise Exception(f"HTTP Request Failed (Max Retries Reached): {str(e)}")
        except KeyError as e:
            raise Exception(f"Response Format Parse Failed: Missing Field {e}")
        except Exception as e:
            retry_count += 1
            if retry_count < max_retries:
                print(f"LLM API Call Failed ({retry_count}/{max_retries}): {str(e)}, retrying in 3 seconds..")
                time.sleep(3)
            else:
                raise Exception(f"LLM API Call Failed (Max Retries Reached): {str(e)}")
