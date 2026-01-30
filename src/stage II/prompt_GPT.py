import requests
import json

def build_prompt(kconfig_snippets: list, makefile_snippets: list, target_config: str) -> str:

    target_core = target_config.replace("CONFIG_", "")
    prompt_template = """### Configuration Item Semantic Explanation:
- depends on: Indicates a hard dependency relationship, meaning the current configuration item can only be configured when all dependencies are satisfied
- select: Indicates a selection relationship, meaning when the current configuration item is enabled, the selected configuration items will be automatically enabled without manual configuration
- source: Used to introduce other Kconfig files, usually appearing in conditional statements, and only introduces configuration items from corresponding files when conditions are met

### Task: Analyze the minimal configuration item set to enable {target_config}, that is, to successfully enable {target_config}, please provide its dependent configuration item set and minimize it
### Core Rules:
1. Hard dependencies:
   - depends on X && Y → Keep all dependencies (missing any one will make {target_config} unable to be configured)
   - depends on X || Y → Only select the 1 most common dependency
2. Select rules:
   - {target_config} select X → X is automatically enabled, no need to add to minimal configuration
   - Multiple configuration items select {target_config} → Only select the 1 most common configuration item
3. Soft dependencies:
   - Driver items described as "need to enable/for example/such as" in help → Only select the 1 most commonly used
4. Ignore items:
   - If other configuration items select {target_config} → Ignore {target_config} itself (no need to add manually)
   - If no configuration items select {target_config} → Must keep {target_config} itself (need to add manually)
   - Duplicate items, comments, empty lines, non-CONFIG starting lines are all ignored

### Analysis Materials:
Kconfig:
{kconfig_content}


Makefile:
{makefile_content}


### Output Requirements:
1. Output is divided into 2 parts:
   - First part: Dependency relationships between configuration items and {target_config} and other configuration items
   - Second part: All configuration items that need to be enabled
2. When outputting the first part, must output all configuration items and their dependencies in a specific format:
   - Each line format: Configuration Item → Dependencies: dependency1, dependency2, ...
   - Example: CONFIG_A → Dependencies: CONFIG_B, CONFIG_C
   - Configuration items without direct dependencies format: Configuration Item → Dependencies: 
3. When outputting the second part, only return configuration items starting with CONFIG_, 1 per line, without any extra characters (comments/explanations/symbols/newlines are not needed)
4. When outputting the second part, output order: Strictly follow the configuration item enable order (dependencies first, depended items after)
5. When outputting the second part, prohibit duplicate output of the same configuration item, no need to sort alphabetically, only output in logical dependency order
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

def call_LLM_api(prompt: str, target_config: str) -> list:
    API_KEY = "your_api_key_placeholder"
    BASE_URL = "your_api_endpoint_placeholder"
    if not API_KEY or API_KEY.strip() == "your_api_key_placeholder":
        raise ValueError("Please replace with a valid API Key")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}"
    }
    data = {
        "model": "model_name",
        "messages": [
            {"role": "system", "content": "You are a professional Linux kernel configuration analyst, strictly follow the output requirements."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.0,
        "max_tokens": 500,
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
        print(f"Status code: {response.status_code}")
        response_json = response.json()
        print(f"Response content: {json.dumps(response_json, ensure_ascii=False)}")
        
        content = response_json["choices"][0]["message"]["content"].strip()
        
        dependencies = []
        for line in content.split("\n"):
            line = line.strip()
            if line.startswith("CONFIG_"):
                dependencies.append(line)

        return dependencies

    except requests.exceptions.RequestException as e:
        raise Exception(f"HTTP request failed: {str(e)}")
    except KeyError as e:
        raise Exception(f"Response format parsing failed: missing field {e}")
    except Exception as e:
        raise Exception(f"API call failed: {str(e)}")

if __name__ == "__main__":
    test_kconfig = [
        """config VSOCKETS
tristate "Virtual Socket protocol"
depends on NET

config VIRTIO_VSOCKETS
tristate "Virtio vsock driver"
depends on VSOCKETS && VIRTIO
select VSOCKETS"""
    ]
    test_makefile = [
        "obj-$(CONFIG_VSOCKETS) += vsock.o",
        "obj-$(CONFIG_VIRTIO_VSOCKETS) += vmw_vsock_virtio_transport.o"
    ]
    test_target = "CONFIG_VSOCKETS"

    prompt = build_prompt(
        kconfig_snippets=test_kconfig,
        makefile_snippets=test_makefile,
        target_config=test_target
    )
    print("=== Template Prompt ===")
    print(prompt)

    try:
        min_deps = call_LLM_api(prompt, test_target)
        print("\n=== Minimal Configuration Items (in enable order) ===")
        print(min_deps)
    except Exception as e:
        print(f"\nError: {e}")
