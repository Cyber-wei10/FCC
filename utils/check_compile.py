import os
import re
import subprocess

def verify_config(config_name: str, kernel_root: str):
    result = {
        "config": config_name,
        "value": None,
        "found_kbuild": False,
        "kbuild_path": None,
        "module_base": None,
        "objects_expected": [],
        "check_dirs": [],
        "verified": False,
        "msg": ""
    }
    os.chdir(kernel_root)

    val = "n"
    with open(".config", "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            m = re.match(r"^" + re.escape(config_name) + r"=([ym])", line)
            if m:
                val = m.group(1)
                break
    result["value"] = val

    pattern_obj = re.compile(
        rf"obj-\$\({re.escape(config_name)}\)\s*\+?=\s*(.+?)(?:\n|$)"
    )
    pattern_objs = re.compile(r"^(\S+)-(objs|y)\s*:?=\s*(.*)$", re.MULTILINE)
    
    found_in_non_arch = False
    def collect_all_objects(start_dir):
        objs = []
        check_dirs = []
        visited = set()

        def dfs(current_dir):
            if current_dir in visited:
                return
            visited.add(current_dir)

            for fname in ["Makefile", "Kbuild"]:
                path = os.path.join(current_dir, fname)
                if not os.path.exists(path):
                    continue
                try:
                    with open(path, "r", errors="ignore") as f:
                        content = f.read()
                except:
                    continue

                match = pattern_obj.search(content)
                if not match:
                    continue
                line = match.group(1).strip()
                items = line.split()

                for item in items:
                    item = item.strip()
                    if not item:
                        continue
                    
                    if item.endswith("/"):
                        subdir = item.rstrip("/")
                        full_sub = os.path.join(current_dir, subdir)
                        check_dirs.append(full_sub)
                        dfs(full_sub)
                    elif item.endswith(".o"):
                        base = item[:-2]
                        expanded = False
                        for m_base, _, m_val in pattern_objs.findall(content):
                            if m_base == base:
                                for o in m_val.split():
                                    o = o.strip()
                                    if o.endswith(".o") and o not in objs:
                                        objs.append(o)
                                expanded = True
                                break
                        if not expanded and item not in objs:
                            objs.append(item)
            return

        dfs(start_dir)
        return objs, check_dirs

    top_path = None
    top_dir = None
    for root, _, files in os.walk("."):
        if "/arch/" in root or root.startswith("./arch/"):
            continue
        for fname in files:
            if fname not in ("Makefile", "Kbuild"):
                continue
            path = os.path.join(root, fname)
            try:
                with open(path, "r", errors="ignore") as f:
                    content = f.read()
                if pattern_obj.search(content):
                    top_path = path
                    top_dir = root
                    found_in_non_arch = True
                    break
            except:
                continue
        if top_dir:
            break

    if not top_dir:
        has_arch_only = False
        for root, _, files in os.walk("."):
            for fname in files:
                if fname not in ("Makefile", "Kbuild"):
                    continue
                path = os.path.join(root, fname)
                try:
                    with open(path, "r", errors="ignore") as f:
                        content = f.read()
                    if pattern_obj.search(content):
                        if "/arch/" in root:
                            has_arch_only = True
                        break
                except:
                    continue
            if has_arch_only:
                break
        if has_arch_only:
            result["verified"] = True
            result["msg"] = "Architecture-dependent config"
            return result
        else:
            result["verified"] = True
            result["msg"] = "Not a Kbuild-related config"
            return result

    all_target_objs, check_dirs = collect_all_objects(top_dir)
    result["found_kbuild"] = True
    result["kbuild_path"] = top_path
    result["objects_expected"] = all_target_objs
    result["check_dirs"] = check_dirs

    ok = False
    if val == "y":
        for root, _, _ in os.walk("."):
            if "/arch/" in root:
                continue
            bpa = os.path.join(root, "built-in.a")
            bpo = os.path.join(root, "built-in.o")

            if os.path.exists(bpa):
                try:
                    out = subprocess.check_output(["ar", "t", bpa], text=True, stderr=subprocess.DEVNULL)
                    files = {os.path.basename(f.strip()) for f in out.splitlines()}
                    for o in all_target_objs:
                        if o in files:
                            ok = True
                            break
                except:
                    pass
            if ok:
                break

            if os.path.exists(bpo):
                try:
                    for o in all_target_objs:
                        sym = o.replace(".o", "")
                        cmd = f"nm {bpo} | grep -qE '\\b{sym}_?'"
                        if subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                            ok = True
                            break
                except:
                    pass
            if ok:
                break

        if not ok:
            for d in check_dirs:
                bpa = os.path.join(d, "built-in.a")
                bpo = os.path.join(d, "built-in.o")
                if os.path.exists(bpa) or os.path.exists(bpo):
                    ok = True
                    break

        if ok:
            result["verified"] = True
            result["msg"] = "=y Objects built OR directory built-in exists"
        else:
            result["verified"] = False
            result["msg"] = "=y No objects built"

    elif val == "m":
        result["verified"] = True
        result["msg"] = "=m Module config"
    elif val == "n":
        result["verified"] = True
        result["msg"] = "=n Disabled"

    return result