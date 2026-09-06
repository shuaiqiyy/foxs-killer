import os
import re
import shutil
import subprocess
from .utils import Colors, backup_file, is_admin

CIPOLICIES_DIR = r'C:\Windows\System32\CodeIntegrity\CiPolicies\Active'

def delete_policy_by_citool(policy_guid: str):
    """使用 citool -rp 移除策略"""
    cmd = ["powershell.exe", "-NoProfile", "-Command", f"citool -rp '{policy_guid}'"]
    try:
        res = subprocess.run(cmd, capture_output=True, stdin=subprocess.DEVNULL, timeout=8)
        stdout = res.stdout.decode("gbk", errors="ignore")
        stderr = res.stderr.decode("gbk", errors="ignore")
        ok = (res.returncode == 0)
        return ok, stdout, stderr, res.returncode
    except Exception as e:
        return False, "", str(e), -1

def scan_citool_policies():
    """通过 citool -lp 扫描恶意代码完整性策略"""
    if not is_admin():
        # citool 查询需要管理员权限，未提权时避免出现 0x80070005 导致程序等待输入
        return []
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", "citool -lp"],
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=8
        )
        if result.returncode != 0:
            return None
        output = result.stdout.decode('utf-8', errors='ignore')
        if '' in output or output.count('') > 10:
            output = result.stdout.decode('gbk', errors='ignore')
        raw_lines = output.splitlines()
        found_blocks = []
        current_block_lines = []
        for line in raw_lines:
            if line.strip().startswith("策略:"):
                if current_block_lines:
                    found_blocks.append("\r\n".join(current_block_lines))
                    current_block_lines = []
            current_block_lines.append(line)
        if current_block_lines:
            found_blocks.append("\r\n".join(current_block_lines))

        def get_field(text, key):
            pat = re.compile(rf"{key}\s*[：:]\s*(.+?)(?=\r?\n|$)")
            m = pat.search(text)
            return m.group(1).strip().lower() if m else None

        policy_list = []
        for blk in found_blocks:
            plat = get_field(blk, "平台策略")
            signed = get_field(blk, "策略已签名")
            enforce = get_field(blk, "当前强制执行")
            # 银狐恶意策略特征：强制执行、非平台策略、未签名
            if enforce == "true" and plat == "false" and signed == "false":
                policy = {
                    "id": get_field(blk, "策略 ID"),
                    "name": get_field(blk, "好记的名称"),
                    "enforce": enforce,
                    "auth": get_field(blk, "授权"),
                    "plat": plat,
                    "signed": signed
                }
                policy_list.append(policy)
        return policy_list
    except Exception as e:
        return None

def scan_cipolicies_directory(malicious_guids: list[str] = None):
    """扫描 CiPolicies\\Active 物理目录下的 .cip 文件，若指定了恶意 GUID 则精准匹配"""
    if not os.path.exists(CIPOLICIES_DIR):
        return []
    cip_files = []
    try:
        for f in os.listdir(CIPOLICIES_DIR):
            if f.lower().endswith('.cip'):
                guid_in_name = f.upper().replace(".CIP", "")
                # 如果有 citool 确定的恶意 ID，优先匹配
                if malicious_guids:
                    matched = any(mg.upper() in guid_in_name for mg in malicious_guids)
                    if not matched:
                        continue  # 忽略微软官方平台策略（如驱动黑名单等）
                
                full_path = os.path.join(CIPOLICIES_DIR, f)
                try:
                    stat = os.stat(full_path)
                    cip_files.append({
                        "filename": f,
                        "path": full_path,
                        "size": stat.st_size,
                        "mtime": stat.st_mtime
                    })
                except Exception:
                    pass
    except Exception as e:
        pass
    return cip_files

def scan_policies():
    """综合扫描所有 CI 策略（精准识别未签名且强制执行的非平台恶意策略）"""
    citool_list = scan_citool_policies() or []
    malicious_ids = [p["id"] for p in citool_list if p.get("id")]
    
    # 仅当发现恶意 ID 时，定位对应的磁盘 CIP 文件；若无恶意策略，则不误报微软官方驱动阻止列表
    disk_cips = scan_cipolicies_directory(malicious_guids=malicious_ids) if malicious_ids else []

    return {
        "citool_policies": citool_list,
        "disk_cip_files": disk_cips
    }

def clean_policies(interactive=False) -> bool:
    """清理恶意 CI 策略及磁盘残留"""
    scan_res = scan_policies()
    citool_list = scan_res["citool_policies"]
    cip_files = scan_res["disk_cip_files"]

    has_threat = bool(citool_list or cip_files)
    if not has_threat:
        print(f"{Colors.GREEN}[CI策略] 未检测到符合银狐特征的未签名恶意 CI 策略或异常 CIP 文件。{Colors.END}")
        return True

    print(f"\n{Colors.YELLOW}[CI策略] 检测到潜在威胁：{Colors.END}")
    if citool_list:
        print(f"  {Colors.RED}【citool 动态策略】检测到 {len(citool_list)} 条可疑策略：{Colors.END}")
        for i, p in enumerate(citool_list, 1):
            print(f"    [{i}] ID: {p['id']} | 名称: {p['name']} | 强制执行: {p['enforce']} | 签名: {p['signed']}")

    if cip_files:
        print(f"  {Colors.RED}【底层 CiPolicies 目录】发现 {len(cip_files)} 个活动 .cip 策略文件：{Colors.END}")
        for f in cip_files:
            print(f"    - {f['path']} ({f['size']} 字节)")

    if interactive:
        ask = input(f"\n是否清理上述检测到的恶意 CI 策略项？ [Y/N]: ").strip().upper()
        if ask != 'Y':
            print(f"{Colors.YELLOW}[CI策略] 已取消操作。{Colors.END}")
            return False

    # 1. 执行 citool 删除
    if citool_list:
        print(f"\n{Colors.CYAN}正在调用 citool 移除动态策略...{Colors.END}")
        for pol in citool_list:
            pid = pol["id"]
            ok, out, err, rc = delete_policy_by_citool(pid)
            if ok:
                print(f"  {Colors.GREEN}✅ 策略删除成功: {pid}{Colors.END}")
            else:
                print(f"  {Colors.RED}❌ 策略删除失败 (rc={rc}): {pid} {err.strip()}{Colors.END}")

    # 2. 针对磁盘上的 .cip 文件提供隔离/删除
    if cip_files:
        print(f"\n{Colors.CYAN}正在处置 CiPolicies 物理文件...{Colors.END}")
        quarantine_dir = os.path.join(os.environ.get("TEMP", r"C:\Windows\Temp"), "foxs_quarantine_cip")
        os.makedirs(quarantine_dir, exist_ok=True)
        for f in cip_files:
            try:
                # 移动隔离而不是直接硬删，确保安全可逆
                target_bak = os.path.join(quarantine_dir, f['filename'])
                shutil.move(f['path'], target_bak)
                print(f"  {Colors.GREEN}✅ 已隔离移出: {f['filename']} -> {target_bak}{Colors.END}")
            except PermissionError:
                print(f"  {Colors.RED}❌ 权限不足！无法移出 {f['filename']}，需要 SYSTEM/TrustedInstaller 或在安全模式下操作。{Colors.END}")
            except Exception as e:
                print(f"  {Colors.RED}❌ 移除失败 {f['filename']}: {e}{Colors.END}")

    print(f"\n{Colors.GREEN}[CI策略] 清理流程执行完毕。若杀软被拦截，建议重启系统使策略完全注销生效。{Colors.END}")
    return True
