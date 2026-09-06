import os
import re
import shutil
import winreg
from .utils import Colors

# 高危临时/公用脏路径（银狐等木马最常落盘执行的位置）
DIRTY_PATH_KEYWORDS = [
    r"\appdata\local\temp",
    r"\appdata\roaming\temp",
    r"\users\public",
    r"\windows\temp",
    r"\temp\\",
    r"\onedrive\cache"  # 银狐专属仿冒 OneDrive 缓存目录
]

# 常见合法用户级官方程序白名单
SAFE_USER_APPS = [
    r"\appdata\local\microsoft\onedrive\onedrive.exe",
    r"\appdata\local\microsoft\teams",
    r"\appdata\local\programs\\"
]

# 命令行风险特征
SUSPICIOUS_CMD_KEYWORDS = [
    "-enc ", "-w hidden", "-windowstyle hidden", "downloadstring",
    "iex(", "iex (", "invoke-expression", "bypass", "mshta", "certutil -urlcache"
]

def is_suspicious_entry(command_str: str) -> tuple[bool, list[str]]:
    """评估启动项命令字符串是否存在风险"""
    cmd_lower = command_str.lower().strip()
    reasons = []

    # 1. 检查是否有混淆或无窗执行参数（高危）
    for kw in SUSPICIOUS_CMD_KEYWORDS:
        if kw in cmd_lower:
            reasons.append(f"包含混淆/隐蔽执行特征: {kw}")
            break

    # 2. 检查仿冒系统进程
    if "svch0st.exe" in cmd_lower or "scvhost.exe" in cmd_lower:
        reasons.append("仿冒系统核心进程名 (svch0st)")

    # 3. 检查是否在非常规高危临时目录执行
    is_dirty = False
    for dp in DIRTY_PATH_KEYWORDS:
        if dp in cmd_lower:
            is_dirty = True
            reasons.append(f"位于高危临时/公用敏感路径: {dp}")
            break

    # 4. 如果不在明确高危临时目录，但命中了白名单，则放行
    if not is_dirty:
        if any(safe in cmd_lower for safe in SAFE_USER_APPS):
            return False, []

    return bool(reasons), reasons

def scan_registry_run_keys():
    """扫描所有 Run 与 RunOnce 注册表项"""
    entries = []
    targets = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU_Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU_RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM_Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM_RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM_Run_x86"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM_RunOnce_x86")
    ]
    for hroot, subkey_path, loc_name in targets:
        try:
            with winreg.OpenKey(hroot, subkey_path, 0, winreg.KEY_READ) as k:
                num_vals = winreg.QueryInfoKey(k)[1]
                for i in range(num_vals):
                    try:
                        v_name, v_data, _ = winreg.EnumValue(k, i)
                        is_risk, reasons = is_suspicious_entry(str(v_data))
                        entries.append({
                            "type": "registry",
                            "hroot": hroot,
                            "subkey_path": subkey_path,
                            "location": loc_name,
                            "name": v_name,
                            "command": str(v_data),
                            "is_risk": is_risk,
                            "reasons": reasons
                        })
                    except Exception:
                        pass
        except Exception:
            pass
    return entries

def scan_winlogon_hijack():
    """扫描 Winlogon Shell 和 Userinit 劫持"""
    hijacks = []
    winlogon_path = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, winlogon_path, 0, winreg.KEY_READ) as k:
            # 检查 Shell (默认为 explorer.exe)
            try:
                shell_val, _ = winreg.QueryValueEx(k, "Shell")
                if shell_val.strip().lower() != "explorer.exe":
                    hijacks.append({
                        "type": "winlogon",
                        "val_name": "Shell",
                        "current": shell_val,
                        "default": "explorer.exe",
                        "reason": "Winlogon Shell 被篡改 (非默认 explorer.exe)"
                    })
            except Exception:
                pass

            # 检查 Userinit (默认为 C:\Windows\system32\userinit.exe,)
            try:
                uinit_val, _ = winreg.QueryValueEx(k, "Userinit")
                normalized = uinit_val.replace('/', '\\').lower().strip()
                if "userinit.exe" not in normalized or len(normalized) > 40:
                    hijacks.append({
                        "type": "winlogon",
                        "val_name": "Userinit",
                        "current": uinit_val,
                        "default": r"C:\Windows\system32\userinit.exe,",
                        "reason": "Winlogon Userinit 疑似被追加病毒程序或篡改"
                    })
            except Exception:
                pass
    except Exception:
        pass
    return hijacks

def scan_startup_folders():
    """扫描开始菜单 Startup 启动文件夹"""
    items = []
    user_startup = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
    common_startup = os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup")

    for folder in [user_startup, common_startup]:
        if os.path.exists(folder):
            try:
                for f in os.listdir(folder):
                    full_path = os.path.join(folder, f)
                    if os.path.isfile(full_path) and not f.lower().endswith('.ini'):
                        is_risk, reasons = is_suspicious_entry(full_path)
                        # 如果非正常捷径或带有可疑后缀
                        ext = os.path.splitext(f)[1].lower()
                        if ext in ['.bat', '.vbs', '.js', '.exe', '.ps1']:
                            is_risk = True
                            reasons.append(f"启动目录直接存放可执行脚本/程序: {ext}")
                        items.append({
                            "type": "folder",
                            "folder": folder,
                            "filename": f,
                            "path": full_path,
                            "is_risk": is_risk,
                            "reasons": reasons
                        })
            except Exception:
                pass
    return items

def scan_all_startups():
    """综合检测所有自启动项"""
    reg_entries = scan_registry_run_keys()
    winlogon_entries = scan_winlogon_hijack()
    folder_entries = scan_startup_folders()

    risks = [r for r in reg_entries if r["is_risk"]]
    folder_risks = [f for f in folder_entries if f["is_risk"]]

    return {
        "reg_risks": risks,
        "winlogon_risks": winlogon_entries,
        "folder_risks": folder_risks,
        "all_reg": reg_entries,
        "all_folder": folder_entries
    }

def clean_startups(interactive=False):
    """清理恶意自启动项"""
    res = scan_all_startups()
    reg_risks = res["reg_risks"]
    winlogon_risks = res["winlogon_risks"]
    folder_risks = res["folder_risks"]

    total_risks = len(reg_risks) + len(winlogon_risks) + len(folder_risks)
    if total_risks == 0:
        print(f"{Colors.GREEN}[自启动项] 未发现符合银狐特征的高危自启动驻留项，状态正常。{Colors.END}")
        return True

    print(f"\n{Colors.YELLOW}[自启动项] 检测到 {total_risks} 项高危启动项：{Colors.END}")
    for r in reg_risks:
        print(f"  {Colors.RED}[注册表 Run]{Colors.END} 名称: {r['name']} ({r['location']})")
        print(f"    命令: {r['command']}")
        print(f"    风险原因: {', '.join(r['reasons'])}")

    for w in winlogon_risks:
        print(f"  {Colors.RED}[Winlogon 劫持]{Colors.END} 键: {w['val_name']} -> 当前值: {w['current']}")
        print(f"    风险原因: {w['reason']}")

    for f in folder_risks:
        print(f"  {Colors.RED}[Startup 文件夹]{Colors.END} 文件: {f['filename']}")
        print(f"    路径: {f['path']}")
        print(f"    风险原因: {', '.join(f['reasons'])}")

    if interactive:
        ask = input(f"\n是否处置上述 {total_risks} 项风险启动项？ [Y/N]: ").strip().upper()
        if ask != 'Y':
            print(f"{Colors.YELLOW}[自启动项] 已取消处置。{Colors.END}")
            return False

    # 1. 清理注册表 Run 项
    for r in reg_risks:
        try:
            with winreg.OpenKey(r["hroot"], r["subkey_path"], 0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, r["name"])
            print(f"  {Colors.GREEN}✅ 成功删除注册表启动项: {r['name']}{Colors.END}")
        except Exception as e:
            print(f"  {Colors.RED}❌ 删除失败 {r['name']}: {e}{Colors.END}")

    # 2. 恢复 Winlogon 默认值
    if winlogon_risks:
        winlogon_path = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, winlogon_path, 0, winreg.KEY_SET_VALUE) as k:
                for w in winlogon_risks:
                    winreg.SetValueEx(k, w["val_name"], 0, winreg.REG_SZ, w["default"])
                    print(f"  {Colors.GREEN}✅ 成功恢复 Winlogon {w['val_name']} 为系统默认值{Colors.END}")
        except Exception as e:
            print(f"  {Colors.RED}❌ 恢复 Winlogon 失败: {e}{Colors.END}")

    # 3. 隔离 Startup 目录恶意文件
    quarantine_dir = os.path.join(os.environ.get("TEMP", r"C:\Windows\Temp"), "foxs_quarantine_startup")
    os.makedirs(quarantine_dir, exist_ok=True)
    for f in folder_risks:
        try:
            target = os.path.join(quarantine_dir, f["filename"])
            shutil.move(f["path"], target)
            print(f"  {Colors.GREEN}✅ 成功隔离启动文件: {f['filename']} -> {target}{Colors.END}")
        except Exception as e:
            print(f"  {Colors.RED}❌ 隔离文件失败 {f['filename']}: {e}{Colors.END}")

    return True
