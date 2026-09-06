import subprocess
from .utils import Colors

# 常见合法的本地开发者调试器或文本编辑器（过滤白名单）
LEGIT_DEBUGGERS = [
    "notepad3.exe", "notepad++.exe", "sublime_text.exe", "code.exe",
    "vsjitdebugger.exe", "windbg.exe", "x64dbg.exe", "x32dbg.exe", "ida.exe", "ida64.exe"
]

def _run_reg(cmd_args: list[str]) -> tuple[int, str]:
    """统一调用 Windows 原生 reg.exe 工具进行安全读写"""
    full_cmd = ["reg.exe"] + cmd_args
    res = subprocess.run(full_cmd, capture_output=True)
    out = res.stdout.decode("gbk", errors="ignore") + res.stderr.decode("gbk", errors="ignore")
    return res.returncode, out

def scan_ifeo():
    """使用原生 reg.exe 全面排查 IFEO 映像劫持"""
    hijacked_items = []
    targets = [
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    ]
    for root_path in targets:
        rc, out = _run_reg(["query", root_path, "/s", "/f", "Debugger"])
        if rc == 0:
            current_key = ""
            for line in out.splitlines():
                s = line.strip()
                if s.startswith("HKEY_LOCAL_MACHINE"):
                    current_key = s
                elif "Debugger" in s and "REG_SZ" in s:
                    # 提取具体的 Debugger 值
                    parts = s.split("REG_SZ", 1)
                    dbg_val = parts[1].strip() if len(parts) > 1 else ""
                    # 提取被劫持的目标程序名
                    target_exe = current_key.split("\\")[-1] if current_key else "Unknown"

                    # 检查是否命中合法白名单编辑器/调试器
                    dbg_lower = dbg_val.lower()
                    if not any(legit in dbg_lower for legit in LEGIT_DEBUGGERS):
                        hijacked_items.append({
                            "target_exe": target_exe,
                            "debugger": dbg_val,
                            "reg_key": current_key
                        })
    return hijacked_items

def clean_ifeo(interactive=False):
    """清理恶意 IFEO 映像劫持"""
    items = scan_ifeo()
    if not items:
        print(f"{Colors.GREEN}[IFEO映像劫持] 未发现异常劫持项，状态正常。{Colors.END}")
        return True

    print(f"\n{Colors.YELLOW}[IFEO映像劫持] 发现 {len(items)} 个程序被劫持：{Colors.END}")
    for item in items:
        print(f"  - 目标: {item['target_exe']} -> 劫持至: {Colors.RED}{item['debugger']}{Colors.END}")

    if interactive:
        ask = input(f"\n是否删除上述 {len(items)} 项恶意劫持？ [Y/N]: ").strip().upper()
        if ask != 'Y':
            print(f"{Colors.YELLOW}[IFEO] 已取消。{Colors.END}")
            return False

    success_cnt = 0
    for item in items:
        rc, out = _run_reg(["delete", item["reg_key"], "/v", "Debugger", "/f"])
        if rc == 0:
            print(f"  {Colors.GREEN}✅ 成功解除劫持: {item['target_exe']}{Colors.END}")
            success_cnt += 1
        else:
            print(f"  {Colors.RED}❌ 解除失败 {item['target_exe']}: {out.strip()}{Colors.END}")
    return success_cnt > 0

def scan_disallow_run():
    """扫描系统软件禁止运行策略 (DisallowRun)"""
    disallowed = []
    targets = [
        ("HKCU", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"),
        ("HKLM", r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun")
    ]
    for tag, reg_path in targets:
        rc, out = _run_reg(["query", reg_path])
        if rc == 0:
            banned = []
            for line in out.splitlines():
                line_str = line.strip()
                if "REG_SZ" in line_str:
                    val = line_str.split("REG_SZ", 1)[1].strip()
                    banned.append(val)
            if banned:
                disallowed.append({
                    "tag": tag,
                    "reg_path": reg_path,
                    "parent_path": reg_path.rsplit("\\", 1)[0],
                    "banned_apps": banned
                })
    return disallowed

def clean_disallow_run(interactive=False):
    """解除 DisallowRun 禁止运行策略"""
    disallowed = scan_disallow_run()
    if not disallowed:
        print(f"{Colors.GREEN}[DisallowRun策略] 未启用软件禁止运行策略，状态正常。{Colors.END}")
        return True

    print(f"\n{Colors.YELLOW}[DisallowRun策略] 检测到系统启用了程序禁止运行黑名单：{Colors.END}")
    for item in disallowed:
        print(f"  - [{item['tag']}] 禁用名单包含 ({len(item['banned_apps'])} 个程序): {', '.join(item['banned_apps'][:10])}")

    if interactive:
        ask = input("\n是否立即清除该黑名单策略？ [Y/N]: ").strip().upper()
        if ask != 'Y':
            print(f"{Colors.YELLOW}[DisallowRun] 已取消。{Colors.END}")
            return False

    for item in disallowed:
        # 删除 DisallowRun 子项
        _run_reg(["delete", item["reg_path"], "/f"])
        # 将父项的 DisallowRun 开关删除或置 0
        _run_reg(["delete", item["parent_path"], "/v", "DisallowRun", "/f"])
        print(f"  {Colors.GREEN}✅ 成功解除 [{item['tag']}] 的限制策略！{Colors.END}")
    return True

def scan_defender_policies():
    """扫描系统安全防护策略是否被恶意关闭"""
    threats = []
    reg_items = [
        (r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware"),
        (r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring"),
        (r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableBehaviorMonitoring")
    ]
    for p, v in reg_items:
        rc, out = _run_reg(["query", p, "/v", v])
        if rc == 0 and "0x1" in out:
            threats.append({"reg_path": p, "val_name": v})
    return threats

def restore_defender_policies(interactive=False):
    """恢复被恶意关闭的安全防护策略"""
    threats = scan_defender_policies()
    if not threats:
        print(f"{Colors.GREEN}[安全防护策略] 策略未被异常关闭，状态正常。{Colors.END}")
        return True

    print(f"\n{Colors.YELLOW}[安全防护策略] 检测到安全防护被注册表策略强制关闭：{Colors.END}")
    for t in threats:
        print(f"  - 策略项: {t['val_name']} = 1 (位于 {t['reg_path']})")

    if interactive:
        ask = input("\n是否恢复系统默认防护策略？ [Y/N]: ").strip().upper()
        if ask != 'Y':
            print(f"{Colors.YELLOW}[安全防护策略] 已取消。{Colors.END}")
            return False

    for t in threats:
        rc, out = _run_reg(["delete", t["reg_path"], "/v", t["val_name"], "/f"])
        if rc == 0:
            print(f"  {Colors.GREEN}✅ 成功恢复防护: 已删除 {t['val_name']}{Colors.END}")
        else:
            print(f"  {Colors.RED}❌ 恢复失败: {out.strip()}{Colors.END}")
    return True

def scan_all_registry_threats():
    """综合检测所有注册表防御对抗项"""
    return {
        "ifeo": scan_ifeo(),
        "disallow_run": scan_disallow_run(),
        "defender": scan_defender_policies()
    }
