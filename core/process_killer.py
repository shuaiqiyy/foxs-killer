import os
import ctypes
from ctypes import wintypes
import subprocess
from .utils import Colors

# 常见被银狐白利用/DLL劫持的特征 DLL
HIJACKED_DLL_NAMES = [
    "version.dll", "dbghelp.dll", "userenv.dll", "cryptbase.dll",
    "wldp.dll", "mpclient.dll", "secur32.dll", "msvcr100.dll"
]

# 仿冒核心系统进程的名称或规则
FAKE_SYSTEM_NAMES = [
    "svch0st.exe", "scvhost.exe", "svchostt.exe",
    "csrsss.exe", "lsasss.exe", "smsss.exe", "taskmgrr.exe", "explorerx.exe"
]

# 必须仅能在 System32 运行的系统进程
STRICT_SYSTEM32_EXES = [
    "svchost.exe", "lsass.exe", "csrss.exe", "smss.exe", "services.exe",
    "winlogon.exe", "wininit.exe", "taskhostw.exe"
]

def get_process_list_native():
    """使用 Win32 API 快速枚举系统活跃进程及其镜像文件路径"""
    processes = []
    kernel32 = ctypes.windll.kernel32

    TH32CS_SNAPPROCESS = 0x00000002
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_wchar * 260)
        ]

    h_snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if h_snap == -1:
        return processes

    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)

    success = kernel32.Process32FirstW(h_snap, ctypes.byref(entry))
    while success:
        pid = entry.th32ProcessID
        name = entry.szExeFile
        exe_path = ""

        if pid > 4:  # 忽略 System Idle 与 System 核心
            h_proc = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if h_proc:
                buf = ctypes.create_unicode_buffer(1024)
                size = wintypes.DWORD(1024)
                if kernel32.QueryFullProcessImageNameW(h_proc, 0, buf, ctypes.byref(size)):
                    exe_path = buf.value
                kernel32.CloseHandle(h_proc)

        processes.append({
            "pid": pid,
            "name": name,
            "exe_path": exe_path
        })
        success = kernel32.Process32NextW(h_snap, ctypes.byref(entry))

    kernel32.CloseHandle(h_snap)
    return processes

def evaluate_process_risk(proc: dict, known_threat_paths: list[str]) -> tuple[int, list[str]]:
    """多维评估进程风险度"""
    score = 0
    tags = []
    pid = proc["pid"]
    name_lower = proc["name"].lower()
    path_lower = proc["exe_path"].lower()

    if not path_lower:
        return 0, []

    # 1. 白名单保护：正规安装在 Program Files 或标准 System32 的非仿冒程序放行
    is_in_prog_files = path_lower.startswith(r"c:\program files")
    is_in_sys32 = path_lower.startswith(r"c:\windows\system32") or path_lower.startswith(r"c:\windows\syswow64")

    # 2. 交叉验证命中：与排查出的恶意计划任务或自启动项路径完全一致
    for tp in known_threat_paths:
        tp_clean = tp.strip('"').strip().lower()
        if tp_clean and (tp_clean == path_lower or tp_clean in path_lower):
            score += 80
            tags.append("交叉锁定: 匹配恶意持久化启动项")
            break

    # 3. 仿冒进程名判定
    if name_lower in FAKE_SYSTEM_NAMES:
        score += 60
        tags.append(f"典型仿冒系统进程名 ({name_lower})")

    # 4. 系统专有进程运行在非法路径（例如 svchost.exe 在 AppData 中运行）
    if name_lower in STRICT_SYSTEM32_EXES and not is_in_sys32:
        score += 70
        tags.append("核心系统组件非官方目录运行 (伪装/越权)")

    # 5. 脏路径判定（银狐极大概率落地在 Temp / AppData / Public）
    dirty_roots = [
        r"\appdata\local\temp",
        r"\appdata\local",
        r"\appdata\roaming",
        r"\users\public",
        r"\windows\temp"
    ]
    is_dirty = any(dr in path_lower for dr in dirty_roots)
    if is_dirty and not is_in_prog_files:
        score += 35
        tags.append("运行于临时/公用敏感可写路径")

        # 6. 白加黑（DLL 劫持）伴随文件检测
        try:
            exe_dir = os.path.dirname(proc["exe_path"])
            if os.path.isdir(exe_dir):
                dir_files = [f.lower() for f in os.listdir(exe_dir)]
                found_hijack_dlls = [dll for dll in HIJACKED_DLL_NAMES if dll in dir_files]
                if found_hijack_dlls:
                    score += 35
                    tags.append(f"白加黑特征: 同目录发现敏感DLL ({', '.join(found_hijack_dlls)})")
        except Exception:
            pass

    return score, tags

def scan_processes(known_threat_paths=None):
    """扫描系统中所有可疑的银狐木马活跃进程"""
    if known_threat_paths is None:
        known_threat_paths = []
    
    raw_list = get_process_list_native()
    suspicious_list = []

    for p in raw_list:
        score, tags = evaluate_process_risk(p, known_threat_paths)
        if score >= 50:
            suspicious_list.append({
                **p,
                "score": score,
                "tags": tags
            })

    return suspicious_list

def kill_processes(targets: list[dict]):
    """强力终止指定进程"""
    killed_cnt = 0
    for t in targets:
        pid = t["pid"]
        name = t["name"]
        print(f"  正在终止进程 PID={pid} ({name})...")
        cmd = ["taskkill", "/f", "/pid", str(pid)]
        ret = subprocess.run(cmd, capture_output=True, text=True)
        if ret.returncode == 0:
            print(f"  {Colors.GREEN}✅ 成功终止进程: {name} (PID: {pid}){Colors.END}")
            killed_cnt += 1
        else:
            print(f"  {Colors.RED}❌ 终止失败 PID={pid}: {ret.stderr.strip()}{Colors.END}")
    return killed_cnt

def clean_processes(known_threat_paths=None, interactive=False):
    """排查并处置可疑银狐活跃进程"""
    sus_list = scan_processes(known_threat_paths)
    if not sus_list:
        print(f"{Colors.GREEN}[活跃进程] 未检测到符合银狐特征的高危活跃进程。{Colors.END}")
        return True, []

    print(f"\n{Colors.YELLOW}[活跃进程] 警报！检测到 {len(sus_list)} 个疑似银狐恶意进程：{Colors.END}")
    for idx, p in enumerate(sus_list, 1):
        print(f"  [{idx}] 进程: {Colors.RED}{p['name']}{Colors.END} (PID: {p['pid']} | 评分: {p['score']})")
        print(f"      路径: {p['exe_path']}")
        print(f"      风险特征: {' | '.join(p['tags'])}\n")

    if interactive:
        ask = input(f"\n是否立即强行终止上述 {len(sus_list)} 个高危进程以阻断木马运行？ [Y/N]: ").strip().upper()
        if ask != 'Y':
            print(f"{Colors.YELLOW}[活跃进程] 用户已取消强杀。{Colors.END}")
            return False, sus_list

    killed = kill_processes(sus_list)
    print(f"\n{Colors.GREEN}[活跃进程] 强杀完毕：成功终止 {killed}/{len(sus_list)} 个恶意进程。{Colors.END}")
    return True, sus_list
