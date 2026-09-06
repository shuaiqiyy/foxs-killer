import os
import sys
import ctypes
import shutil
from datetime import datetime

# 控制台颜色代码（标准 ANSI）
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

# 初始化 Windows 控制台 ANSI 支持
def init_console():
    if os.name == 'nt':
        os.system('')
        try:
            if hasattr(sys.stdout, 'reconfigure'):
                sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
            if hasattr(sys.stderr, 'reconfigure'):
                sys.stderr.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
        except Exception:
            pass

def is_admin() -> bool:
    """检查当前进程是否具有管理员权限"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def require_admin_prompt():
    """如果不是管理员权限，提示用户"""
    if not is_admin():
        print(f"{Colors.YELLOW}[警告] 当前未以管理员身份运行！部分修复（如修改 Hosts、清理 CI 策略、强制终止进程）将失败。{Colors.END}")
        print(f"{Colors.YELLOW}[建议] 请右键使用「以管理员身份运行」启动本程序。{Colors.END}\n")

def backup_file(filepath: str) -> str:
    """对关键文件在修改前进行带时间戳的备份"""
    if not os.path.exists(filepath):
        return ""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        bak_path = f"{filepath}.bak_{timestamp}"
        shutil.copy2(filepath, bak_path)
        return bak_path
    except Exception as e:
        print(f"{Colors.RED}[备份失败] 无法备份 {filepath}: {e}{Colors.END}")
        return ""

def print_banner():
    banner = Colors.CYAN + r"""
======================================================================
  ______          _        _  ___ _ _           
 |  ____|        | |      | |/ (_) | |          
 | |__ _____  ___| | _____| ' / _| | | ___ _ __ 
 |  __/ _ \ \/ / | |/ / __|  < | | | |/ _ \ '__|
 | | | (_) >  < _|   <\__ \ . \| | | |  __/ |   
 |_|  \___/_/\_(_)_|\_\___/_|\_\_|_|_|\___|_|   
======================================================================
  银狐（Silver Fox / ValleyRAT）病毒深度排查与修复工具 v2.0
  纯原生标准库架构 · 开源 · 可扩展二次开发
======================================================================
""" + Colors.END
    print(banner)
