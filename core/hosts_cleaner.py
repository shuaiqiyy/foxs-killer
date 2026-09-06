import os
import re
import subprocess
from .utils import Colors, backup_file

HOSTS_PATH = r'C:\Windows\System32\drivers\etc\hosts'

# 广谱安全厂商与分析平台特征域名
KNOWN_SECURITY_DOMAINS = [
    # 360 系列
    '360.cn', '360safe.com', '360.com', 'qihucdn.com', 'weishi.360.cn',
    'sd.360.cn', 'down.360safe.com', 'dl.360safe.com', 'update.360safe.com', 'soft.360.cn',
    # 火绒安全
    'huorong.cn', 'down.huorong.cn', 'api.huorong.cn', 'bbs.huorong.cn', 'update.huorong.cn',
    # 腾讯电脑管家
    'guanjia.qq.com', 'pc.qq.com', 'pcmgr.qq.com', 'dlied1.qq.com', 'dlied6.qq.com',
    # 微步在线
    'threatbook.cn', 'threatbook.io', 'threatbook.com',
    # 金山毒霸
    'duba.net', 'ijinshan.com', 'kingsoft.com', 'kxescan.com',
    # 微软 Windows Defender / Update
    'smartscreen.microsoft.com', 'definitionupdates.microsoft.com', 'windowsupdate.com',
    'wdcp.microsoft.com', 'wdcpalt.microsoft.com',
    # 其他安全厂商
    'qianxin.com', 'sangfor.com.cn', 'sangfor.com', 'rising.com.cn', 'antiy.com',
    'virustotal.com', 'kaspersky.com', 'eset.com'
]

# 启发式安全关键词（当被解析到 127.0.0.1 或 0.0.0.0 时命中）
SECURITY_KEYWORDS = [
    '360', 'huorong', 'guanjia', 'threatbook', 'duba', 'jinshan', 'kingsoft',
    'qianxin', 'sangfor', 'rising', 'antivirus', 'antiy', 'kaspersky',
    'defender', 'smartscreen', 'virustotal', 'avast', 'eset', 'symantec'
]

def scan_hosts():
    """扫描 hosts 文件中被银狐等木马恶意劫持的条目"""
    if not os.path.exists(HOSTS_PATH):
        return []
    hijacked = []
    try:
        with open(HOSTS_PATH, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        for idx, line in enumerate(lines, 1):
            s_line = line.strip()
            if not s_line or s_line.startswith('#'):
                continue
            # 检查是否匹配已知域名
            matched = False
            for d in KNOWN_SECURITY_DOMAINS:
                if d in s_line.lower():
                    hijacked.append({"line_no": idx, "content": s_line, "domain": d, "reason": "匹配已知安全厂商域名"})
                    matched = True
                    break
            if matched:
                continue
            # 启发式检测：解析到 127.0.0.1 或 0.0.0.0，且域名含有安全关键词
            if s_line.startswith(('127.0.0.1', '0.0.0.0', '::1')):
                for kw in SECURITY_KEYWORDS:
                    if kw in s_line.lower():
                        hijacked.append({"line_no": idx, "content": s_line, "domain": kw, "reason": "疑似杀软/安全域名重定向劫持"})
                        break
    except Exception as e:
        print(f"{Colors.RED}[Hosts扫描失败] {e}{Colors.END}")
    return hijacked

def clean_hosts(interactive=False) -> bool:
    """清理 hosts 文件中被劫持的条目并重置 DNS 缓存"""
    hijacked = scan_hosts()
    if not hijacked:
        print(f"{Colors.GREEN}[Hosts] 未发现银狐相关域名劫持规则，文件状态正常。{Colors.END}")
        return True

    print(f"\n{Colors.YELLOW}[Hosts] 发现 {len(hijacked)} 条疑似恶意劫持规则：{Colors.END}")
    for item in hijacked:
        print(f"  行 {item['line_no']}: {item['content']} ({Colors.RED}{item['reason']}{Colors.END})")

    if interactive:
        ask = input(f"\n是否立即清理上述 {len(hijacked)} 条 Hosts 劫持规则？ [Y/N]: ").strip().upper()
        if ask != 'Y':
            print(f"{Colors.YELLOW}[Hosts] 已取消清理。{Colors.END}")
            return False

    bak = backup_file(HOSTS_PATH)
    if bak:
        print(f"{Colors.CYAN}[Hosts] 已自动备份原始文件至: {bak}{Colors.END}")

    try:
        with open(HOSTS_PATH, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        hijacked_contents = {h['content'] for h in hijacked}
        cleaned_lines = [line for line in lines if line.strip() not in hijacked_contents]

        with open(HOSTS_PATH, 'w', encoding='utf-8') as f:
            f.writelines(cleaned_lines)

        print(f"{Colors.GREEN}[Hosts] ✅ 成功清除 {len(hijacked)} 条劫持规则！{Colors.END}")

        # 自动刷新 DNS 缓存
        try:
            subprocess.run(["ipconfig", "/flushdns"], capture_output=True, text=True)
            print(f"{Colors.GREEN}[Hosts] ✅ 系统 DNS 缓存已自动刷新。{Colors.END}")
        except Exception:
            pass

        return True
    except PermissionError:
        print(f"{Colors.RED}[Hosts] ❌ 权限不足！修改 Hosts 需要管理员权限，请右键管理员运行。{Colors.END}")
        return False
    except Exception as e:
        print(f"{Colors.RED}[Hosts] ❌ 清理失败: {e}{Colors.END}")
        return False
