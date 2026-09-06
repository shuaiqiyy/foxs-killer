import winreg
from .utils import Colors

INTERNET_SETTINGS_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

def scan_proxy():
    """扫描系统 WinINet 代理配置与 PAC 脚本设置"""
    threats = []
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_PATH, 0, winreg.KEY_READ) as k:
            # 1. 检查 ProxyEnable
            proxy_enabled = 0
            try:
                proxy_enabled, _ = winreg.QueryValueEx(k, "ProxyEnable")
            except Exception:
                pass

            # 2. 检查 ProxyServer
            proxy_server = ""
            try:
                proxy_server, _ = winreg.QueryValueEx(k, "ProxyServer")
            except Exception:
                pass

            # 3. 检查 AutoConfigURL (PAC 自动化代理配置脚本)
            pac_url = ""
            try:
                pac_url, _ = winreg.QueryValueEx(k, "AutoConfigURL")
            except Exception:
                pass

            if proxy_enabled == 1 and proxy_server:
                threats.append({
                    "type": "ProxyServer",
                    "value": proxy_server,
                    "desc": f"系统代理已启用并指向: {proxy_server}"
                })

            if pac_url:
                threats.append({
                    "type": "AutoConfigURL",
                    "value": pac_url,
                    "desc": f"配置了 PAC 自动化代理脚本: {pac_url}"
                })
    except Exception:
        pass
    return threats

def clean_proxy(interactive=False):
    """重置网络代理为默认直连模式，清除恶意 PAC 劫持"""
    threats = scan_proxy()
    if not threats:
        print(f"{Colors.GREEN}[网络代理] 系统代理与 PAC 规则状态正常，未开启异常代理劫持。{Colors.END}")
        return True

    print(f"\n{Colors.YELLOW}[网络代理] 检测到系统代理配置异常：{Colors.END}")
    for t in threats:
        print(f"  - {Colors.RED}{t['type']}{Colors.END}: {t['value']} ({t['desc']})")

    if interactive:
        ask = input("\n是否重置网络代理为直连并清除 PAC 脚本配置？ [Y/N]: ").strip().upper()
        if ask != 'Y':
            print(f"{Colors.YELLOW}[网络代理] 用户取消重置。{Colors.END}")
            return False

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_PATH, 0, winreg.KEY_SET_VALUE) as k:
            # 禁用 ProxyEnable
            winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            # 清理 AutoConfigURL
            try:
                winreg.DeleteValue(k, "AutoConfigURL")
            except Exception:
                pass
        print(f"{Colors.GREEN}[网络代理] ✅ 代理已成功重置为直连，恶意 PAC 劫持已清除！{Colors.END}")
        return True
    except Exception as e:
        print(f"{Colors.RED}[网络代理] ❌ 重置代理失败: {e}{Colors.END}")
        return False
