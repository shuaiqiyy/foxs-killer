import sys
import os

# 确保导入路径包含当前根目录
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.utils import Colors, init_console, is_admin, require_admin_prompt, print_banner
from core.hosts_cleaner import scan_hosts, clean_hosts
from core.policy_cleaner import scan_policies, clean_policies
from core.reg_repair import scan_all_registry_threats, clean_ifeo, clean_disallow_run, restore_defender_policies
from core.startup_cleaner import scan_all_startups, clean_startups
from core.task_cleaner import scan_schtasks, clean_tasks
from core.process_killer import scan_processes, clean_processes
from core.network_cleaner import scan_proxy, clean_proxy

def run_full_diagnosis():
    """全盘深度体检诊断报告"""
    print(f"\n{Colors.BOLD}{Colors.HEADER}==================== [系统深度安全体检] ===================={Colors.END}")
    print(f"[*] 正在收集威胁情报并扫描系统环境，请稍候...\n")

    # 1. 扫描计划任务
    task_risks, total_tasks, _ = scan_schtasks()
    threat_paths = []
    for t in task_risks:
        threat_paths.extend(t.get("suspicious_paths", []))

    # 2. 扫描自启动项
    startup_res = scan_all_startups()
    for r in startup_res["reg_risks"]:
        threat_paths.append(r["command"])
    for f in startup_res["folder_risks"]:
        threat_paths.append(f["path"])

    # 3. 扫描进程 (结合前两项收集到的持久化路径进行交叉验证)
    proc_risks = scan_processes(known_threat_paths=threat_paths)

    # 4. 扫描 Hosts
    hosts_risks = scan_hosts()

    # 5. 扫描 CI 策略
    policy_res = scan_policies()
    citool_cnt = len(policy_res["citool_policies"])
    cip_cnt = len(policy_res["disk_cip_files"])

    # 6. 扫描注册表对抗项
    reg_res = scan_all_registry_threats()
    ifeo_cnt = len(reg_res["ifeo"])
    disallow_cnt = len(reg_res["disallow_run"])
    def_cnt = len(reg_res["defender"])

    # 7. 扫描网络代理
    proxy_risks = scan_proxy()

    # 汇总输出面板
    print(f"{Colors.BOLD}----------- 体检结果汇总 -----------{Colors.END}")
    
    def format_item(name, count, detail_str=""):
        if count > 0:
            return f"  [!] {name:<18}: {Colors.RED}发现 {count} 项高危威胁 {detail_str}{Colors.END}"
        else:
            return f"  [✓] {name:<18}: {Colors.GREEN}正常 (未检出威胁){Colors.END}"

    print(format_item("内存活跃进程", len(proc_risks), "(可疑木马/白利用进程)"))
    print(format_item("保活计划任务", len(task_risks), f"(系统共 {total_tasks} 条任务)"))
    print(format_item("自启动项驻留", len(startup_res["reg_risks"]) + len(startup_res["winlogon_risks"]) + len(startup_res["folder_risks"])))
    print(format_item("Hosts 域名劫持", len(hosts_risks), "(杀软/安全域名被拦截)"))
    print(format_item("CI/WDAC策略压制", citool_cnt + cip_cnt, "(杀软程序被系统底层策略封锁)"))
    print(format_item("IFEO 映像劫持", ifeo_cnt, "(任务管理器/杀软被重定向)"))
    print(format_item("DisallowRun 限制", disallow_cnt, "(程序禁止运行黑名单)"))
    print(format_item("Defender防护压制", def_cnt, "(实时防护被注册表强制关闭)"))
    print(format_item("网络代理/PAC劫持", len(proxy_risks)))
    print(f"{Colors.BOLD}------------------------------------{Colors.END}\n")

    total_threats = (len(proc_risks) + len(task_risks) + len(startup_res["reg_risks"]) +
                     len(hosts_risks) + citool_cnt + cip_cnt + ifeo_cnt + disallow_cnt +
                     def_cnt + len(proxy_risks))

    if total_threats > 0:
        print(f"{Colors.YELLOW}👉 系统存在银狐木马感染或防御压制痕迹（共发现 {total_threats} 处风险点）。建议立即执行「一键极速急救」。{Colors.END}\n")
    else:
        print(f"{Colors.GREEN}🎉 恭喜！当前系统状态健康，未检测到银狐病毒常见驻留与对抗特征。{Colors.END}\n")

    return {
        "threat_paths": threat_paths,
        "total_threats": total_threats
    }

def run_one_click_cure():
    """一键全流程急救清理：按最佳安全防护顺序逆向拆解木马链条"""
    print(f"\n{Colors.BOLD}{Colors.RED}==================== [执行一键全流程急救] ===================={Colors.END}")
    print(f"{Colors.CYAN}[流程规划]{Colors.END}")
    print(f"  Step 1: 扫描并强力切断恶意活跃进程 (先断运行态)")
    print(f"  Step 2: 排查并清除保活计划任务 (防止杀完又起)")
    print(f"  Step 3: 清理注册表与目录自启动项 (斩断重启自启)")
    print(f"  Step 4: 解除 IFEO 映像劫持与 DisallowRun 限制 (恢复杀软和排查工具启动权限)")
    print(f"  Step 5: 移除未签名 CI 代码完整性策略与异常 CIP 文件 (解开杀软拦截策略)")
    print(f"  Step 6: 修复 Hosts 文件安全厂商域名拦截并刷新 DNS (恢复安全软件联网更新)")
    print(f"  Step 7: 恢复 Windows Defender 默认防护 (激活系统防线)")
    print(f"  Step 8: 重置网络代理与 PAC 配置 (恢复网络环境)\n")

    # 预先收集可能由持久化引入的路径
    task_risks, _, _ = scan_schtasks()
    startup_res = scan_all_startups()
    threat_paths = []
    for t in task_risks:
        threat_paths.extend(t.get("suspicious_paths", []))
    for r in startup_res["reg_risks"]:
        threat_paths.append(r["command"])
    for f in startup_res["folder_risks"]:
        threat_paths.append(f["path"])

    print(f"{Colors.BOLD}--- [1/8] 查杀恶意活跃进程 ---{Colors.END}")
    clean_processes(known_threat_paths=threat_paths, interactive=True)

    print(f"\n{Colors.BOLD}--- [2/8] 处置恶意保活计划任务 ---{Colors.END}")
    clean_tasks(interactive=True)

    print(f"\n{Colors.BOLD}--- [3/8] 清理自启动驻留项 ---{Colors.END}")
    clean_startups(interactive=True)

    print(f"\n{Colors.BOLD}--- [4/8] 解除 IFEO 与 DisallowRun 注册表限制 ---{Colors.END}")
    clean_ifeo(interactive=True)
    clean_disallow_run(interactive=True)

    print(f"\n{Colors.BOLD}--- [5/8] 清除 CI/WDAC 恶意底层策略 ---{Colors.END}")
    clean_policies(interactive=True)

    print(f"\n{Colors.BOLD}--- [6/8] 修复 Hosts 文件劫持 ---{Colors.END}")
    clean_hosts(interactive=True)

    print(f"\n{Colors.BOLD}--- [7/8] 恢复 Windows Defender 策略 ---{Colors.END}")
    restore_defender_policies(interactive=True)

    print(f"\n{Colors.BOLD}--- [8/8] 检查并重置网络代理 ---{Colors.END}")
    clean_proxy(interactive=True)

    print(f"\n{Colors.BOLD}{Colors.GREEN}==================== [急救清理流程全部执行完毕] ===================={Colors.END}")
    print(f"{Colors.GREEN}温馨提示：{Colors.END}")
    print(f"1. 建议重启电脑，确保已被移除的代码完整性策略（CI Policy）完全从内核中注销。")
    print(f"2. 重启后请打开火绒、360或Windows Defender进行一次全盘查杀，彻底清除落盘的静态文件。")

def modular_menu():
    """高级分项处置菜单"""
    while True:
        print(f"\n{Colors.BOLD}-------- 分项专项处置菜单 --------{Colors.END}")
        print("  [1] 恶意活跃进程识别与强力查杀")
        print("  [2] 保活计划任务排查与处置 (禁用/彻底删除)")
        print("  [3] 注册表与目录自启动项清理")
        print("  [4] 解除 IFEO 映像劫持与 DisallowRun 限制")
        print("  [5] 清除 CI / WDAC 恶意代码完整性策略")
        print("  [6] 修复 Hosts 域名劫持并刷新 DNS")
        print("  [7] 恢复 Windows Defender 默认防护策略")
        print("  [8] 重置 WinINet 网络代理与 PAC 脚本")
        print("  [0] 返回主菜单")
        choice = input("请选择功能编号 [0-8]: ").strip()

        if choice == "1":
            clean_processes(interactive=True)
        elif choice == "2":
            clean_tasks(interactive=True)
        elif choice == "3":
            clean_startups(interactive=True)
        elif choice == "4":
            clean_ifeo(interactive=True)
            clean_disallow_run(interactive=True)
        elif choice == "5":
            clean_policies(interactive=True)
        elif choice == "6":
            clean_hosts(interactive=True)
        elif choice == "7":
            restore_defender_policies(interactive=True)
        elif choice == "8":
            clean_proxy(interactive=True)
        elif choice == "0":
            break
        else:
            print(f"{Colors.RED}输入无效，请重新选择。{Colors.END}")

def parse_cli_args():
    """解析命令行快速参数（支持静默自动化调用）"""
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg in ["--scan", "-s"]:
            run_full_diagnosis()
            sys.exit(0)
        elif arg in ["--clean-all", "-c"]:
            run_one_click_cure()
            sys.exit(0)
        elif arg == "--clean-hosts":
            clean_hosts(interactive=False)
            sys.exit(0)
        elif arg == "--clean-tasks":
            clean_tasks(interactive=False)
            sys.exit(0)
        elif arg == "--clean-policies":
            clean_policies(interactive=False)
            sys.exit(0)
        elif arg == "--kill-proc":
            clean_processes(interactive=False)
            sys.exit(0)
        elif arg in ["--help", "-h"]:
            print("参数说明:")
            print("  --scan, -s        快速执行全盘深度体检并输出报告")
            print("  --clean-all, -c   一键静默/交互执行全量急救清理")
            print("  --clean-hosts     仅清理 Hosts 文件中的域名劫持")
            print("  --clean-tasks     仅清理与禁用风险计划任务")
            print("  --clean-policies  仅清理 CI 恶意策略与 CIP 文件")
            print("  --kill-proc       仅排查并终止银狐恶意进程")
            sys.exit(0)

def main():
    init_console()
    print_banner()
    require_admin_prompt()
    parse_cli_args()

    while True:
        print(f"\n{Colors.BOLD}【主控制台】请选择操作模式：{Colors.END}")
        print(f"  {Colors.CYAN}[1] 全盘深度体检 (检测活跃进程/计划任务/自启/Hosts/CI策略等并生成报告){Colors.END}")
        print(f"  {Colors.RED}[2] 一键极速急救 (推荐：按防护闭环顺序一键查杀进程并清理所有驻留项){Colors.END}")
        print(f"  {Colors.YELLOW}[3] 高级分项处置 (进入子菜单单独处置某个特定安全模块){Colors.END}")
        print(f"  [0] 退出程序")

        choice = input("\n请输入选项数字 [0-3]: ").strip()
        if choice == "1":
            run_full_diagnosis()
        elif choice == "2":
            run_one_click_cure()
        elif choice == "3":
            modular_menu()
        elif choice == "0":
            print(f"\n{Colors.GREEN}感谢使用 foxs-killer，祝您的系统安全稳定！{Colors.END}")
            break
        else:
            print(f"{Colors.RED}输入无效，请输入 0、1、2 或 3。{Colors.END}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}程序已被用户手动中断。{Colors.END}")
        sys.exit(0)
