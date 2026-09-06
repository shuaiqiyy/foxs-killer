import os
import io
import csv
import subprocess
from .utils import Colors

# 白名单安全程序路径（必须绝对以这些开头，且不含混淆参数）
SAFE_EXE_PREFIXES = [
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\program files",
    r"c:\program files (x86)"
]

def is_safe_system_task(task_path: str, prog: str, args: str) -> bool:
    """智能白名单过滤系统原生任务与官方常用软件，大幅减少误报噪音"""
    task_path_lower = task_path.lower()
    prog_lower = prog.lower().strip()
    args_lower = args.lower().strip()

    # 包含高危脚本混淆参数的一律不放行
    has_bad_args = any(bad in args_lower or bad in prog_lower for bad in ["-enc", "hidden", "bypass", "iex", "downloadstring", "mshta", "http:", "https:"])
    if has_bad_args:
        return False

    # 1. 微软系统原生核心任务
    if task_path_lower.startswith(r"\microsoft\windows"):
        if any(prog_lower.startswith(prefix) for prefix in SAFE_EXE_PREFIXES):
            return True

    # 2. 微软官方 OneDrive 正常启动任务（银狐常在 \onedrive\cache 伪装，官方位于正规版本子目录）
    if "onedrive startup task" in task_path_lower:
        if r"\microsoft\onedrive" in prog_lower and r"\onedrive\cache" not in prog_lower:
            return True

    # 3. 微软 Edge / Google Chrome 官方更新任务
    if any(k in task_path_lower for k in ["microsoftedgeupdatetask", "googleupdatetask"]):
        return True

    return False

def scan_schtasks(csv_output_path="计划任务全量导出.csv"):
    """全量导出并深度排查计划任务"""
    cmd = ["schtasks", "/query", "/v", "/fo", "csv", "/nh"]
    ret = subprocess.run(cmd, capture_output=True, encoding="gbk", errors="replace")
    if ret.returncode != 0:
        print(f"{Colors.RED}[计划任务] 执行 schtasks /query 失败: {ret.stderr}{Colors.END}")
        return [], 0, ""

    field_names = [
        "任务名称", "任务路径", "状态", "下次运行时间", "上次运行时间",
        "作者", "任务触发器", "任务要运行的任务", "程序脚本", "添加参数",
        "起始于", "注释", "任务状态", "空闲时间", "电源管理",
        "运行用户", "是否交互", "是否后台", "运行方式"
    ]
    stream = io.StringIO(ret.stdout)
    reader = csv.DictReader(stream, fieldnames=field_names)
    all_tasks = []
    for row in reader:
        clean_row = {k: row.get(k, "") for k in field_names}
        all_tasks.append(clean_row)

    # 写入全量 CSV 供留存分析
    try:
        with open(csv_output_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=field_names)
            writer.writeheader()
            writer.writerows(all_tasks)
    except Exception:
        pass

    risk_list = []
    for t in all_tasks:
        name = t.get("任务名称", "").strip()
        path = t.get("任务路径", "").strip()
        prog = t.get("程序脚本", "").strip().lower()
        args = t.get("添加参数", "").strip().lower()
        trigger = t.get("任务触发器", "")

        # 1. 过滤微软官方原生无害任务
        if is_safe_system_task(path, prog, args):
            continue

        score = 0
        risk_tags = []
        suspicious_paths = []

        # 2. 脏路径判定（高危）
        dirty_keywords = [r"\appdata\local", r"\appdata\roaming", r"\users\public", r"\windows\temp", r"\temp", "%temp%"]
        for dk in dirty_keywords:
            if dk in prog or dk in args:
                score += 40
                risk_tags.append("可疑临时/公用路径")
                # 记录可能的可执行程序路径
                suspicious_paths.append(t.get("程序脚本", "").strip())
                break

        # 3. 恶意命令行混淆特征
        if any(bad in args or bad in prog for bad in ["-enc", "-w hidden", "-windowstyle hidden", "downloadstring", "bypass", "mshta"]):
            score += 35
            risk_tags.append("隐蔽/混淆脚本命令行")

        # 4. 仿冒系统核心名
        if "svch0st" in prog or "scvhost" in prog:
            score += 30
            risk_tags.append("仿冒系统进程名")

        # 5. 高频/短周期触发器
        if "1分钟" in trigger or "5分钟" in trigger or "10分钟" in trigger:
            score += 20
            risk_tags.append("短周期保活拉起")

        if "登录时" in trigger or "系统启动时" in trigger:
            if score > 0: # 只有在存在其他可疑迹象时才计分，避免正常启动任务误报
                score += 15
                risk_tags.append("开机/登录自启")

        # 达到风险阈值
        if score >= 35:
            full_tn = (path if path.endswith("\\") else path + "\\") + name if path and path != "\\" else "\\" + name
            risk_list.append({
                **t,
                "full_task_name": full_tn,
                "risk_score": score,
                "risk_tag": "|".join(risk_tags),
                "suspicious_paths": suspicious_paths
            })

    return risk_list, len(all_tasks), os.path.abspath(csv_output_path)

def disable_tasks(risk_list):
    """批量禁用计划任务"""
    ok_cnt, fail_cnt = 0, 0
    for item in risk_list:
        tn = item["full_task_name"]
        print(f"  正在禁用: {tn}")
        ret = subprocess.run(
            ["schtasks", "/change", "/tn", tn, "/disable"],
            capture_output=True,
            encoding="gbk",
            errors="replace"
        )
        if ret.returncode == 0:
            print(f"  {Colors.GREEN}✅ 禁用成功: {tn}{Colors.END}")
            ok_cnt += 1
        else:
            print(f"  {Colors.RED}❌ 禁用失败 ({ret.returncode}): {ret.stderr.strip()}{Colors.END}")
            fail_cnt += 1
    return ok_cnt, fail_cnt

def delete_tasks(risk_list):
    """彻底删除计划任务"""
    ok_cnt, fail_cnt = 0, 0
    for item in risk_list:
        tn = item["full_task_name"]
        print(f"  正在物理删除任务: {tn}")
        ret = subprocess.run(
            ["schtasks", "/delete", "/tn", tn, "/f"],
            capture_output=True,
            encoding="gbk",
            errors="replace"
        )
        if ret.returncode == 0:
            print(f"  {Colors.GREEN}✅ 彻底删除成功: {tn}{Colors.END}")
            ok_cnt += 1
        else:
            print(f"  {Colors.RED}❌ 删除失败 ({ret.returncode}): {ret.stderr.strip()}{Colors.END}")
            fail_cnt += 1
    return ok_cnt, fail_cnt

def clean_tasks(interactive=False):
    """排查与处置计划任务"""
    risk_list, total, csv_path = scan_schtasks()
    print(f"{Colors.CYAN}[计划任务] 系统总计登记 {total} 条任务，已导出备份至: {csv_path}{Colors.END}")

    if not risk_list:
        print(f"{Colors.GREEN}[计划任务] 经过白名单智能过滤，未检测到高危银狐保活计划任务。{Colors.END}")
        return True, []

    print(f"\n{Colors.YELLOW}[计划任务] 发现 {len(risk_list)} 条高危保活计划任务：{Colors.END}")
    for idx, item in enumerate(risk_list, 1):
        print(f"  [{idx}] 任务名: {Colors.RED}{item['full_task_name']}{Colors.END}")
        print(f"      标签: {item['risk_tag']} (评分: {item['risk_score']})")
        print(f"      执行: {item['程序脚本']} {item['添加参数']}")
        print(f"      触发: {item['任务触发器']}\n")

    if interactive:
        print("请选择处置方式：")
        print("  [1] 一键彻底删除 (推荐，完全斩断木马保活)")
        print("  [2] 一键禁用 (保留配置，仅阻止自动拉起)")
        print("  [N] 跳过处置")
        choice = input("请输入选项 [1/2/N]: ").strip().upper()
        if choice == "1":
            ok, fail = delete_tasks(risk_list)
            print(f"\n{Colors.GREEN}已删除 {ok} 条，失败 {fail} 条{Colors.END}")
            return True, risk_list
        elif choice == "2":
            ok, fail = disable_tasks(risk_list)
            print(f"\n{Colors.GREEN}已禁用 {ok} 条，失败 {fail} 条{Colors.END}")
            return True, risk_list
        else:
            print(f"{Colors.YELLOW}[计划任务] 用户跳过处置。{Colors.END}")
            return False, risk_list

    # 非交互模式默认直接禁用
    disable_tasks(risk_list)
    return True, risk_list
