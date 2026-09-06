import os
import re
import io
import csv
import subprocess
import ctypes
import sys

hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
whitelist = ['weishi.360.cn', 'www.360.cn', 'sd.360.cn']

def is_admin():
    """检查是否具有管理员权限"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def clean_hosts_whitelist(whitelist_domains):
    """清理hosts文件中的白名单域名"""
    if not os.path.exists(hosts_path):
        print(f"Hosts文件不存在: {hosts_path}")
        return False

    try:
        with open(hosts_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        new_lines = []
        removed = []

        for line in lines:
            if not line.strip() or line.strip().startswith('#'):
                new_lines.append(line)
                continue

            should_remove = False
            for domain in whitelist_domains:
                # 使用正则精确匹配域名，避免误删
                if re.search(rf'\b{re.escape(domain)}\b', line, re.IGNORECASE):
                    should_remove = True
                    removed.append(line.strip())
                    break

            if not should_remove:
                new_lines.append(line)

        if not removed:
            print("[hosts] 未发现银狐相关域名劫持规则")
            return False

        # 备份原文件
        backup_path = hosts_path + '.bak'
        if not os.path.exists(backup_path):
            with open(backup_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            print(f"[hosts] 已备份原文件到: {backup_path}")

        with open(hosts_path, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)

        print(f"[hosts] 已删除 {len(removed)} 条劫持规则")
        return True

    except PermissionError:
        print("[hosts] 权限不足，请以管理员身份运行本脚本！")
        return False
    except Exception as e:
        print(f"[hosts] 处理失败: {e}")
        return False

def delete_policy(policy_guid: str):
    """删除指定的CI策略"""
    try:
        cmd = ["powershell.exe", "-Command", f"citool -rp '{policy_guid}'"]
        res = subprocess.run(cmd, capture_output=True, timeout=30)
        stdout = res.stdout.decode("gbk", errors="ignore")
        stderr = res.stderr.decode("gbk", errors="ignore")
        return res.returncode == 0, stdout, stderr, res.returncode
    except subprocess.TimeoutExpired:
        return False, "", "命令执行超时", -1
    except Exception as e:
        return False, "", str(e), -1

def find_malicious_policy():
    """查找可疑的CI策略"""
    try:
        result = subprocess.run(
            ["powershell.exe", "-Command", "citool -lp"],
            capture_output=True, timeout=30
        )

        if result.returncode != 0:
            print("[CI策略] citool -lp 执行失败")
            return None

        output = None
        for encoding in ['utf-8', 'gbk', 'gb2312']:
            try:
                output = result.stdout.decode(encoding)
                if '策略' in output or 'Policy' in output:
                    break
            except:
                continue
        if output is None:
            output = result.stdout.decode('utf-8', errors='ignore')

        raw_lines = output.splitlines()
        found_blocks = []
        current_block_lines = []

        for line in raw_lines:
            if line.strip().startswith("策略:") or line.strip().startswith("Policy:"):
                if current_block_lines:
                    found_blocks.append("\r\n".join(current_block_lines))
                    current_block_lines = []
            current_block_lines.append(line)
        if current_block_lines:
            found_blocks.append("\r\n".join(current_block_lines))

        def get_field(text, key):
            patterns = [
                rf"{key}\s*[：:]\s*(.+?)(?=\r?\n|$)",
                rf"{key}\s*=\s*(.+?)(?=\r?\n|$)"
            ]
            for pat in patterns:
                m = re.search(pat, text, re.IGNORECASE)
                if m:
                    return m.group(1).strip()
            return None

        policy_list = []
        for blk in found_blocks:
            plat = get_field(blk, "平台策略") or get_field(blk, "Platform")
            signed = get_field(blk, "策略已签名") or get_field(blk, "Signed")
            enforce = get_field(blk, "当前强制执行") or get_field(blk, "Enforced")

            if enforce and enforce.lower() == "true" and plat and plat.lower() == "false" and signed and signed.lower() == "false":
                policy = {
                    "id": get_field(blk, "策略 ID") or get_field(blk, "Policy ID"),
                    "name": get_field(blk, "好记的名称") or get_field(blk, "Friendly Name"),
                    "enforce": enforce,
                    "auth": get_field(blk, "授权") or get_field(blk, "Authorization"),
                    "plat": plat,
                    "signed": signed
                }
                if policy["id"]:
                    policy_list.append(policy)

        return policy_list

    except subprocess.TimeoutExpired:
        print("[CI策略] 命令执行超时")
        return None
    except Exception as e:
        print(f"[CI策略] 执行异常: {e}")
        return None

def CImain():
    """CI策略清理主函数"""
    res = find_malicious_policy()
    if not res:
        print("\n[CI策略] 未检测到符合特征的恶意CI策略")
        return

    print(f"\n[CI策略] 检测到 {len(res)} 条疑似银狐恶意策略")
    for i, p in enumerate(res, 1):
        print(f"[{i}] ID:{p['id']} | {p['name']} | 强制执行:{p['enforce']} | 平台策略:{p['plat']} | 签名:{p['signed']}")

    while True:
        ask = input("\n是否删除上述恶意策略 [Y]Yes , [N]No：").strip()
        if ask.upper() == "Y":
            print("\n开始执行恶意策略删除……")
            for pol in res:
                pid = pol["id"]
                print(f"\n正在删除: {pid} | {pol['name']}")
                ok, out, err, rc = delete_policy(pid)
                if ok:
                    print(f"删除成功: {pid}")
                else:
                    print(f"删除失败 rc={rc}")
                    if out:
                        print(f"stdout: {out}")
                    if err:
                        print(f"stderr: {err}")
            print("\n====全部删除操作执行完毕====")
            return
        elif ask.upper() == "N":
            print("已取消删除操作")
            return
        else:
            print("输入无效，请输入 Y 或者 N")

def disable_risk_tasks(selected_tasks):
    """禁用选中的计划任务"""
    if not selected_tasks:
        print("没有要禁用的任务。")
        return

    print("\n开始禁用选中的计划任务……")
    ok_cnt = 0
    fail_cnt = 0

    for task in selected_tasks:
        # 获取完整任务路径
        task_path = task.get("任务路径", "").strip()
        task_name = task.get("任务名称", "").strip()
        if not task_name:
            continue

        # 构建完整路径
        if task_path and task_path != "\\":
            if not task_path.startswith("\\"):
                task_path = "\\" + task_path
            if not task_path.endswith("\\"):
                task_path += "\\"
            full_name = task_path + task_name
        else:
            full_name = "\\" + task_name

        full_name = re.sub(r'\\+', '\\', full_name)  # 清理多余反斜杠
        print(f"\n正在禁用: {full_name}")

        try:
            ret = subprocess.run(
                ["schtasks", "/change", "/tn", full_name, "/disable"],
                capture_output=True, encoding="gbk", errors="replace", timeout=10
            )
            if ret.returncode == 0:
                print(f"禁用成功: {full_name}")
                ok_cnt += 1
            else:
                print(f"禁用失败 rc={ret.returncode}: {ret.stderr.strip()}")
                fail_cnt += 1
        except subprocess.TimeoutExpired:
            print(f"禁用超时: {full_name}")
            fail_cnt += 1
        except Exception as e:
            print(f"禁用异常: {full_name} - {e}")
            fail_cnt += 1

    print(f"\n====计划任务禁用完毕：成功 {ok_cnt} 条，失败 {fail_cnt} 条====")

def dump_schtasks_to_csv(csv_output_path="计划任务全量导出.csv"):
    """导出计划任务并识别风险项"""
    print("\n正在获取计划任务列表...")

    # 使用 /v /fo csv 获取详细列表
    cmd = ["schtasks", "/query", "/v", "/fo", "csv"]
    try:
        ret = subprocess.run(cmd, capture_output=True, encoding="gbk", errors="replace", timeout=30)
    except subprocess.TimeoutExpired:
        print("[错误] schtasks 命令超时")
        return 0, [], ""
    except Exception as e:
        print(f"[错误] 执行 schtasks 失败: {e}")
        return 0, [], ""

    if ret.returncode != 0:
        print(f"[错误] schtasks 执行失败: {ret.stderr}")
        return 0, [], ""

    # 解析CSV
    try:
        reader = csv.DictReader(io.StringIO(ret.stdout))
        # 获取实际列名，用于后续匹配
        fieldnames = reader.fieldnames if reader.fieldnames else []
        # 寻找关键字段的实际名称（兼容不同语言环境）
        name_key = next((f for f in fieldnames if f in ["任务名称", "TaskName"]), "任务名称")
        path_key = next((f for f in fieldnames if f in ["任务路径", "TaskPath"]), "任务路径")
        trigger_key = next((f for f in fieldnames if f in ["任务触发器", "Trigger"]), "任务触发器")
        script_key = next((f for f in fieldnames if f in ["程序脚本", "Task To Run"]), "程序脚本")
        args_key = next((f for f in fieldnames if f in ["添加参数", "Arguments"]), "添加参数")

        tasks = []
        for row in reader:
            task = {
                "任务名称": row.get(name_key, "").strip(),
                "任务路径": row.get(path_key, "").strip(),
                "任务触发器": row.get(trigger_key, "").strip(),
                "程序脚本": row.get(script_key, "").strip(),
                "添加参数": row.get(args_key, "").strip(),
                # 原始行数据保留，方便查看
                "原始数据": row
            }
            tasks.append(task)

        # 写入CSV文件（包含所有任务）
        with open(csv_output_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows([t["原始数据"] for t in tasks])

        # 识别风险任务
        risk_list = []
        for task in tasks:
            prog = task.get("程序脚本", "").lower()
            trigger = task.get("任务触发器", "")
            is_risk = False
            risk_tags = []

            # 触发器风险
            if "登录时" in trigger:
                is_risk = True
                risk_tags.append("登录触发")
            if "系统启动时" in trigger:
                is_risk = True
                risk_tags.append("启动触发")
            if re.search(r"延迟\s*(1|5|10)\s*分钟", trigger):
                is_risk = True
                risk_tags.append("短延迟触发")

            # 路径风险
            suspicious_paths = [
                "appdata", "\\temp\\", "%temp%", "\\roaming\\",
                "\\local\\temp", "\\downloads\\", "\\desktop\\",
                "\\documents\\", "\\public\\", "\\tmp\\"
            ]
            for path in suspicious_paths:
                if path in prog:
                    is_risk = True
                    risk_tags.append(f"可疑路径:{path}")
                    break

            # 脚本扩展名风险
            suspicious_exts = ['.ps1', '.vbs', '.bat', '.cmd', '.js', '.jse', '.wsf', '.hta', '.exe']
            for ext in suspicious_exts:
                if prog.endswith(ext):
                    # 排除常见系统程序
                    if not any(safe in prog for safe in ["\\windows\\", "\\program files\\", "\\program files (x86)\\"]):
                        is_risk = True
                        risk_tags.append(f"脚本/可执行文件:{ext}")
                    break

            if is_risk:
                task["风险标签"] = "|".join(risk_tags)
                risk_list.append(task)

        # 显示风险任务
        if risk_list:
            print("\n======[计划任务风险项]======")
            for i, task in enumerate(risk_list, 1):
                print(f"[{i}] {task.get('任务路径','')}{task.get('任务名称','')}")
                print(f"    程序: {task.get('程序脚本','')} {task.get('添加参数','')}")
                print(f"    触发器: {task.get('任务触发器','')}")
                print(f"    风险标签: {task['风险标签']}\n")

            # 用户选择要禁用的任务
            print("请选择要禁用的任务（输入序号，用逗号或短横线分隔，或输入 'all' 全部禁用，'none' 跳过）：")
            choice = input("> ").strip().lower()
            if choice == 'none':
                print("已跳过计划任务禁用。")
            elif choice == 'all':
                disable_risk_tasks(risk_list)
            else:
                # 解析用户输入
                selected_indices = set()
                parts = choice.split(',')
                for part in parts:
                    part = part.strip()
                    if '-' in part:
                        try:
                            start, end = map(int, part.split('-'))
                            selected_indices.update(range(start, end + 1))
                        except:
                            print(f"忽略无效的范围: {part}")
                    elif part.isdigit():
                        selected_indices.add(int(part))
                # 筛选有效索引
                selected_tasks = [risk_list[i-1] for i in sorted(selected_indices) if 1 <= i <= len(risk_list)]
                if selected_tasks:
                    disable_risk_tasks(selected_tasks)
                else:
                    print("未选择任何有效任务。")
        else:
            print("\n[计划任务] 未检测到风险项")

        return len(tasks), risk_list, os.path.abspath(csv_output_path)

    except Exception as e:
        print(f"[错误] 解析计划任务数据时出错: {e}")
        return 0, [], ""

if __name__ == "__main__":
    print("=" * 50)
    print("银狐专杀工具")
    print("Maker: shuaiqiyy")
    print("=" * 50)

    # 管理员权限检查
    if not is_admin():
        print("[警告] 未检测到管理员权限！")
        print("[警告] 计划任务禁用、CI策略删除和hosts修改可能需要管理员权限。")
        print("[警告] 请右键以管理员身份运行本脚本。\n")

    # 执行顺序：1.计划任务 2.CI策略 3.hosts
    print("\n[1/3] 检查计划任务...")
    total, risks, csvfile = dump_schtasks_to_csv()
    if csvfile:
        print(f"\n计划任务全量导出已保存至：{csvfile}，共 {total} 条任务")

    print("\n[2/3] 检查CI策略...")
    CImain()

    print("\n[3/3] 修复hosts文件...")
    clean_hosts_whitelist(whitelist)

    print("\n" + "=" * 50)
    print("全部清理流程执行完毕")
    print("=" * 50)
    input("按回车键退出...")
