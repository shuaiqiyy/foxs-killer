import os
import re
import io
import csv
import subprocess

hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
whitelist = ['weishi.360.cn', 'www.360.cn','sd.360.cn']

def clean_hosts_whitelist(whitelist_domains):
    if not os.path.exists(hosts_path):
        print(f"Hosts文件不存在: {hosts_path}")
        return False
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
            if domain in line:
                should_remove = True
                removed.append(line.strip())
                break
        if not should_remove:
            new_lines.append(line)
    if not removed:
        print("[hosts] 未发现银狐相关域名劫持规则")
        return False
    try:
        with open(hosts_path, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)
        print(f"[hosts] 已删除 {len(removed)} 条劫持规则")
        return True
    except PermissionError:
        print("[hosts] 权限不足，请以管理员身份运行本脚本！")
        return False


def delete_policy(policy_guid: str):
    cmd = [
        "powershell.exe",
        "-Command",
        f"citool -rp '{policy_guid}'"
    ]
    res = subprocess.run(cmd, capture_output=True)
    stdout = res.stdout.decode("gbk", errors="ignore")
    stderr = res.stderr.decode("gbk", errors="ignore")
    ok = (res.returncode == 0)
    return ok, stdout, stderr, res.returncode


def find_malicious_policy():
    try:
        result = subprocess.run(
            ["powershell.exe", "-Command", "citool -lp"],
            capture_output=True
        )
        if result.returncode != 0:
            print("[CI策略] citool -lp 执行失败")
            return None
        output = result.stdout.decode('utf-8', errors='ignore')
        if '��' in output or output.count('�') > 10:
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
        print(f"[CI策略] 执行异常: {e}")
        return None

def CImain():
    res = find_malicious_policy()
    if res:
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
                        print(f"✅删除成功: {pid}")
                    else:
                        print(f"❌删除失败 rc={rc}")
                        print(f"stdout:{out}")
                        print(f"stderr:{err}")
                print("\n====全部删除操作执行完毕====")
                return
            elif ask.upper() == "N":
                print("已取消删除操作")
                return
            else:
                print("输入无效，请输入 Y 或者 N")
    else:
        print("\n[CI策略] 未检测到符合特征的恶意CI策略")

def disable_risk_tasks(risk_list):
    print("\n开始禁用风险计划任务……")
    ok_cnt = 0
    fail_cnt = 0
    for item in risk_list:
        path = item.get("任务路径", "").strip()
        name = item.get("任务名称", "").strip()
        if not name:
            continue
        if name.startswith("\\"):
            tn = name
        elif path and path != "\\":
            tn = (path if path.endswith("\\") else path + "\\") + name
        else:
            tn = "\\" + name
        print(f"\n正在禁用: {tn}")
        ret = subprocess.run(
            ["schtasks", "/change", "/tn", tn, "/disable"],
            capture_output=True,
            encoding="gbk",
            errors="replace"
        )
        if ret.returncode == 0:
            print(f"✅禁用成功: {tn}")
            ok_cnt += 1
        else:
            print(f"❌禁用失败 rc={ret.returncode}: {ret.stderr.strip()}")
            fail_cnt += 1
    print(f"\n====计划任务禁用完毕：成功 {ok_cnt} 条，失败 {fail_cnt} 条====")


def dump_schtasks_to_csv(csv_output_path="计划任务全量导出.csv"):
    cmd = [
        "schtasks",
        "/query",
        "/v",
        "/fo", "csv",
        "/nh"
    ]
    ret = subprocess.run(cmd, capture_output=True, encoding="gbk", errors="replace")
    if ret.returncode != 0:
        print(f"[错误] schtasks执行失败: {ret.stderr}")
        return 0, [], ""
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
    with open(csv_output_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=field_names)
        writer.writeheader()
        writer.writerows(all_tasks)
    risk_list = []
    for t in all_tasks:
        prog = t.get("程序脚本", "").lower()
        trigger = t.get("任务触发器", "")
        is_risk = False
        risk_tag = []
        if "登录时" in trigger:
            is_risk = True
            risk_tag.append("登录触发")
        if "系统启动时" in trigger:
            is_risk = True
            risk_tag.append("系统启动触发")
        if "1分钟" in trigger:
            is_risk = True
            risk_tag.append("延迟1分钟")
        if "5分钟" in trigger:
            is_risk = True
            risk_tag.append("延迟5分钟")
        if "10分钟" in trigger:
            is_risk = True
            risk_tag.append("延迟10分钟")
        if "appdata" in prog or "\\temp\\" in prog or "%temp%" in prog:
            is_risk = True
            risk_tag.append("可疑路径")

        if is_risk:
            risk_list.append({**t, "风险标签": "|".join(risk_tag)})
    if risk_list:
        print("\n======[计划任务风险项]======")
        for item in risk_list:
            print(f"[{item['风险标签']}] {item['任务路径']}{item['任务名称']}")
            print(f"    程序: {item['程序脚本']} {item['添加参数']}")
            print(f"    触发器: {item['任务触发器']}\n")
        while True:
            ask = input("\n是否一键禁用上述风险计划任务 [Y]Yes , [N]No：").strip()
            if ask.upper() == "Y":
                disable_risk_tasks(risk_list)
                break
            elif ask.upper() == "N":
                print("已跳过计划任务禁用，请自行手动处理")
                break
            else:
                print("输入无效，请输入 Y 或者 N")
    else:
        print("\n[计划任务] 未检测到风险项")

    return len(all_tasks), risk_list, os.path.abspath(csv_output_path)


if __name__ == "__main__":
    print("====银狐专杀工具====")
    print("====Maker:shuaiqiyy====")
    clean_hosts_whitelist(whitelist)
    CImain()
    total, risks, csvfile = dump_schtasks_to_csv()
    print(f"计划任务已保存至：{csvfile}，共 {total} 条任务")
    input("====全部清理流程执行完毕====")
