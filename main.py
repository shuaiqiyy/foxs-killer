import os
import re
import ctypes
import subprocess


# ========== 配置 ==========
hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
whitelist = ['weishi.360.cn', 'www.360.cn', 'sd.360.cn']

# ========== 辅助函数 ==========
def is_admin():
    """检查是否具有管理员权限"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def disable_and_stop_all_tasks():
    ps_script = """
    $tasks = Get-ScheduledTask
    $disable_ok = 0
    $disable_fail = 0
    $stop_ok = 0
    $stop_fail = 0
    $total = $tasks.Count
    $current = 0

    foreach ($t in $tasks) {
        $current++
        $fullName = $t.TaskPath + $t.TaskName
        Write-Progress -Activity "处理计划任务" -Status "正在处理: $fullName" -PercentComplete (($current / $total) * 100)

        # 1. 禁用任务
        try {
            Disable-ScheduledTask -InputObject $t -ErrorAction Stop | Out-Null
            $disable_ok++
        } catch {
            $disable_fail++
        }

        # 2. 尝试停止任务（双重机制）
        $stopped = $false
        try {
            Stop-ScheduledTask -InputObject $t -ErrorAction Stop | Out-Null
            $stop_ok++
            $stopped = $true
        } catch {
            # 备选方案：schtasks /end
            try {
                $taskPath = $t.TaskPath.TrimEnd('\')
                $taskName = $t.TaskName
                if ($taskPath -and $taskPath -ne "\") {
                    $fullTaskName = $taskPath + "\" + $taskName
                } else {
                    $fullTaskName = "\" + $taskName
                }
                & schtasks /end /tn $fullTaskName 2>$null
                if ($LASTEXITCODE -eq 0) {
                    $stop_ok++
                    $stopped = $true
                } else {
                    $stop_fail++
                }
            } catch {
                $stop_fail++
            }
        }
        # 每处理50个任务或最后一个任务时输出一行摘要
        if (($current % 50 -eq 0) -or ($current -eq $total)) {
            Write-Host "[进度] $current / $total  禁用成功:$disable_ok  停止成功:$stop_ok"
        }
    }

    Write-Host "STATS: $disable_ok $disable_fail $stop_ok $stop_fail"
    """

    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=300  # 给足时间处理大量任务
        )
        if result.returncode != 0:
            print("[错误] PowerShell 执行失败:", result.stderr)
            return 0, 0, 0, 0

        output = result.stdout
        lines = output.splitlines()

        # 查找 STATS 行
        stats_line = None
        for line in reversed(lines):
            if line.startswith("STATS:"):
                stats_line = line
                break

        if stats_line:
            parts = stats_line.split()
            if len(parts) >= 5:
                return int(parts[1]), int(parts[2]), int(parts[3]), int(parts[4])

        # 降级方案：从最后一行提取数字
        if lines:
            last_line = lines[-1]
            numbers = re.findall(r'\d+', last_line)
            if len(numbers) >= 4:
                return map(int, numbers[:4])

        print("[警告] 未能解析统计信息，原始输出末尾：", lines[-3:] if lines else "")
        return 0, 0, 0, 0

    except subprocess.TimeoutExpired:
        print("[错误] 命令执行超时")
        return 0, 0, 0, 0
    except Exception as e:
        print(f"[错误] 执行异常: {e}")
        return 0, 0, 0, 0

# ========== 2. CI策略处理  ==========
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

# ========== 3. Hosts修复（保持不变） ==========
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
                if re.search(rf'\b{re.escape(domain)}\b', line, re.IGNORECASE):
                    should_remove = True
                    removed.append(line.strip())
                    break

            if not should_remove:
                new_lines.append(line)

        if not removed:
            print("[hosts] 未发现银狐相关域名劫持规则")
            return False

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

# ========== 主程序 ==========
if __name__ == "__main__":
    print("=" * 50)
    print("银狐专杀工具")
    print("Maker: shuaiqiyy")
    print("=" * 50)

    if not is_admin():
        print("[警告] 未检测到管理员权限！")
        print("[警告] 计划任务禁用、CI策略删除和hosts修改可能需要管理员权限。")
        print("[警告] 请右键以管理员身份运行本脚本。\n")

    # 1. 计划任务
    print("\n[1/3] 禁用并强制停止所有计划任务...")
    dis_ok, dis_fail, stop_ok, stop_fail = disable_and_stop_all_tasks()
    print(f"[计划任务] 禁用成功: {dis_ok}，禁用失败: {dis_fail}；停止成功: {stop_ok}，停止失败: {stop_fail}")

    # 2. CI策略
    print("\n[2/3] 检查CI策略...")
    CImain()

    # 3. Hosts修复
    print("\n[3/3] 修复hosts文件...")
    clean_hosts_whitelist(whitelist)

    print("\n" + "=" * 50)
    print("全部清理流程执行完毕")
    print("=" * 50)
    input("按回车键退出...")
