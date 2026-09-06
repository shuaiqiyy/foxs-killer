# ======================================================================
# foxs-killer (银狐病毒专杀与应急修复脚本 v2.0 - 纯原生 PowerShell 版)
# 适用平台: Windows 7 / 10 / 11 全系 (真正零依赖，无需安装 Python)
# 运行方式: powershell -c "irm <短链接>|iex" 或右键管理员运行
# ======================================================================

[CmdletBinding()]
param(
    [switch]$Scan,
    [switch]$CleanAll
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# 1. 自动管理员权限检测与智能提权
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[*] 检测到当前非管理员权限，正在申请 UAC 管理员提权..." -ForegroundColor Yellow
    try {
        if ($PSCommandPath) {
            Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -ErrorAction Stop
            exit
        } else {
            # 若为 irm ... | iex 内存执行模式，将脚本载荷暂存至临时文件并以管理员拉起
            $tempBoot = "$env:TEMP\fox_boot.ps1"
            $scriptContent = $MyInvocation.MyCommand.ScriptBlock.ToString()
            if ($scriptContent) {
                Set-Content -Path $tempBoot -Value $scriptContent -Encoding UTF8
                Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$tempBoot`"" -ErrorAction Stop
                exit
            }
        }
    } catch {
        Write-Host "[!] 自动提权弹窗被取消或环境不支持交互，将在当前权限下运行（涉及 Hosts、底层策略等操作需管理员权限）..." -ForegroundColor DarkYellow
    }
}

function Show-Banner {
    Clear-Host
    Write-Host @"
======================================================================
  ______          _        _  ___ _ _           
 |  ____|        | |      | |/ (_) | |          
 | |__ _____  ___| | _____| ' / _| | | ___ _ __ 
 |  __/ _ \ \/ / | |/ / __|  < | | | |/ _ \ '__|
 | | | (_) >  < _|   <\__ \ . \| | | |  __/ |   
 |_|  \___/_/\_(_)_|\_\___/_|\_\_|_|_|\___|_|   
======================================================================
  银狐（Silver Fox / ValleyRAT）病毒应急专杀系统 v2.0
  [纯原生 PowerShell 内存直跑版 · 真正零依赖 · 开源透明]
======================================================================
"@ -ForegroundColor Cyan
}

# ==================== 模块 1: Hosts 域名劫持修复 ====================
$HostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$KnownSecurityDomains = @(
    '360.cn', '360safe.com', '360.com', 'qihucdn.com', 'weishi.360.cn', 'sd.360.cn',
    'huorong.cn', 'down.huorong.cn', 'api.huorong.cn', 'bbs.huorong.cn',
    'guanjia.qq.com', 'pc.qq.com', 'pcmgr.qq.com', 'threatbook.cn', 'threatbook.io',
    'duba.net', 'ijinshan.com', 'kingsoft.com', 'smartscreen.microsoft.com',
    'definitionupdates.microsoft.com', 'windowsupdate.com', 'qianxin.com', 'sangfor.com.cn'
)

function Scan-HostsFile {
    $hijacked = @()
    if (-not (Test-Path $HostsPath)) { return $hijacked }
    $lines = Get-Content $HostsPath -ErrorAction SilentlyContinue
    $lineNo = 1
    foreach ($line in $lines) {
        $s = $line.Trim()
        if ($s -and -not $s.StartsWith('#')) {
            $isMatch = $false
            foreach ($d in $KnownSecurityDomains) {
                if ($s.ToLower().Contains($d)) {
                    $hijacked += [PSCustomObject]@{ LineNo = $lineNo; Content = $s; Domain = $d }
                    $isMatch = $true
                    break
                }
            }
            if (-not $isMatch -and ($s.StartsWith('127.0.0.1') -or $s.StartsWith('0.0.0.0'))) {
                if ($s -match 'antivirus|defender|360|huorong|guanjia|duba|threatbook') {
                    $hijacked += [PSCustomObject]@{ LineNo = $lineNo; Content = $s; Domain = 'Heuristic' }
                }
            }
        }
        $lineNo++
    }
    return $hijacked
}

function Repair-HostsFile {
    param([switch]$Interactive)
    $risks = Scan-HostsFile
    if ($risks.Count -eq 0) {
        Write-Host "[Hosts] 未发现银狐域名劫持规则，状态正常。" -ForegroundColor Green
        return
    }
    Write-Host "`n[Hosts] 发现 $($risks.Count) 条安全厂商域名被劫持拦截:" -ForegroundColor Yellow
    $risks | ForEach-Object { Write-Host "  行 $($_.LineNo): $($_.Content)" -ForegroundColor Red }

    if ($Interactive) {
        $ans = Read-Host "`n是否立即清除上述 Hosts 劫持项？ [Y/N]"
        if ($ans -notmatch '^[Yy]$') { return }
    }

    # 备份 Hosts
    $bak = "$HostsPath.bak_" + (Get-Date -Format "yyyyMMdd_HHmmss")
    Copy-Item $HostsPath $bak -Force
    Write-Host "[Hosts] 已自动备份原始文件至: $bak" -ForegroundColor Cyan

    $lines = Get-Content $HostsPath
    $riskContents = $risks | ForEach-Object { $_.Content }
    $cleanLines = $lines | Where-Object { $_.Trim() -notin $riskContents }
    $cleanLines | Set-Content $HostsPath -Encoding UTF8
    ipconfig /flushdns | Out-Null
    Write-Host "[Hosts] ✅ 成功清除 $($risks.Count) 条劫持规则并已刷新 DNS 缓存！" -ForegroundColor Green
}

# ==================== 模块 2: CI / WDAC 恶意底层策略清除 ====================
function Scan-CiPolicies {
    $malicious = @()
    if (-not $isAdmin) { return $malicious }
    if (Get-Command citool -ErrorAction SilentlyContinue) {
        try {
            $out = "" | citool -lp 2>$null
            $blocks = ($out -join "`n") -split '(?=策略:)'
            foreach ($blk in $blocks) {
                if ($blk -match '当前强制执行\s*:\s*true' -and $blk -match '平台策略\s*:\s*false' -and $blk -match '策略已签名\s*:\s*false') {
                    $id = if ($blk -match '策略 ID\s*:\s*([^\r\n]+)') { $matches[1].Trim() } else { "" }
                    $name = if ($blk -match '好记的名称\s*:\s*([^\r\n]+)') { $matches[1].Trim() } else { "" }
                    if ($id) {
                        $malicious += [PSCustomObject]@{ Id = $id; Name = $name }
                    }
                }
            }
        } catch {}
    }
    return $malicious
}

function Repair-CiPolicies {
    param([switch]$Interactive)
    $pols = Scan-CiPolicies
    if ($pols.Count -eq 0) {
        Write-Host "[CI策略] 未检测到符合银狐特征的未签名恶意 CI 策略。" -ForegroundColor Green
        return
    }
    Write-Host "`n[CI策略] 检测到 $($pols.Count) 条阻止杀软运行的恶意 WDAC 策略:" -ForegroundColor Yellow
    $pols | ForEach-Object { Write-Host "  - 策略 ID: $($_.Id) | 名称: $($_.Name)" -ForegroundColor Red }

    if ($Interactive) {
        $ans = Read-Host "`n是否移除上述恶意 CI 策略？ [Y/N]"
        if ($ans -notmatch '^[Yy]$') { return }
    }

    foreach ($p in $pols) {
        Write-Host "  正在移除策略: $($p.Id)..." -ForegroundColor Cyan
        "" | citool -rp "'$($p.Id)'" 2>$null
        Write-Host "  ✅ 策略注销完成: $($p.Id)" -ForegroundColor Green
    }
    Write-Host "[CI策略] 策略清理完毕，建议清理完成后重启计算机以使内核策略注销。" -ForegroundColor Green
}

# ==================== 模块 3: 注册表防御对抗排查与修复 ====================
function Scan-RegistryThreats {
    $ifeoList = @()
    $disallowList = @()
    $defenderList = @()

    # 1. 扫描 IFEO 劫持
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    )
    $legitDbg = @('notepad3.exe', 'notepad++.exe', 'vsjitdebugger.exe', 'windbg.exe', 'x64dbg.exe', 'code.exe')
    foreach ($rp in $regPaths) {
        if (Test-Path $rp) {
            Get-ChildItem $rp -ErrorAction SilentlyContinue | ForEach-Object {
                $dbg = (Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
                if ($dbg) {
                    $isLegit = $false
                    foreach ($ld in $legitDbg) { if ($dbg.ToLower().Contains($ld)) { $isLegit = $true; break } }
                    if (-not $isLegit) {
                        $ifeoList += [PSCustomObject]@{ Target = $_.PSChildName; Debugger = $dbg; Path = $_.PSPath }
                    }
                }
            }
        }
    }

    # 2. 扫描 DisallowRun
    $disKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"
    )
    foreach ($dk in $disKeys) {
        if (Test-Path $dk) {
            $props = Get-ItemProperty $dk -ErrorAction SilentlyContinue
            $banned = ($props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { $_.Value })
            if ($banned) {
                $disallowList += [PSCustomObject]@{ KeyPath = $dk; BannedApps = $banned }
            }
        }
    }

    # 3. 扫描 Windows Defender 禁用项
    $defKeys = @(
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name = "DisableAntiSpyware" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableRealtimeMonitoring" }
    )
    foreach ($dk in $defKeys) {
        if (Test-Path $dk.Path) {
            $val = (Get-ItemProperty $dk.Path -Name $dk.Name -ErrorAction SilentlyContinue).$($dk.Name)
            if ($val -eq 1) {
                $defenderList += [PSCustomObject]@{ Path = $dk.Path; Name = $dk.Name }
            }
        }
    }

    return @{ IFEO = $ifeoList; Disallow = $disallowList; Defender = $defenderList }
}

function Repair-RegistryThreats {
    param([switch]$Interactive)
    $res = Scan-RegistryThreats
    $tot = $res.IFEO.Count + $res.Disallow.Count + $res.Defender.Count
    if ($tot -eq 0) {
        Write-Host "[注册表策略] IFEO劫持、DisallowRun限制与Defender策略状态正常。" -ForegroundColor Green
        return
    }

    if ($res.IFEO.Count -gt 0) {
        Write-Host "`n[IFEO劫持] 检测到 $($res.IFEO.Count) 个程序启动被恶意劫持:" -ForegroundColor Yellow
        $res.IFEO | ForEach-Object { Write-Host "  - 目标: $($_.Target) -> 劫持至: $($_.Debugger)" -ForegroundColor Red }
    }
    if ($res.Disallow.Count -gt 0) {
        Write-Host "`n[DisallowRun] 检测到系统启用了杀软禁止运行黑名单:" -ForegroundColor Yellow
        $res.Disallow | ForEach-Object { Write-Host "  - 位置: $($_.KeyPath) 拦截数: $($_.BannedApps.Count)" -ForegroundColor Red }
    }
    if ($res.Defender.Count -gt 0) {
        Write-Host "`n[Defender被压制] 检测到 Windows Defender 实时防护被注册表策略关闭:" -ForegroundColor Yellow
        $res.Defender | ForEach-Object { Write-Host "  - 策略项: $($_.Name) = 1" -ForegroundColor Red }
    }

    if ($Interactive) {
        $ans = Read-Host "`n是否立即修复上述注册表限制与劫持？ [Y/N]"
        if ($ans -notmatch '^[Yy]$') { return }
    }

    # 修复 IFEO
    foreach ($item in $res.IFEO) {
        Remove-ItemProperty -Path $item.Path -Name Debugger -Force -ErrorAction SilentlyContinue
        Write-Host "  ✅ 成功解除 IFEO 劫持: $($item.Target)" -ForegroundColor Green
    }
    # 修复 DisallowRun
    foreach ($item in $res.Disallow) {
        $parent = Split-Path $item.KeyPath -Parent
        Remove-ItemProperty -Path $parent -Name DisallowRun -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $item.KeyPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  ✅ 成功解除 DisallowRun 软件禁止运行黑名单" -ForegroundColor Green
    }
    # 修复 Defender
    foreach ($item in $res.Defender) {
        Remove-ItemProperty -Path $item.Path -Name $item.Name -Force -ErrorAction SilentlyContinue
        Write-Host "  ✅ 成功恢复 Defender 策略: $($item.Name)" -ForegroundColor Green
    }
}

# ==================== 模块 4: 自启动驻留项排查 ====================
function Scan-StartupThreats {
    $risks = @()
    $runPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )
    $dirtyKeywords = @('\appdata\local\temp', '\appdata\roaming\temp', '\users\public', '\windows\temp', '\onedrive\cache')
    $safeApps = @('\appdata\local\microsoft\onedrive\onedrive.exe', '\appdata\local\microsoft\teams', '\appdata\local\programs\')

    foreach ($rp in $runPaths) {
        if (Test-Path $rp) {
            $props = Get-ItemProperty $rp -ErrorAction SilentlyContinue
            foreach ($prop in $props.PSObject.Properties) {
                if ($prop.Name -match '^PS') { continue }
                $val = ([string]$prop.Value).ToLower()
                $isDirty = $false
                foreach ($dk in $dirtyKeywords) {
                    if ($val.Contains($dk)) { $isDirty = $true; break }
                }
                if ($isDirty -or $val.Contains("-enc ") -or $val.Contains("-w hidden") -or $val.Contains("svch0st")) {
                    $isSafe = $false
                    foreach ($sa in $safeApps) { if ($val.Contains($sa) -and -not $isDirty) { $isSafe = $true; break } }
                    if (-not $isSafe) {
                        $risks += [PSCustomObject]@{ RegPath = $rp; Name = $prop.Name; Command = $prop.Value }
                    }
                }
            }
        }
    }
    return $risks
}

function Repair-StartupThreats {
    param([switch]$Interactive)
    $risks = Scan-StartupThreats
    if ($risks.Count -eq 0) {
        Write-Host "[自启动项] 未发现符合银狐特征的高危临时目录自启动项。" -ForegroundColor Green
        return
    }
    Write-Host "`n[自启动项] 发现 $($risks.Count) 项高危自启动项:" -ForegroundColor Yellow
    $risks | ForEach-Object { Write-Host "  - [$($_.Name)] 命令: $($_.Command)" -ForegroundColor Red }

    if ($Interactive) {
        $ans = Read-Host "`n是否清除上述风险自启动项？ [Y/N]"
        if ($ans -notmatch '^[Yy]$') { return }
    }
    foreach ($r in $risks) {
        Remove-ItemProperty -Path $r.RegPath -Name $r.Name -Force -ErrorAction SilentlyContinue
        Write-Host "  ✅ 成功删除启动项: $($r.Name)" -ForegroundColor Green
    }
}

# ==================== 模块 5: 计划任务排查与处置 ====================
function Scan-ScheduledTaskThreats {
    $risks = @()
    $allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    $dirtyWords = @('\appdata\local\temp', '\appdata\roaming\temp', '\users\public', '\windows\temp', '\onedrive\cache')

    foreach ($t in $allTasks) {
        $taskPath = $t.TaskPath.ToLower()
        $taskName = $t.TaskName.ToLower()
        $actions = $t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }
        $actionStr = ($actions -join " ").ToLower()

        # 过滤微软原生白名单
        if ($taskPath.StartsWith('\microsoft\windows') -and -not ($actionStr -match '-enc|hidden|downloadstring|bypass')) {
            continue
        }
        # 过滤官方 OneDrive 启动任务
        if ($taskName.Contains('onedrive startup task') -and $actionStr.Contains('\microsoft\onedrive') -and -not $actionStr.Contains('\cache')) {
            continue
        }

        $isRisk = $false
        foreach ($dw in $dirtyWords) {
            if ($actionStr.Contains($dw)) { $isRisk = $true; break }
        }
        if ($actionStr -match '-enc\s+|-w\s+hidden|downloadstring|bypass|svch0st') {
            $isRisk = $true
        }

        if ($isRisk) {
            $risks += [PSCustomObject]@{
                TaskPath = $t.TaskPath
                TaskName = $t.TaskName
                Action   = $actionStr
                FullTask = ($t.TaskPath.TrimEnd('\') + '\' + $t.TaskName)
            }
        }
    }
    return $risks
}

function Repair-ScheduledTasks {
    param([switch]$Interactive)
    $risks = Scan-ScheduledTaskThreats
    if ($risks.Count -eq 0) {
        Write-Host "[计划任务] 智能白名单过滤后，未检测到高危保活计划任务。" -ForegroundColor Green
        return
    }
    Write-Host "`n[计划任务] 发现 $($risks.Count) 条高危保活任务:" -ForegroundColor Yellow
    $risks | ForEach-Object {
        Write-Host "  - 任务: $($_.FullTask)" -ForegroundColor Red
        Write-Host "    执行: $($_.Action)" -ForegroundColor DarkGray
    }

    if ($Interactive) {
        Write-Host "`n请选择处置方式:"
        Write-Host "  [1] 一键彻底删除 (推荐)"
        Write-Host "  [2] 仅禁用任务"
        Write-Host "  [N] 跳过处置"
        $choice = Read-Host "请输入 [1/2/N]"
        if ($choice -eq '1') {
            foreach ($r in $risks) {
                Unregister-ScheduledTask -TaskPath $r.TaskPath -TaskName $r.TaskName -Confirm:$false -ErrorAction SilentlyContinue
                Write-Host "  ✅ 成功物理删除计划任务: $($r.FullTask)" -ForegroundColor Green
            }
        } elseif ($choice -eq '2') {
            foreach ($r in $risks) {
                Disable-ScheduledTask -TaskPath $r.TaskPath -TaskName $r.TaskName -ErrorAction SilentlyContinue | Out-Null
                Write-Host "  ✅ 已禁用计划任务: $($r.FullTask)" -ForegroundColor Green
            }
        }
    } else {
        foreach ($r in $risks) {
            Disable-ScheduledTask -TaskPath $r.TaskPath -TaskName $r.TaskName -ErrorAction SilentlyContinue | Out-Null
        }
    }
}

# ==================== 模块 6: 银狐活跃木马进程识别与强杀 ====================
function Scan-ProcessThreats {
    $risks = @()
    $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    $dirtyRoots = @('\appdata\local\temp', '\users\public', '\windows\temp')
    $fakeNames = @('svch0st.exe', 'scvhost.exe', 'csrsss.exe', 'lsasss.exe', 'taskmgrr.exe')

    foreach ($p in $procs) {
        $exe = [string]$p.ExecutablePath
        $cmd = [string]$p.CommandLine
        $pName = [string]$p.Name
        $pidNum = $p.ProcessId

        if (-not $exe) { continue }
        $exeLower = $exe.ToLower()
        $nameLower = $pName.ToLower()

        # 白名单忽略核心系统目录正规程序
        if ($exeLower.StartsWith("c:\program files") -or ($exeLower.StartsWith("c:\windows\system32") -and $nameLower -notin $fakeNames)) {
            continue
        }

        $isThreat = $false
        $reason = ""

        if ($fakeNames -contains $nameLower) {
            $isThreat = $true
            $reason = "仿冒系统进程名 ($nameLower)"
        } elseif ($nameLower -eq 'svchost.exe' -and -not $exeLower.StartsWith('c:\windows\system32')) {
            $isThreat = $true
            $reason = "非系统目录伪装 svchost 进程"
        } else {
            foreach ($dr in $dirtyRoots) {
                if ($exeLower.Contains($dr)) {
                    $isThreat = $true
                    $reason = "运行于敏感临时脏路径 ($dr)"
                    break
                }
            }
        }

        if ($isThreat) {
            $risks += [PSCustomObject]@{
                ProcessId = $pidNum
                Name      = $pName
                Path      = $exe
                Reason    = $reason
            }
        }
    }
    return $risks
}

function Repair-ProcessThreats {
    param([switch]$Interactive)
    $risks = Scan-ProcessThreats
    if ($risks.Count -eq 0) {
        Write-Host "[活跃进程] 未检测到银狐特征高危活跃进程。" -ForegroundColor Green
        return
    }
    Write-Host "`n[活跃进程] 警报！检测到 $($risks.Count) 个疑似银狐木马活跃进程:" -ForegroundColor Yellow
    $risks | ForEach-Object {
        Write-Host "  - 进程: $($_.Name) (PID: $($_.ProcessId))" -ForegroundColor Red
        Write-Host "    路径: $($_.Path)"
        Write-Host "    特征: $($_.Reason)" -ForegroundColor DarkYellow
    }

    if ($Interactive) {
        $ans = Read-Host "`n是否立即强行终止上述高危木马进程？ [Y/N]"
        if ($ans -notmatch '^[Yy]$') { return }
    }
    foreach ($r in $risks) {
        Stop-Process -Id $r.ProcessId -Force -ErrorAction SilentlyContinue
        Write-Host "  ✅ 成功终止恶意进程: $($r.Name) (PID: $($r.ProcessId))" -ForegroundColor Green
    }
}

# ==================== 模块 7: 网络代理与 PAC 劫持重置 ====================
function Repair-NetworkProxy {
    param([switch]$Interactive)
    $inetPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    if (Test-Path $inetPath) {
        $props = Get-ItemProperty $inetPath
        $pEnable = $props.ProxyEnable
        $pServer = $props.ProxyServer
        $pacUrl = $props.AutoConfigURL

        if (($pEnable -eq 1 -and $pServer) -or $pacUrl) {
            Write-Host "`n[网络代理] 检测到系统网络代理被修改或存在 PAC 劫持:" -ForegroundColor Yellow
            if ($pServer) { Write-Host "  - 代理服务器: $pServer" -ForegroundColor Red }
            if ($pacUrl)  { Write-Host "  - PAC自动脚本: $pacUrl" -ForegroundColor Red }

            if ($Interactive) {
                $ans = Read-Host "`n是否重置网络代理为默认直连？ [Y/N]"
                if ($ans -notmatch '^[Yy]$') { return }
            }
            Set-ItemProperty -Path $inetPath -Name ProxyEnable -Value 0
            Remove-ItemProperty -Path $inetPath -Name AutoConfigURL -Force -ErrorAction SilentlyContinue
            Write-Host "[网络代理] ✅ 已重置网络代理为直连模式并清除 PAC 脚本！" -ForegroundColor Green
            return
        }
    }
    Write-Host "[网络代理] 系统代理与 PAC 规则正常，未开启异常代理。" -ForegroundColor Green
}

# ==================== 全盘体检与一键急救总线 ====================
function Run-FullDiagnosis {
    Write-Host "`n==================== [系统深度安全体检] ====================" -ForegroundColor Magenta
    Write-Host "[*] 正在扫描分析系统环境，请稍候...`n"

    $h = Scan-HostsFile
    $p = Scan-CiPolicies
    $r = Scan-RegistryThreats
    $s = Scan-StartupThreats
    $t = Scan-ScheduledTaskThreats
    $proc = Scan-ProcessThreats

    Write-Host "----------- 体检结果汇总 -----------" -ForegroundColor White
    function Format-Item($name, $count, $detail="") {
        if ($count -gt 0) {
            Write-Host ("  [!] {0,-18}: 发现 {1} 项高危威胁 {2}" -f $name, $count, $detail) -ForegroundColor Red
        } else {
            Write-Host ("  [✓] {0,-18}: 正常 (未检出威胁)" -f $name) -ForegroundColor Green
        }
    }

    Format-Item "内存活跃进程" $proc.Count "(可疑木马/白利用进程)"
    Format-Item "保活计划任务" $t.Count "(开机/登录循环保活任务)"
    Format-Item "自启动项驻留" $s.Count "(临时脏路径自启动项)"
    Format-Item "Hosts 域名劫持" $h.Count "(杀软/安全官网域名被屏蔽)"
    Format-Item "CI/WDAC策略压制" $p.Count "(杀软被底层代码完整性策略拦截)"
    Format-Item "IFEO 映像劫持" $r.IFEO.Count "(任务管理器/杀软启动被篡改)"
    Format-Item "DisallowRun 限制" $r.Disallow.Count "(程序禁止运行黑名单)"
    Format-Item "Defender防护压制" $r.Defender.Count "(实时防护被注册表强制关闭)"
    Write-Host "------------------------------------" -ForegroundColor White

    $total = $proc.Count + $t.Count + $s.Count + $h.Count + $p.Count + $r.IFEO.Count + $r.Disallow.Count + $r.Defender.Count
    if ($total -gt 0) {
        Write-Host "`n👉 警告：当前系统检出 $total 处银狐木马典型对抗或驻留项！建议立即执行「一键极速急救」。`n" -ForegroundColor Yellow
    } else {
        Write-Host "`n🎉 恭喜！当前系统未发现银狐木马已知特征，安全状态良好。`n" -ForegroundColor Green
    }
}

function Run-OneClickCure {
    Write-Host "`n==================== [执行一键全流程急救] ====================" -ForegroundColor Red
    Write-Host "  Step 1: 扫描并强力切断恶意活跃进程 (先断运行态)"
    Write-Host "  Step 2: 排查并清除保活计划任务 (防止杀完又起)"
    Write-Host "  Step 3: 清理注册表与目录自启动项 (斩断自启链)"
    Write-Host "  Step 4: 解除 IFEO 映像劫持与 DisallowRun 限制 (恢复工具运行权限)"
    Write-Host "  Step 5: 移除未签名 CI 恶意策略 (解开杀软底层封锁)"
    Write-Host "  Step 6: 修复 Hosts 文件安全域名拦截并刷新 DNS (恢复杀软更新访问)"
    Write-Host "  Step 7: 恢复 Windows Defender 默认防护"
    Write-Host "  Step 8: 检查并重置网络代理`n"

    Write-Host "--- [1/8] 查杀恶意活跃进程 ---" -ForegroundColor White
    Repair-ProcessThreats -Interactive

    Write-Host "`n--- [2/8] 处置恶意保活计划任务 ---" -ForegroundColor White
    Repair-ScheduledTasks -Interactive

    Write-Host "`n--- [3/8] 清理自启动驻留项 ---" -ForegroundColor White
    Repair-StartupThreats -Interactive

    Write-Host "`n--- [4/8] 解除 IFEO 与 DisallowRun 注册表限制 ---" -ForegroundColor White
    Repair-RegistryThreats -Interactive

    Write-Host "`n--- [5/8] 清除 CI/WDAC 恶意底层策略 ---" -ForegroundColor White
    Repair-CiPolicies -Interactive

    Write-Host "`n--- [6/8] 修复 Hosts 文件劫持 ---" -ForegroundColor White
    Repair-HostsFile -Interactive

    Write-Host "`n--- [7/8] 检查并重置网络代理 ---" -ForegroundColor White
    Repair-NetworkProxy -Interactive

    Write-Host "`n==================== [急救清理流程全部执行完毕] ====================" -ForegroundColor Green
    Write-Host "建议：处置完毕后请重启计算机以注销底层 CI 策略，并使用杀毒软件进行一次全盘扫描。" -ForegroundColor Cyan
}

if ($Scan) {
    Show-Banner
    Run-FullDiagnosis
    exit
}

if ($CleanAll) {
    Show-Banner
    Run-OneClickCure
    exit
}

# ==================== 主入口菜单 ====================
Show-Banner

while ($true) {
    Write-Host "`n【主控制台】请选择操作模式:" -ForegroundColor White
    Write-Host "  [1] 全盘深度体检 (检测进程/计划任务/自启/Hosts/CI策略等并生成报告)" -ForegroundColor Cyan
    Write-Host "  [2] 一键极速急救 (推荐：按防护闭环顺序一键查杀进程并清理所有驻留项)" -ForegroundColor Red
    Write-Host "  [3] 单项快速修复: Hosts 域名劫持" -ForegroundColor Gray
    Write-Host "  [4] 单项快速修复: CI/WDAC 恶意策略" -ForegroundColor Gray
    Write-Host "  [5] 单项快速修复: IFEO 映像劫持与 DisallowRun" -ForegroundColor Gray
    Write-Host "  [6] 单项快速修复: 保活计划任务" -ForegroundColor Gray
    Write-Host "  [7] 单项快速查杀: 活跃恶意进程" -ForegroundColor Gray
    Write-Host "  [0] 退出程序" -ForegroundColor Gray

    $c = Read-Host "`n请输入选项编号 [0-7]"
    switch ($c) {
        '1' { Run-FullDiagnosis }
        '2' { Run-OneClickCure }
        '3' { Repair-HostsFile -Interactive }
        '4' { Repair-CiPolicies -Interactive }
        '5' { Repair-RegistryThreats -Interactive }
        '6' { Repair-ScheduledTasks -Interactive }
        '7' { Repair-ProcessThreats -Interactive }
        '0' { Write-Host "`n感谢使用 foxs-killer，祝系统安全！`n" -ForegroundColor Green; exit }
        default { Write-Host "输入无效，请重新输入。" -ForegroundColor Red }
    }
}
