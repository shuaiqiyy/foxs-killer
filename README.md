# foxs-killer (银狐病毒深度排查与急救修复工具 v2.0)

针对国内活跃的**银狐（Silver Fox / 游蛇 / ValleyRAT）**远控木马家族的深度查杀、自启动清理与防御恢复工具。基于全网主流安全厂商（火绒、奇安信、深信服、微步在线、360）的真实攻防情报进行全面重构升级。

---

## 🌟 核心升级特性 (v2.0)

| 查杀维度 | v1.0 原始能力 | v2.0 升级能力 |
| :--- | :--- | :--- |
| **内存活跃进程** | 完全无查杀（需用户手动排查） | **智能多维识别引擎**：结合持久化交叉锁定、临时脏路径、仿冒名称与白加黑同目录特征，支持一键批量强杀 |
| **保活计划任务** | 全量导出无白名单（误报严重） | **系统白名单过滤库**：智能屏蔽微软原生任务，聚焦 AppData/Temp 短周期保活任务，支持禁用与彻底物理删除 |
| **自启动项驻留** | 无独立检测 | **全域自启动排查**：覆盖注册表 `Run` / `RunOnce`、Winlogon 劫持及用户 `Startup` 目录 |
| **注册表对抗** | 未覆盖 | **映像劫持与限制解除**：扫描并解除 `IFEO Debugger` 劫持、`DisallowRun` 程序黑名单及 Defender 恶意禁用项 |
| **CI / WDAC策略** | 仅依赖 `citool -lp` | **双层排查**：动态 `citool` 枚举删除 + `CIPolicies\Active` 底层文件扫描隔离 |
| **Hosts 域名劫持** | 仅硬编码 3 个 360 域名 | **全量厂商库 + 启发式引擎**：覆盖 360、火绒、腾讯管家、微步、金山、微软更新等，自动备份原文件并刷新 DNS |
| **网络代理劫持** | 未覆盖 | **WinINet 代理重置**：检测并清除恶意代理服务器与 PAC 脚本劫持 |
| **架构与依赖** | 单文件粗糙脚本 | **模块化架构**：结构清晰，纯 Python 标准库开发，**零第三方 pip 依赖**，免杀兼容好 |

---

## 📁 项目目录架构

```
coder/fox/
├── core/                      # 核心功能模块库
│   ├── __init__.py
│   ├── utils.py               # 控制台着色、管理员提权检测、文件备份工具
│   ├── hosts_cleaner.py       # Hosts 广谱安全域名劫持检测与一键修复
│   ├── policy_cleaner.py      # CI/WDAC 恶意代码完整性策略深度清理
│   ├── reg_repair.py          # IFEO 映像劫持、DisallowRun 限制、Defender 策略恢复
│   ├── startup_cleaner.py     # 注册表 Run/RunOnce/Winlogon 与 Startup 启动项排查
│   ├── task_cleaner.py        # 计划任务智能过滤、风险加权评分、禁用与强删
│   ├── process_killer.py      # 银狐活跃木马/白利用加载器识别与强制终止
│   └── network_cleaner.py     # WinINet 网络代理与 PAC 脚本劫持排查与重置
├── main.py                    # 统一主控制台（体检报告、一键急救、分项处置）
├── release/                   # 历史发布程序产物
└── README.md                  # 项目文档
```

---

## 🚀 极速应急：Win + R 运行框一行命令秒跑 (推荐)

**受害者电脑即使完全没有安装 Python、没有预先下载任何文件，也能一键秒级急救！**

直接按下键盘快捷键 **`Win + R`**，在弹出的「运行」窗口中粘贴以下命令回车：

```powershell
powershell -c "irm https://raw.githubusercontent.com/shuaiqiyy/foxs-killer/main/fox.ps1|iex"
```
*(💡 绑定短域名后，命令可精简为 `powershell -c "irm is.gd/foxkill|iex"`，仅 36 字符！)*

#### 原理解析：
1. **零环境依赖**：Windows 7 / 10 / 11 全系出厂内置 PowerShell。
2. **内存直接加载**：`irm` 从云端拉取脚本，`iex` 直接在内存中启动，不在受害者电脑留存垃圾。
3. **内置自动提权**：脚本首行检测到非管理员时，会自动呼出 Windows UAC 提权确认框。

---

## 💻 本地控制台使用方式

### 1. PowerShell 原生版直接运行（推荐，免 Python）
```powershell
# 交互式菜单运行
powershell -ExecutionPolicy Bypass -File .\fox.ps1

# 静默全盘深度体检
powershell -ExecutionPolicy Bypass -File .\fox.ps1 -Scan

# 一键急救处置
powershell -ExecutionPolicy Bypass -File .\fox.ps1 -CleanAll
```

### 2. Python 源码版调试运行
```powershell
# 交互式菜单运行
python main.py

# 命令行静默参数
python main.py --scan       # 执行体检报告
python main.py --clean-all  # 一键急救清理
python main.py --kill-proc  # 仅排查强杀恶意进程
python main.py --clean-hosts# 仅清理 Hosts 劫持
```

---

## 🛠️ 二次开发指南

### 1. 扩充恶意域名黑名单
编辑 `core/hosts_cleaner.py` 中的 `KNOWN_SECURITY_DOMAINS` 与 `SECURITY_KEYWORDS` 数组，加入新捕获的 C2 或被劫持域名。

### 2. 增强进程识别特征
编辑 `core/process_killer.py` 中的 `evaluate_process_risk()` 函数。可加入新的仿冒进程名称（`FAKE_SYSTEM_NAMES`）或常见白利用伴随动态库（`HIJACKED_DLL_NAMES`）。

### 3. 本地打包为单个可执行 EXE
本项目坚持使用 Python 标准库，打包无需携带沉重的外部轮子：
```powershell
# 打包为单文件控制台程序，内置 UAC 管理员提权请求
pyinstaller -F --uac-admin -n "foxs-killer-v2.0" main.py
```
打包产物将位于 `dist/foxs-killer-v2.0.exe`。

---

## ⚠️ 处置后建议

1. **重启计算机**：彻底注销被移除的内核级代码完整性策略（CI Policy）。
2. **全盘深度杀毒**：解开系统的杀软拦截后，打开火绒安全、360安全卫士或系统自带的 Windows Defender 进行一次全盘扫描，彻底清除硬盘角落里残留的木马实体文件。
3. **更改敏感凭据**：银狐具备键盘记录与通信软件窃密功能，在确认系统清理完毕后，尽快修改该设备上曾经登录过的财务、邮箱、即时通讯及关键平台密码。
