# foxs-killer
银狐病毒查杀脚本

## 快捷命令

使用管理员身份打开powershell

```powershell
$wc=New-Object System.Net.WebClient;$wc.DownloadFile("https://github.com/shuaiqiyy/foxs-killer/releases/download/v1.0/foxs-killer-x64.exe","$env:TEMP\foxs-killer-x64.exe");Start-Process "$env:TEMP\foxs-killer-x64.exe" -Verb RunAs
```


### 功能：
实现对hosts文件篡改恢复。

实现对恶意策略的识别和删除（禁用杀软的相关策略）。

实现对恶意计划任务（病毒进程保活）的禁用。

用户需手动结束存在的进程（进程名多变，无法自动结束。但极有辨识度）。

手动在任务管理器取消开机自启动，即可恢复正常。

最后使用杀软清除病毒残留即可。
