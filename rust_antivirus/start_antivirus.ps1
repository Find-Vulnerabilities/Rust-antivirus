# 快速启动脚本 - 3秒启动完整防护
# 需要管理员权限运行

#Requires -RunAsAdministrator
param(
    [switch]$NoGUI = $false,
    [switch]$Verbose = $false
)

$ErrorActionPreference = "Continue"
$WarningPreference = "SilentlyContinue"

# 色彩定义
$ColorSuccess = @{ ForegroundColor = "Green" }
$ColorError = @{ ForegroundColor = "Red" }
$ColorInfo = @{ ForegroundColor = "Cyan" }
$ColorWarning = @{ ForegroundColor = "Yellow" }

# 脚本目录
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ReleaseDir = Join-Path $ScriptDir "target\release"
$ConfigDir = Join-Path $ScriptDir "Configuration"

Write-Host "`n" @ColorInfo
Write-Host "╔════════════════════════════════════════════╗" @ColorInfo
Write-Host "║  🛡️  Wenle Antivirus - 快速启动            ║" @ColorInfo  
Write-Host "║  版本: 0.2.0-Enterprise                    ║" @ColorInfo
Write-Host "║  状态: 商业级生产可用                       ║" @ColorInfo
Write-Host "╚════════════════════════════════════════════╝" @ColorInfo

# ===========================
# 1. 验证文件完整性
# ===========================
Write-Host "`n[步骤1] 验证文件完整性..." @ColorInfo

$requiredFiles = @(
    "target\release\wenle-antivirus.exe",
    "target\release\file_monitor.exe", 
    "target\release\memory_monitor.exe",
    "Configuration\anti.yarac"
)

$allFilesExist = $true
foreach ($file in $requiredFiles) {
    $fullPath = Join-Path $ScriptDir $file
    if (Test-Path $fullPath) {
        $size = (Get-Item $fullPath).Length / 1MB
        Write-Host "  ✓ $(Split-Path $file -Leaf) ($([math]::Round($size, 1)) MB)" @ColorSuccess
    } else {
        Write-Host "  ✗ 缺失: $file" @ColorError
        $allFilesExist = $false
    }
}

if (-not $allFilesExist) {
    Write-Host "`n错误: 缺少必要文件! 请重新编译。" @ColorError
    exit 1
}

# ===========================
# 2. 创建隔离目录
# ===========================
Write-Host "`n[步骤2] 初始化隔离系统..." @ColorInfo

$quarantineDir = "$env:LOCALAPPDATA\Temp\WenleQuarantine"
if (-not (Test-Path $quarantineDir)) {
    New-Item -Path $quarantineDir -ItemType Directory -Force | Out-Null
    Write-Host "  ✓ 隔离目录已创建: $quarantineDir" @ColorSuccess
} else {
    Write-Host "  ✓ 隔离目录已存在" @ColorSuccess
}

# ===========================
# 3. 创建日志目录
# ===========================
Write-Host "`n[步骤3] 初始化日志系统..." @ColorInfo

$logsDir = Join-Path $ScriptDir "logs"
if (-not (Test-Path $logsDir)) {
    New-Item -Path $logsDir -ItemType Directory -Force | Out-Null
}
Write-Host "  ✓ 日志目录: $logsDir" @ColorSuccess

# ===========================
# 4. 启动监控进程
# ===========================
Write-Host "`n[步骤4] 启动监控系统..." @ColorInfo

$mainProg = Join-Path $ReleaseDir "wenle-antivirus.exe"
$fileMonitor = Join-Path $ReleaseDir "file_monitor.exe"
$memMonitor = Join-Path $ReleaseDir "memory_monitor.exe"

# 终止已有进程
Get-Process -Name "wenle-antivirus", "file_monitor", "memory_monitor" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

# 启动文件监控
Write-Host "  启动文件监控..." @ColorInfo
Start-Process -FilePath $fileMonitor -NoNewWindow -PassThru | Out-Null
Start-Sleep -Milliseconds 300

# 启动内存监控  
Write-Host "  启动内存监控..." @ColorInfo
Start-Process -FilePath $memMonitor -NoNewWindow -PassThru | Out-Null
Start-Sleep -Milliseconds 300

# 启动主程序
if (-not $NoGUI) {
    Write-Host "  启动 GUI 面板..." @ColorInfo
    Start-Process -FilePath $mainProg
} else {
    Write-Host "  [--NoGUI] 跳过 GUI (仅后台监控)" @ColorWarning
}

# ===========================
# 5. 验证进程
# ===========================
Write-Host "`n[步骤5] 验证防护系统..." @ColorInfo

Start-Sleep -Milliseconds 1000

$procs = @{
    "文件监控" = "file_monitor"
    "内存监控" = "memory_monitor"
}

if (-not $NoGUI) {
    $procs["GUI面板"] = "wenle-antivirus"
}

$allRunning = $true
foreach ($name in $procs.Keys) {
    $procName = $procs[$name]
    $proc = Get-Process -Name $procName -ErrorAction SilentlyContinue
    if ($proc) {
        Write-Host "  ✓ $name (PID: $($proc.Id))" @ColorSuccess
    } else {
        Write-Host "  ✗ $name 未运行" @ColorError
        $allRunning = $false
    }
}

# ===========================
# 6. 显示启动结果
# ===========================
Write-Host "`n" @ColorInfo
if ($allRunning) {
    Write-Host "╔════════════════════════════════════════════╗" @ColorSuccess
    Write-Host "║  ✅ 防护系统已启动                          ║" @ColorSuccess
    Write-Host "║  监控路径:                                 ║" @ColorSuccess
    Write-Host "║  - C:\Windows\System32                    ║" @ColorSuccess
    Write-Host "║  - C:\ProgramData                         ║" @ColorSuccess
    Write-Host "║  - C:\Program Files*                      ║" @ColorSuccess
    Write-Host "║  - C:\Users (下载文件)                    ║" @ColorSuccess
    Write-Host "║                                            ║" @ColorSuccess
    Write-Host "║  隔离目录:                                 ║" @ColorSuccess
    Write-Host "║  - $quarantineDir" @ColorSuccess
    Write-Host "║                                            ║" @ColorSuccess
    Write-Host "║  日志文件:                                 ║" @ColorSuccess
    Write-Host "║  - $logsDir\*.log" @ColorSuccess
    Write-Host "╚════════════════════════════════════════════╝" @ColorSuccess
} else {
    Write-Host "⚠️  部分进程启动失败，请检查日志。" @ColorWarning
}

Write-Host "`n💡 提示:" @ColorInfo
Write-Host "  - 隔离威胁: $quarantineDir" @ColorInfo
Write-Host "  - 查看进程: Get-Process file_monitor" @ColorInfo
Write-Host "  - 停止防护: Get-Process file_monitor* | Stop-Process" @ColorInfo
Write-Host ""

if ($Verbose) {
    Write-Host "=== 详细信息 ===" @ColorInfo
    Write-Host "主程序路径: $mainProg" @ColorInfo
    Write-Host "YARA规则库: $(Join-Path $ScriptDir 'Configuration\anti.yarac')" @ColorInfo
}

Write-Host ""
