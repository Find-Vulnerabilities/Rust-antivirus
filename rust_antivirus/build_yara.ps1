# Windows YARA 編譯腳本
# 用途：從 yara-4.5.5 源碼編譯生成 .lib 和 .dll
# 支持 Visual Studio 2017/2019/2022 和 x64/x86 架構

param(
    [ValidateSet("x64", "x86")]
    [string]$Architecture = "x64",
    
    [ValidateSet("2017", "2019", "2022")]
    [string]$VSVersion = "2022",
    
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

# 確定 VS 路徑和生成器名稱
$vsMap = @{
    "2017" = ("Visual Studio 2017", "Visual Studio 15 2017")
    "2019" = ("Visual Studio 2019", "Visual Studio 16 2019")
    "2022" = ("Visual Studio 2022", "Visual Studio 17 2022")
}

$vsName, $generatorName = $vsMap[$VSVersion]

# 確定架構參數
$archMap = @{
    "x64" = "x64"
    "x86" = "Win32"
}
$archParam = $archMap[$Architecture]

Write-Host "========================================" -ForegroundColor Green
Write-Host "YARA Windows Build Script" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "Visual Studio: $vsName" -ForegroundColor Yellow
Write-Host "Architecture: $Architecture" -ForegroundColor Yellow
Write-Host "Configuration: $Configuration" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Green

# 取得 YARA 源碼目錄
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$yaraSourceDir = Join-Path $scriptDir "third_party\yara\yara-4.5.5"
$buildDir = Join-Path $scriptDir "third_party\yara\build"
$libOutDir = Join-Path $scriptDir "third_party\yara\lib\$Architecture\$Configuration"

# 驗證源碼存在
if (-not (Test-Path $yaraSourceDir)) {
    Write-Error "YARA source directory not found: $yaraSourceDir"
    exit 1
}

Write-Host "`n[1/5] Creating build directory..." -ForegroundColor Cyan
if (-not (Test-Path $buildDir)) {
    New-Item -ItemType Directory -Path $buildDir | Out-Null
}
Set-Location $buildDir
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue *

Write-Host "[2/5] Running CMake configuration..." -ForegroundColor Cyan
$cmakeCmd = @(
    "cmake",
    "..",
    "-G", "`"$generatorName`"",
    "-A", $archParam,
    "-DCMAKE_BUILD_TYPE=$Configuration",
    "-DBUILD_SHARED_LIBS=OFF",
    "-DENABLE_CUCKOO=OFF",
    "-DENABLE_MAGIC=OFF"
)

& cmake @cmakeCmd
if ($LASTEXITCODE -ne 0) {
    Write-Error "CMake configuration failed"
    exit 1
}

Write-Host "[3/5] Building YARA library..." -ForegroundColor Cyan
$buildCmd = @(
    "cmake",
    "--build", ".",
    "--config", $Configuration,
    "--target", "yara",
    "--", "/m"
)

& cmake @buildCmd
if ($LASTEXITCODE -ne 0) {
    Write-Error "YARA build failed"
    exit 1
}

Write-Host "[4/5] Creating output directory..." -ForegroundColor Cyan
$releaseLibDir = Join-Path $buildDir $Configuration
if (-not (Test-Path $libOutDir)) {
    New-Item -ItemType Directory -Path $libOutDir -Force | Out-Null
}

Write-Host "[5/5] Copying output files..." -ForegroundColor Cyan

# 複製生成的 lib
$libFiles = Get-ChildItem -Path $releaseLibDir -Name "*.lib" -ErrorAction SilentlyContinue
if ($libFiles) {
    Copy-Item -Path (Join-Path $releaseLibDir $libFiles) -Destination $libOutDir -Force
    Write-Host "Copied lib files to: $libOutDir" -ForegroundColor Green
} else {
    Write-Error "No .lib files found in $releaseLibDir"
    exit 1
}

# 複製頭文件
$headerOutDir = Join-Path $scriptDir "third_party\yara\include\yara"
if (-not (Test-Path $headerOutDir)) {
    New-Item -ItemType Directory -Path $headerOutDir -Force | Out-Null
}
Copy-Item -Path (Join-Path $yaraSourceDir "libyara\include\yara\*") -Destination $headerOutDir -Force -Recurse
Write-Host "Copied header files to: $headerOutDir" -ForegroundColor Green

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Build completed successfully!" -ForegroundColor Green
Write-Host "Output: $libOutDir" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Green

Write-Host "`nNext steps:" -ForegroundColor Cyan
Write-Host "1. Run 'cargo build' to compile your Rust project with YARA support" -ForegroundColor White
Write-Host "2. The build.rs script will automatically link to the compiled library" -ForegroundColor White
