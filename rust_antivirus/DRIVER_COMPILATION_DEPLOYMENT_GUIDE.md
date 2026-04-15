#驅動編譯與部署完全指南

## 第一部分: 環境準備

### 開發工具安装

#### 1. Visual Studio 2019 或 2022 (含 C++ 開發工具)

```bash
#使用chocolatey快速安裝
choco install visualstudio2022community -y
# 選擇: Desktop development with C++
```

#### 2. Windows Driver Kit (WDK)

```
下載: https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
安装版本: WDK for Windows 11 (或 Windows 10 適用)
```

#### 3. Rust 開發環境

```bash
# 安裝 Rust (如果尚未安裝)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 新增 Windows 目標
rustup target add x86_64-pc-windows-msvc
rustup target add i686-pc-windows-msvc

# 驗證安裝
rustc --version
cargo --version
```

---

## 第二部分: C驅動編譯

### 步驟 1: 準備驅動項目

```bash
cd rust_antivirus\driver\wenle_minifilter

# 確認檔案存在
ls -la minifilter.c message.h
```

### 步驟 2: 使用 Visual Studio 編譯

#### 方法A: Visual Studio IDE (推薦)

1. 打開 Visual Studio
2. File → Open → Project → wenle_minifilter.vcxproj ***(如果存在)**
3. 如果.vcxproj不存在,需要手動建立:

#### 方法B: 使用 Windows Driver Kit (推薦用於WDK)

```batch
# 打開 Developer Command Prompt for VS 2022
cd rust_antivirus\driver\wenle_minifilter

# 編譯 (假設WDK已安裝且路徑設置正確)
cl.exe /D_KERNEL_MODE /I"%WDK_PATH%\Include\km" minifilter.c

# 或使用 MSBuild (如果有.vcxproj)
MSBuild minifilter.vcxproj /p:Configuration=Release /p:Platform=x64
```

#### 方法 C: Linux/WSL (使用 ClangCL)

```bash
# 在WSL中安裝WDK headers即可
# 但實際編譯建議在Windows上進行,因為涉及簽署
```

### 步驟 3: 編譯結果驗證

```bash
# 檢查是否生成 .obj 和 .sys 檔案
dir *.sys *.obj /s

# 預期輸出:
# 2026/03/09  12:34    123,456  wenle_minifilter.sys

# 如果生成失敗,檢查錯誤:
# - error LNK2019: unresolved external symbol '__imp_FltRegisterFilter'
#   → 需要連結 fltlib.lib (在WDK\Lib\km\x64\fltlib.lib)
# - error C2169: native keyword requires runtime option /clr
#   → 回查編譯參數,確保是 /clr 禁用
```

---

## 第三部分: Rust 應用編譯

```bash
cd rust_antivirus

# 編譯發行版本
cargo build --release

# 輸出檔案位置:
# target\release\wenle-antivirus.exe
# target\release\file-monitor.exe
# target\release\memory-monitor.exe

# 驗證編譯
.\target\release\wenle-antivirus.exe --version 2>&1 | head -5
```

---

## 第四部分: 驅動簽署

### ⚠️ 重要: 測試 vs 生產簽署

#### 測試環境簽署 (自簽)

```batch
@echo off
REM 生成自簽證書 (僅用於測試!)
makecert -r -pe -n "CN=Wenle Test Certificate" -ss ca^
         -a sha256 -len 2048 -cy authority WenleTest.cer

REM 將.cer轉換為.pfx供簽署使用
pvk2pfx -pvk WenleTest.pvk -spc WenleTest.cer -pfx WenleTest.pfx -po password

REM 簽署驅動
signtool sign /f WenleTest.pfx /p password /t http://timestamp.digicert.com^
        wenle_minifilter.sys

REM 驗證簽署
signtool verify /pa wenle_minifilter.sys
```

#### 生產環境簽署 (企業/WHQL)

```batch
REM 步驟1: 購買代碼簽署證書 (EV Authenticode)
REM 供應商: 如 DigiCert, Sectigo, GlobalSign 等
REM 費用: $200-500 USD/年

REM 步驟2: 使用企業證書簽署
signtool sign /f enterprise_cert.pfx /p password^
        /t http://timestamp.digicert.com /sha1 THUMBPRINT^
        wenle_minifilter.sys

REM 步驟3: WHQL 提交 (可選,加速硬體相容性認證)
REM https://docs.microsoft.com/en-us/windows-hardware/test/hlk/

REM 步驟4: 部署到客戶端
copy wenle_minifilter.sys %SystemRoot%\System32\drivers\
```

---

## 第五部分: 安裝驅動

### 啟用測試模式 (開發用)

```batch
REM ---警告: 這會關閉某些驅動簽署檢查!---
REM 僅在開發/測試環境中執行

bcdedit /set testsigning on
REM 重啟電腦
shutdown /r /t 0
```

### 使用 sc.exe 安裝驅動

```batch
REM 複製驅動到系統目錄
copy wenle_minifilter.sys C:\Windows\System32\drivers\

REM 建立驅動服務
sc create WenleMinifilter binPath= "C:\Windows\System32\drivers\wenle_minifilter.sys"^
                           type= kernel^
                           start= auto^
                           group= "File System"^
                           DisplayName= "Wenle Minifilter Antivirus Driver"

REM 驗證服務
sc query WenleMinifilter

REM 啟動服務
sc start WenleMinifilter

REM 檢查狀態
sc query WenleMinifilter | find "STATE"
REM 預期: STATE              : 4  RUNNING
```

### 使用 INF 檔案安裝 (生產級)

建立 `wenle_minifilter.inf`:

```ini
[Version]
Signature = "$Windows NT$"
Class = FSFilter
ClassGuid = {90A18991-23CA-403B-8D6B-6EA07B32FC5D}
Provider = %WenleProvider%
DriverVer = 03/09/2026, 2.0.0.0

[SourceDisksNames]
1 = %DiskId1%

[SourceDisksFiles]
wenle_minifilter.sys = 1

[DefaultInstall.NTx86]
CopyFiles = MinifilterFiles.NTx86

[DefaultInstall.NTamd64]
CopyFiles = MinifilterFiles.NTamd64

[DefaultInstall.NTx86.Services]
AddService = WenleMinifilter, 0x00000800, WenleMinifilter.ServiceInstall

[DefaultInstall.NTamd64.Services]
AddService = WenleMinifilter, 0x00000800, WenleMinifilter.ServiceInstall

[MinifilterFiles.NTx86]
wenle_minifilter.sys,

[MinifilterFiles.NTamd64]
wenle_minifilter.sys,

[WenleMinifilter.ServiceInstall]
DisplayName = %ServiceName%
Description = %ServiceDesc%
ServiceBinary = %SystemRoot%\System32\drivers\wenle_minifilter.sys
ServiceType = 2  ; SERVICE_FILE_SYSTEM_DRIVER
StartType = 2    ; SERVICE_AUTO_START
ErrorControl = 1 ; SERVICE_ERROR_NORMAL

[Strings]
WenleProvider = "Wenle Security"
DiskId1 = "Wenle Antivirus Driver Installation Disk"
ServiceName = "Wenle Minifilter Antivirus"
ServiceDesc = "Provides real-time file system monitoring and malware blocking"
```

安裝:
```batch
pnputil.exe /add-driver wenle_minifilter.inf /install
```

---

## 第六部分: 安裝使用者模式應用

```batch
REM 建立安裝目錄
mkdir "C:\Program Files\Wenle Antivirus"

REM 複製執行檔和依賴組件
copy target\release\wenle-antivirus.exe      "C:\Program Files\Wenle Antivirus\"
copy target\release\file-monitor.exe         "C:\Program Files\Wenle Antivirus\"
copy target\release\memory-monitor.exe       "C:\Program Files\Wenle Antivirus\"

REM 複製YARA規則引擎
copy Configuration\anti.yarac                "C:\Program Files\Wenle Antivirus\"
copy Configuration\yara64.exe                "C:\Program Files\Wenle Antivirus\"
copy Configuration\yarac64.exe               "C:\Program Files\Wenle Antivirus\"

REM 建立隔離資料夾
mkdir "C:\ProgramData\WenleAntivirus\Quarantine"
mkdir "C:\ProgramData\WenleAntivirus\Logs"

REM 設置快捷方式
powershell -Command ^
  "$ShortcutPath = $env:APPDATA + '\Microsoft\Windows\Start Menu\Programs\Wenle Antivirus.lnk'; ^
   $WshShell = New-Object -ComObject WScript.Shell; ^
   $Shortcut = $WshShell.CreateShortcut($ShortcutPath); ^
   $Shortcut.TargetPath = 'C:\Program Files\Wenle Antivirus\wenle-antivirus.exe'; ^
   $Shortcut.WorkingDirectory = 'C:\Program Files\Wenle Antivirus'; ^
   $Shortcut.Save()"

REM 啟動應用
"C:\Program Files\Wenle Antivirus\wenle-antivirus.exe"
```

---

## 第七部分: 故障排除

### 驅動編譯錯誤

#### 錯誤: "fltKernel.h not found"

```
解決方案:
1. 驗證WDK已正確安裝
2. 設置Include路徑:
   Visual Studio → Project Properties → VC++ Directories
   Include Directories: %WDK_PATH%\Include\km;%WDK_PATH%\Include\shared
```

#### 錯誤: "Unable to open include file 'fltKernel.h'"

```
解決方案:
export WDK_PATH=C:\Program Files (x86)\Windows Kits\10
cl.exe /I"%WDK_PATH%\Include\km" /I"%WDK_PATH%\Include\shared" minifilter.c
```

#### 編譯成功但無法加載驅動

```
可能原因:
1. ❌ 驅動未簽署 → 在測試模式中簽署或啟用 bcdedit /set testsigning on
2. ❌ 驅動版本不相容 → 檢查 WDK 版本與目標 Windows 版本
3. ❌ 依賴庫未連結 → 確保連結了 fltlib.lib advapi32.lib

檢查驅動加載狀態:
wevtutil qe System /q:"Event[System[EventID=7000 or EventID=7001]]" /format:text |^
  grep -i "WenleMinifilter"
```

### 應用程序错误

#### 無法連接驅動

```
症狀: YARA掃描功能失效, 其他功能正常

原因:
a) 驅動未啟動  → sc start WenleMinifilter
b) 通訊端口關閉 → 檢查驅動日誌

解決方案:
1. 檢查驅動狀態:
   sc query WenleMinifilter
2. 檢查事件日誌:
   eventvwr.msc → Windows Logs → System → WenleMinifilter
3. 重新啟動驅動:
   sc stop WenleMinifilter & sc start WenleMinifilter
```

---

## 第八部分: 驗證部署

### 檢查清單

- [ ] Rust 應用可執行
- [ ] yara64.exe 可正常工作
- [ ] anti.yarac 規則文件完整
- [ ] 驅動加載成功 (`sc query WenleMinifilter` returns STATE: 4 RUNNING)
- [ ] GUI 正常顯示,可以手動掃描
- [ ] 隔離目錄可寫入
- [ ] 驅動簽署有效

### 測試掃描

```bash
# 1. 測試 YARA CLI 掃描
cd "C:\Program Files\Wenle Antivirus"
yara64.exe -C anti.yarac C:\Windows\notepad.exe

# 預期: write到符合規則的檔案,或無輸出(未匹配)

# 2. 在 GUI 中掃描已知目錄
# → 單擊 "Start Scan" 按鈕

# 3. 觀察驅動日誌(DebugView)
# → 應該看到 "[WenleMinifilter]" 文字的調試輸出
```

---

## 第九部分: 性能优化与調整

### 掃描逾時設定

在 `driver/wenle_minifilter/minifilter.c` 中,修改:

```c
// 目前: 5秒逾時
Status = FltSendMessage(
    gFilterHandle,
    &gClientPort,
    &RequestBuffer,
    sizeof(SCAN_REQUEST_MESSAGE),
    &ResponseBuffer,
    &ReplyLength,
    NULL  // Timeout = default (5 sec)
);

// 改為 30秒逾時:
PLARGE_INTEGER Timeout = ...;  // 設置 30 秒
Status = FltSendMessage(
    gFilterHandle,
    &gClientPort,
    &RequestBuffer,
    sizeof(SCAN_REQUEST_MESSAGE),
    &ResponseBuffer,
    &ReplyLength,
    Timeout
);
```

### 排除掃描目錄

在 `src/engine.rs` 中增加:

```rust
const EXCLUDED_PATHS: &[&str] = &[
    "C:\\Windows\\",
    "C:\\Program Files\\",
    "C:\\ProgramData\\",
    // 添加更多...
];
```

---

## ✅ 安裝確認

安裝完成後,應看到:

1. **GUI 啟動**
   ```
   ✓ "Wenle Antivirus - Rust Edition" 窗口出現
   ```

2. **驅動載入**
   ```
   ✓ Services: WenleMinifilter = RUNNING
   ✓ Event Log: No errors from WenleMinifilter
   ```

3. **功能運行**
   ```
   ✓ 可手動掃描檔案/目錄
   ✓ 隔離惡意檔案到 C:\ProgramData\WenleAntivirus\Quarantine\
   ✓ 檔案監控子進程正常運行
   ```

---

## 📞 常見詢問

### Q: 編譯過程需要多久?

**A:** 首次編譯 Rust ~2-5分鐘 (取決於網路速度下載依賴),  
後續增量編譯 ~10-30秒。  
C驅動編譯 <1秒。

### Q: 能否在 Windows 7 上運行?

**A:** 不行。Minifilter API 需要 Windows Vista+, WDF 需要 Windows Vista+ (XP 及更早不支援)。

### Q: 自簽驅動會被防毒軟件標記嗎?

**A:** 可能會。解決方案: 購買正式代碼簽署證書或在組織內部白名單。

### Q: 如何更新規則?

**A:** 替換 Configuration\anti.yarac 檔案,重新啟動應用。

---

**最後更新**: 2026-03-09  
**版本**: 2.0-Enterprise-Deploy-Guide
