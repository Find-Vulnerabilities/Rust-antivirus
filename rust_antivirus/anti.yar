import "pe"

rule Suspicious_UEFI_Modification_Improved : pe
{
    meta:
        description = "Detects binaries attempting to modify UEFI firmware or EFI variables"
        author = "wenszeyui"
        version = "2.1"
        date = "2025-07-30"
        reference = "UEFI tampering detection"
        severity = "high"

    strings:
        // EFI modification APIs
        $efi1 = "SetFirmwareEnvironmentVariableA" wide ascii
        $efi2 = "SetFirmwareEnvironmentVariableW" wide ascii
        $efi3 = "SetFirmwareEnvironmentVariableEx" wide ascii
        $efi4 = "GetFirmwareEnvironmentVariable" wide ascii

        // EFI paths
        $linux_efi_path = "/sys/firmware/efi/efivars" ascii
        $esp_path = /GLOBALROOT\\Device\\HarddiskVolume[0-9]+\\EFI\\/ wide ascii

        // Bootkit signature
        $bootkit_sig = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 }

        // Legitimate update tools
        $legit_uefi1 = "UEFI Firmware Update" wide ascii
        $legit_uefi2 = "BIOS Update Utility" wide ascii

    condition:
        pe.is_pe and
        filesize < 5MB and
        any of ($efi*) and
        not any of ($legit_uefi*) and
        (
            any of ($linux_efi_path, $esp_path, $bootkit_sig) or
            (
                pe.imports("kernel32.dll", "SetFirmwareEnvironmentVariableA") or
                pe.imports("kernel32.dll", "SetFirmwareEnvironmentVariableW") or
                pe.imports("kernel32.dll", "SetFirmwareEnvironmentVariableEx") or
                pe.imports("kernel32.dll", "GetFirmwareEnvironmentVariable")
            )
        )
}


rule Detect_File_Encryption_Behavior {
    strings:
        $crypto1 = "CryptEncrypt" nocase
        $crypto2 = "AES_encrypt" nocase
        $ransom_note = /_decrypt_instructions/i
    condition:
        any of ($crypto*) and $ransom_note
}


rule Detect_File_Extension_Change_Improved : pe
{
    meta:
        description = "Detects binaries that attempt to change file extensions, common in ransomware"
        author = "wennszeyui"
        version = "2.1"
        date = "2025-07-30"
        category = "behavioral"
        maltype = "ransomware or file modifier"
        false_positives = "Some backup utilities may trigger"

    strings:
        // Suspicious extensions
        $ext1 = ".locked" wide ascii
        $ext2 = ".encrypted" wide ascii
        $ext3 = ".enc" wide ascii
        $ext4 = ".pay" wide ascii
        $ext5 = ".deadbolt" wide ascii
        $ext6 = ".crypted" wide ascii
        $ext7 = ".xyz" wide ascii

        // Rename APIs
        $rename1 = "MoveFileA" wide ascii
        $rename2 = "MoveFileW" wide ascii
        $rename3 = "MoveFileExA" wide ascii
        $rename4 = "MoveFileExW" wide ascii

        // Legitimate backup tools
        $legit_backup1 = "Backup Exec" wide ascii
        $legit_backup2 = "Acronis" wide ascii

    condition:
        pe.is_pe and
        not any of ($legit_backup*) and
        any of ($ext*) and
        any of ($rename*) and
        (
            pe.imports("kernel32.dll", "MoveFileA") or
            pe.imports("kernel32.dll", "MoveFileW") or
            pe.imports("kernel32.dll", "MoveFileExA") or
            pe.imports("kernel32.dll", "MoveFileExW")
        )
}


rule Detect_File_Infection_Improved
{
    meta:
        description = "Detects file infectors that append or inject malicious code into PE executables"
        author = "wenszeyui"
        version = "1.1"
        date = "2025-07-04"
        category = "file-infector"
        maltype = "virus"

    strings:
        $marker1 = "INFECTED_BY_SZ" nocase
        $marker2 = "VIRUS_PAYLOAD" nocase
        $marker3 = { E8 ?? ?? ?? ?? 5B 81 EB }
        $marker4 = { 60 E8 ?? ?? ?? ?? 61 }

    condition:
        pe.is_pe and
        (any of ($marker*) or
         pe.entry_point > pe.sections[pe.number_of_sections - 1].virtual_address)
}


rule Detect_Deletion_of_Critical_C_Drive_Files_Improved
{
    meta:
        description = "Detects attempts to delete critical system files on C:\\ drive"
        author = "szeyui"
        version = "1.1"
        date = "2025-07-04"
        category = "destructive"
        maltype = "wiper / ransomware"

    strings:
        // Deletion APIs
        $delete1 = "DeleteFileA"
        $delete2 = "DeleteFileW"
        $delete3 = "SHFileOperation"
        $delete4 = "RemoveDirectoryA"
        $delete5 = "RemoveDirectoryW"

        // Critical system paths (regex for flexibility)
        $sys1 = /[Cc]:\\\\Windows\\\\System32\\\\ntoskrnl\.exe/
        $sys2 = /[Cc]:\\\\Windows\\\\System32\\\\winload\.exe/
        $sys3 = /[Cc]:\\\\Windows\\\\System32\\\\config\\\\SAM/
        $sys4 = /[Cc]:\\\\Windows\\\\System32\\\\drivers\\\\/
        $sys5 = /[Cc]:\\\\boot\.ini/
        $sys6 = /[Cc]:\\\\Windows\\\\explorer\.exe/
        $sys7 = /[Cc]:\\\\Windows\\\\System32\\\\hal\.dll/

    condition:
        pe.is_pe and
        any of ($delete*) and any of ($sys*)
}

rule Detect_Chat_Log_Stealer_Trojan_With_Facebook_Improved
{
    meta:
        description = "Detects trojans that attempt to steal chat logs from messaging apps including Facebook"
        author = "szeyui"
        version = "1.2"
        date = "2025-07-04"
        category = "infostealer"
        maltype = "chat log stealer"

    strings:
        // Messaging platforms
        $discord = "Discord\\Local Storage\\leveldb"
        $telegram = "Telegram Desktop\\tdata"
        $whatsapp = "WhatsApp\\User Data"
        $skype = "Skype\\My Skype Received Files"
        $wechat = "WeChat Files"
        $qq = "Tencent\\QQ"
        $facebook1 = "Facebook\\Messenger"
        $facebook2 = "messenger.com"
        $facebook3 = "messages/inbox"
        $facebook4 = "threads"

        // Chat content
        $chat1 = "chatlog"
        $chat2 = "message history"
        $chat3 = "conversation"
        $chat4 = "msgstore.db"
        $chat5 = "sqlite3_open"

        // Exfiltration
        $exfil1 = "WinHttpSendRequest"
        $exfil2 = "InternetOpenUrl"
        $exfil3 = "curl"
        $exfil4 = "ftp://"
        $exfil5 = "POST /upload"

        // Decryption / encoding
        $crypto1 = "CryptUnprotectData"
        $crypto2 = "Base64Decode"

    condition:
        pe.is_pe and
        (any of ($discord, $telegram, $whatsapp, $skype, $wechat, $qq, $facebook*)) and
        any of ($chat*) and
        any of ($exfil*) and
        any of ($crypto*)
}

rule Detect_Webcam_Spy_Trojan_Improved
{
    meta:
        description = "Detects trojans that attempt to access, record, and exfiltrate webcam footage"
        author = "wenszeyui"
        version = "1.1"
        date = "2025-07-04"
        category = "spyware"
        maltype = "webcam stealer"

    strings:
        // Webcam access
        $cam1 = "capCreateCaptureWindowA"
        $cam2 = "capCreateCaptureWindowW"
        $cam3 = "capDriverConnect"
        $cam4 = "capGrabFrame"
        $cam5 = "capFileSaveAs"
        $cam6 = "avicap32.dll"
        $cam7 = "mf.dll"
        $cam8 = "DirectShow"
        $cam9 = "MediaCapture"
        $cam10 = "Windows.Media.Capture"

        // Device identifiers
        $dev1 = "\\\\.\\Global\\usbvideo"
        $dev2 = "vid_"
        $dev3 = "device\\video"
        $dev4 = "CameraCaptureUI"

        // Output formats
        $ext1 = ".avi"
        $ext2 = ".mp4"
        $ext3 = ".jpg"
        $ext4 = ".bmp"
        $ext5 = "webcam_capture"

        // Exfiltration
        $exfil1 = "WinHttpSendRequest"
        $exfil2 = "InternetOpenUrl"
        $exfil3 = "POST /upload"
        $exfil4 = "ftp://"
        $exfil5 = "http://"

    condition:
        pe.is_pe and
        (any of ($cam*) or any of ($dev*)) and
        any of ($ext*) and
        any of ($exfil*)
}


rule Detect_MBR_Modification_Improved
{
    meta:
        description = "Detects binaries attempting to modify the Master Boot Record (MBR)"
        author = "wenszeyui"
        version = "1.1"
        date = "2025-07-05"
        category = "bootkit"
        maltype = "MBR modifier"

    strings:
        // API functions
        $api1 = "CreateFileA" nocase
        $api2 = "CreateFileW" nocase
        $api3 = "WriteFile" nocase
        $api4 = "DeviceIoControl" nocase
        $api5 = "ReadFile" nocase
        $api6 = "SetFilePointer" nocase

        // Disk access targets
        $disk = /\\\\\.\\(PhysicalDrive|C)([0-9]*)?/ nocase

        // Known malicious MBR patterns
        $bootkit1 = { B8 00 7C 8E D8 8E C0 BE 00 7C BF 00 06 B9 00 02 F3 A5 }
        $bootkit2 = { FA 33 C0 8E D0 BC 00 7C FB 8E D8 E8 00 00 }

    condition:
        pe.is_pe and (
            (any of ($api*) and $disk) or
            (uint16(0x1FE) == 0xAA55 and any of ($bootkit*))
        )
}


rule Detect_GPT_Partition_Modification_Improved
{
    meta:
        description = "Detects binaries attempting to modify GPT partition tables"
        author = "wenszeyui"
        version = "1.1"
        date = "2025-07-05"
        category = "bootkit / persistence"
        maltype = "GPT modifier"

    strings:
        // API functions
        $api1 = "CreateFileA" nocase
        $api2 = "CreateFileW" nocase
        $api3 = "WriteFile" nocase
        $api4 = "DeviceIoControl" nocase
        $api5 = "ReadFile" nocase

        // Disk access targets
        $disk = /\\\\\.\\(PhysicalDrive|Harddisk)[0-9]+(\\Partition[0-9]+)?/ nocase

        // GPT header signature
        $gpt_sig = { 45 46 49 20 50 41 52 54 }  // "EFI PART"

        // Known GUIDs
        $guid1 = { 28 73 2A C1 1F F8 D2 11 BA 4B 00 A0 C9 3E C9 3B }  // EFI System Partition
        $guid2 = { A2 A0 D0 EB E5 B9 33 44 87 C0 68 B6 B7 26 99 C7 }  // Microsoft Reserved

    condition:
        pe.is_pe and
        (any of ($api*) and $disk) and
        (any of ($gpt_sig, $guid1, $guid2))
}


rule Suspicious_JS_Downloader_Improved
{
    meta:
        description = "Detects JavaScript files that download and execute payloads"
        author = "wenszeyui"
        category = "script"
        maltype = "downloader"

    strings:
        // Download behavior
        $url = /https?:\/\/[^\s"]+/ nocase
        $xmlhttp1 = "MSXML2.XMLHTTP" nocase
        $xmlhttp2 = "XMLHttpRequest" nocase
        $stream = "ADODB.Stream" nocase

        // Execution behavior
        $eval = "eval(" nocase
        $wscript = "WScript.Shell" nocase
        $run = ".Run(" nocase
        $powershell = "powershell -" nocase

        // Obfuscation
        $obf1 = "String.fromCharCode" nocase
        $obf2 = "unescape(" nocase

        // File writing
        $write1 = "SaveToFile" nocase
        $write2 = "CreateTextFile" nocase

    condition:
        filesize < 100KB and
        (1 of ($url, $xmlhttp1, $xmlhttp2, $stream, $powershell)) and
        (any of ($eval, $wscript, $run)) and
        (any of ($write1, $write2) or any of ($obf1, $obf2))
}
rule Detect_Script_Persistence_Improved
{
    meta:
        description = "Detects scripts attempting to establish persistence via registry, tasks, or startup folder"
        author = "wenszeyui"
        category = "script"
        maltype = "persistence"

    strings:
        $reg1 = "reg add" nocase
        $reg2 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg3 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $schtasks = "schtasks /create" nocase
        $startup = "\\Startup\\" nocase
        $wmi = "__EventFilter" nocase
        $profile = "Microsoft.PowerShell_profile.ps1" nocase

    condition:
        filesize < 100KB and
        (2 of ($reg*, $schtasks, $startup, $wmi, $profile))
}
rule Detect_Script_UEFI_Modification_Improved
{
    meta:
        description = "Detects scripts attempting to modify UEFI firmware or EFI variables"
        author = "szeyui"
        category = "script / firmware"
        maltype = "UEFI tampering"

    strings:
        $wmi = "GetObject(\"winmgmts:" nocase
        $bios = "Win32_BIOS" nocase
        $firmware1 = "SetFirmwareEnvironmentVariable" nocase
        $firmware2 = "SetFirmwareEnvironmentVariableEx" nocase
        $firmware3 = "GetFirmwareEnvironmentVariable" nocase
        $ps = "powershell.exe" nocase
        $efi1 = "\\EFI\\" nocase
        $efi2 = "GLOBALROOT\\Device\\HarddiskVolume" nocase

    condition:
        filesize < 100KB and
        any of ($wmi, $bios, $firmware1, $firmware2, $firmware3, $ps) and
        any of ($efi1, $efi2)
}
rule Detect_Browser_Password_Stealer_Improved
{
    meta:
        description = "Detects attempts to steal and exfiltrate browser passwords"
        author = "szeyui"
        category = "infostealer"
        maltype = "browser stealer"

    strings:
        // Browser password storage
        $chrome = "Chrome\\User Data\\Default\\Login Data"
        $firefox = "signons.sqlite"
        $edge = "Microsoft\\Edge\\User Data"
        $brave = "BraveSoftware\\Brave-Browser\\User Data"
        $opera = "Opera Software\\Opera Stable"

        // Exfiltration
        $exfil1 = "POST /upload"
        $exfil2 = "WinHttpSendRequest"
        $exfil3 = "HttpSendRequest"
        $exfil4 = "InternetOpenUrl"

        // Decryption
        $decrypt = "CryptUnprotectData"

    condition:
        pe.is_pe and
        any of ($chrome, $firefox, $edge, $brave, $opera) and
        any of ($exfil1, $exfil2, $exfil3, $exfil4) and
        $decrypt
}

rule Detect_EFI_Driver_Load_Improved
{
    meta:
        description = "Detects potential EFI driver loading behavior"
        author = "szeyui"
        category = "bootkit"
        maltype = "efi loader"

    strings:
        $efi1 = "\\EFI\\Boot\\bootx64.efi"
        $efi2 = "LoadImage"
        $efi3 = "StartImage"
        $efi4 = "HandleProtocol"
        $efi5 = "InstallProtocolInterface"
        $sig = { 45 46 49 20 50 41 52 54 } // "EFI PART"

    condition:
        // FIX: remove pe.is_64bit, use only pe.machine == pe.MACHINE_AMD64
        (pe.is_pe and pe.machine == pe.MACHINE_AMD64 and
         2 of ($efi*)) or $sig
}

rule Detect_DLL_Injector_Improved
{
    meta:
        description = "Detects potential DLL injection behavior in PE files"
        author = "szeyui"
        category = "trojan"
        maltype = "injector"

    strings:
        $api1 = "OpenProcess"
        $api2 = "VirtualAllocEx"
        $api3 = "WriteProcessMemory"
        $api4 = "CreateRemoteThread"
        $api5 = "LoadLibraryA"
        $api6 = "LoadLibraryW"
        $dll = /\.dll/i

    condition:
        pe.is_pe and
        4 of ($api*) and $dll
}

rule VBScript_FileInfector_SZ_Improved
{
    meta:
        description = "Detects VBScript virus with file infection, destructive behavior, and obfuscation"
        author = "szeyui"
        version = "1.1"
        date = "2025-07-17"
        category = "virus"
        maltype = "vbscript file infector"

    strings:
        // Infection and replication
        $copy1 = "CreateObject(\"Scripting.FileSystemObject\")"
        $copy2 = "CopyFile WScript.ScriptFullName"
        $copy3 = "GetSpecialFolder"
        $copy4 = "WScript.ScriptFullName"

        // Destructive behavior
        $del1 = /Delete(File|Folder)\s+"C:\\\\.*"/
        $del2 = "SetAttr"

        // Dynamic execution / obfuscation
        $exec1 = "Execute("
        $exec2 = "Eval("
        $exec3 = "Chr("
        $exec4 = "Base64Decode"

        // Marker or payload
        $marker = "INFECTED_BY_SZ"

    condition:
        any of ($copy*) and any of ($del*) and any of ($exec*) and $marker
}

rule Detect_Process_Injection_Improved
{
    meta:
        description = "Detects potential process injection behavior in PE files"
        author = "wenszeyui"
        category = "trojan"
        maltype = "process injector"

    strings:
        $api1 = "CreateRemoteThread"
        $api2 = "NtCreateThreadEx"
        $api3 = "WriteProcessMemory"
        $api4 = "VirtualAllocEx"
        $api5 = "QueueUserAPC"
        $api6 = "SetWindowsHookEx"

    condition:
        pe.is_pe and
        pe.imports("kernel32.dll", "WriteProcessMemory") or
        pe.imports("kernel32.dll", "CreateRemoteThread") or
        pe.imports("ntdll.dll", "NtCreateThreadEx") or
        3 of ($api*)
}




rule Detect_Self_Modifying_Code_Improved
{
    meta:
        description = "Detects potential self-modifying code behavior in PE files"
        author = "wenszeyui"
        category = "malware"
        maltype = "self-modifying code"

    strings:
        $api1 = "VirtualProtect"
        $api2 = "VirtualAlloc"
        $api3 = "WriteProcessMemory"
        $api4 = "FlushInstructionCache"

    condition:
        pe.is_pe and
        (pe.imports("kernel32.dll", "VirtualProtect") and
         pe.imports("kernel32.dll", "VirtualAlloc") and
         pe.imports("kernel32.dll", "WriteProcessMemory") and
         pe.imports("kernel32.dll", "FlushInstructionCache")) or
        all of ($api*)
}