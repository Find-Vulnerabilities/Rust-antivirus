@echo off
REM Wenle Antivirus Minifilter Driver Build Script (WDK)
REM This script builds the kernel-mode minifilter driver

setlocal enabledelayedexpansion

echo ===== Wenle Minifilter Driver Build Script =====
echo.

REM Check for Visual Studio and WDK installation
set FOUND_WDK=0
set WDK_PATH=

echo Checking for Windows Driver Kit installation...

REM Try common WDK installation paths
if exist "C:\Program Files (x86)\Windows Kits\10" (
    set WDK_PATH=C:\Program Files (x86)\Windows Kits\10
    set FOUND_WDK=1
)

if exist "C:\Program Files\Windows Kits\10" (
    set WDK_PATH=C:\Program Files\Windows Kits\10
    set FOUND_WDK=1
)

if !FOUND_WDK! equ 0 (
    echo ERROR: Windows Driver Kit (WDK) not found!
    echo Please install Windows Driver Kit 10 or later from:
    echo https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
    exit /b 1
)

echo Found WDK at: !WDK_PATH!
echo.

REM Set up environment
set ARM_TOOLS_PATH=!WDK_PATH!\Tools\arm64
set MSVC_PATH=
set ARCH=amd64

REM Try to find MSVC compiler
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019" (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022" (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
) else (
    echo ERROR: Visual Studio not found!
    exit /b 1
)

REM Create output directory
if not exist ".\build_output" mkdir build_output

echo.
echo Building minifilter.sys for %ARCH% architecture...
echo.

REM Compile C code
set INCLUDE=!WDK_PATH!\include\10.0.22621.0
set LIB=!WDK_PATH!\lib\10.0.22621.0\%ARCH%

cl.exe /nologo ^
    /W4 /WX /D _KERNEL_ /D WINNT=1 ^
    /I "!INCLUDE!\km" ^
    /I "!INCLUDE!\shared" ^
    /I "!INCLUDE!\um" ^
    /I "%cd%" ^
    /c minifilter.c ^
    /Fo.\build_output\minifilter.obj

if errorlevel 1 (
    echo ERROR: Compilation failed!
    exit /b 1
)

echo.
echo Linking minifilter.sys...
echo.

REM Link to create .sys driver
link.exe /nologo ^
    /subsystem:native ^
    /driver ^
    /entry:DriverEntry ^
    /out:.\build_output\minifilter.sys ^
    .\build_output\minifilter.obj ^
    !LIB!\ntoskrnl.lib ^
    !LIB!\hal.lib ^
    !LIB!\fltmgr.lib

if errorlevel 1 (
    echo ERROR: Linking failed!
    exit /b 1
)

echo.
echo Build completed successfully!
echo Output: .\build_output\minifilter.sys
echo.

REM Copy to release directory
if exist ".\build_output\minifilter.sys" (
    if not exist "..\..\..\target\release" mkdir ..\..\..\target\release
    copy /Y .\build_output\minifilter.sys ..\..\..\target\release\minifilter.sys
    echo Driver copied to: ..\..\..\target\release\minifilter.sys
)

endlocal
exit /b 0
