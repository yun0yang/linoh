@echo off
set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "VCVARSALL="
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    set "VSINSTALL=%%i"
)
if defined VSINSTALL set "VCVARSALL=!VSINSTALL!\VC\Auxiliary\Build\vcvarsall.bat"
if not exist "%VCVARSALL%" set "VCVARSALL=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
call "%VCVARSALL%" x64 >nul 2>&1
cd /d d:\cluster\linoh
echo Compiling builder.cpp...
cl /std:c++20 /EHsc /permissive- /O2 /utf-8 /DLINOH_USE_STUB_ASIO /I. /Iinclude /Ithird_party\asio\include src\net\udp_transport.cpp /c /Fobuild\udp_transport.obj
echo Exit code: %ERRORLEVEL%
