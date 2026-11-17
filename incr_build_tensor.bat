@echo off
setlocal enabledelayedexpansion

set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"

set "VCVARSALL="
if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSINSTALL=%%i"
    if defined VSINSTALL set "VCVARSALL=!VSINSTALL!\VC\Auxiliary\Build\vcvarsall.bat"
)
if not exist "%VCVARSALL%" (
    for %%E in (Community Professional Enterprise BuildTools) do (
        if not exist "%VCVARSALL%" if exist "%ProgramFiles%\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvarsall.bat" set "VCVARSALL=%ProgramFiles%\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvarsall.bat"
    )
)
if not exist "%VCVARSALL%" (
    echo ERROR: Could not find vcvarsall.bat
    exit /b 1
)
call "%VCVARSALL%" x64
if errorlevel 1 ( echo ERROR: vcvarsall failed & exit /b 1 )

cd /d %~dp0

set "CXXFLAGS=/std:c++20 /EHsc /permissive- /O2 /utf-8 /MD /DLINOH_USE_STUB_ASIO /I. /Iinclude /Ithird_party\asio\include /Ithird_party\openssl\include"

echo === compile src\multimodal\tensor_stream.cpp ===
cl %CXXFLAGS% src\multimodal\tensor_stream.cpp /c /Fo:build\core_tensor_stream.obj
if errorlevel 1 ( echo FAILED: tensor_stream.cpp & exit /b 1 )

echo === rebuild linoh.lib with core_*.obj ===
lib /NOLOGO /OUT:"build\linoh.lib" build\core_*.obj
if errorlevel 1 ( echo FAILED: linoh.lib & exit /b 1 )

echo === compile tests\test_tensor_stream.cpp ===
cl %CXXFLAGS% tests\test_tensor_stream.cpp /c /Fo:build\test_tensor_stream.obj
if errorlevel 1 ( echo FAILED: test_tensor_stream.cpp & exit /b 1 )

echo === link test_tensor_stream.exe ===
link /NOLOGO /OUT:"build\test_tensor_stream.exe" "build\test_tensor_stream.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE
if errorlevel 1 ( echo FAILED: test_tensor_stream.exe & exit /b 1 )

echo === compile tests\test_tensor_stream_timeout.cpp ===
cl %CXXFLAGS% tests\test_tensor_stream_timeout.cpp /c /Fo:build\test_tensor_stream_timeout.obj
if errorlevel 1 ( echo FAILED: test_tensor_stream_timeout.cpp & exit /b 1 )

echo === link test_tensor_stream_timeout.exe ===
link /NOLOGO /OUT:"build\test_tensor_stream_timeout.exe" "build\test_tensor_stream_timeout.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE
if errorlevel 1 ( echo FAILED: test_tensor_stream_timeout.exe & exit /b 1 )

echo === INCR BUILD OK ===
