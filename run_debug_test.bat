@echo off
set "msvcPath=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64"
set "msvcInc=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\include"
set "msvcLib=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\lib\x64"
set "sdkInc=C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0"
set "sdkLib=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0"
set "PATH=%msvcPath%;%PATH%"
set "INCLUDE=%msvcInc%;%sdkInc%\ucrt;%sdkInc%\um;%sdkInc%\shared"
set "LIB=%msvcLib%;%sdkLib%\um\x64;%sdkLib%\ucrt\x64"
cd /d %~dp0

set "FL=/std:c++20 /EHsc /permissive- /O2 /utf-8 /I. /Ithird_party/asio/include /Ithird_party/openssl/include /Iinclude"

echo === test_debug_echo.cpp ===
cl %FL% examples\test_debug_echo.cpp /Fo:build\test_debug_echo.obj
if errorlevel 1 goto :err

echo === linking test_debug_echo.exe ===
link /NOLOGO /OUT:"build\test_debug_echo.exe" build\test_debug_echo.obj build\linoh.lib ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE
if errorlevel 1 goto :err

echo === Run ===
build\test_debug_echo.exe
goto :eof

:err
echo FAILED
exit /b 1
