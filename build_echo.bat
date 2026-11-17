@echo off
set "msvcPath=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64"
set "msvcInc=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\include"
set "msvcLib=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\lib\x64"
set "sdkInc=C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0"
set "sdkLib=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0"
set "PATH=%msvcPath%;%PATH%"
set "INCLUDE=%msvcInc%;%sdkInc%\um;%sdkInc%\ucrt;%sdkInc%\shared"
set "LIB=%msvcLib%;%sdkLib%\um\x64;%sdkLib%\ucrt\x64"
cd /d %~dp0

if not exist build mkdir build

set "FL=/std:c++20 /EHsc /permissive- /O2 /utf-8 /I. /Ithird_party/asio/include /Ithird_party/openssl/include /Iinclude"

echo === linoh_echo_server.cpp ===
cl %FL% examples\linoh_echo_server.cpp /c /Fo:build\linoh_echo_server.obj
if errorlevel 1 goto :err

echo === linoh_echo_client.cpp ===
cl %FL% examples\linoh_echo_client.cpp /c /Fo:build\linoh_echo_client.obj
if errorlevel 1 goto :err

echo === linking linoh_echo_server.exe ===
link /NOLOGO /OUT:"build\linoh_echo_server.exe" "build\linoh_echo_server.obj" "build\linoh.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE
if errorlevel 1 goto :err

echo === linking linoh_echo_client.exe ===
link /NOLOGO /OUT:"build\linoh_echo_client.exe" "build\linoh_echo_client.obj" "build\linoh.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE
if errorlevel 1 goto :err

echo === Build Success ===
dir "build\linoh_echo_*.exe"
goto :eof

:err
echo === Build FAILED ===
exit /b 1
