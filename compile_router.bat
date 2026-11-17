@echo off
set "msvcPath=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64"
set "msvcInc=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\include"
set "sdkInc=C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0"
set "sdkLib=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0"
set "msvcLib=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\lib\x64"
set "PATH=%msvcPath%;%PATH%"
set "INCLUDE=%msvcInc%;%sdkInc%\um;%sdkInc%\ucrt;%sdkInc%\shared"
set "LIB=%msvcLib%;%sdkLib%\um\x64;%sdkLib%\ucrt\x64"
cd /d %~dp0
cl /std:c++20 /EHsc /permissive- /O2 /utf-8 /I. /Ithird_party/asio/include /Iinclude src\protocol\router.cpp /c /Fobuild\router.obj
echo Exit code: %ERRORLEVEL%
