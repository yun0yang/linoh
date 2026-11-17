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

echo === handshake_token_key.obj ===
cl /std:c++20 /EHsc /permissive- /O2 /utf-8 /I. /Ithird_party/asio/include /Iinclude src\tls\handshake_token_key.cpp /c /Fobuild\handshake_token_key.obj
if errorlevel 1 goto :eof
echo OK.

echo === connection.obj ===
cl /std:c++20 /EHsc /permissive- /O2 /utf-8 /I. /Ithird_party/asio/include /Iinclude src\endpoint\connection.cpp /c /Fobuild\connection.obj
if errorlevel 1 goto :eof
echo OK.

echo === linoh_c.obj ===
cl /std:c++20 /EHsc /permissive- /O2 /utf-8 /I. /Ithird_party/asio/include /Iinclude src\linoh_c.cpp /c /Fobuild\linoh_c.obj
if errorlevel 1 goto :eof
echo OK.

echo === linoh.lib ===
if exist "build\linoh.lib" del /F /Q "build\linoh.lib"
lib /NOLOGO /OUT:"build\linoh.lib" ^
  "build\builder.obj" ^
  "build\connection.obj" ^
  "build\crypto.obj" ^
  "build\crypto_provider.obj" ^
  "build\ed25519_verifier.obj" ^
  "build\endpoint.obj" ^
  "build\endpoint_addr.obj" ^
  "build\handshake_token_key.obj" ^
  "build\key.obj" ^
  "build\packet.obj" ^
  "build\router.obj" ^
  "build\socket.obj" ^
  "build\udp_transport.obj" ^
  "build\linoh_c.obj" ^
  "build\evp_stub.obj"
echo lib: %ERRORLEVEL%
dir "build\linoh.lib"
