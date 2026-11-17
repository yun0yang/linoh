@echo off
set "msvcPath=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64"
set "PATH=%msvcPath%;%PATH%"
set "LIB=%~dp0\build"
if exist "%LIB%\linoh.lib" del /F /Q "%LIB%\linoh.lib"
lib /NOLOGO /OUT:"%LIB%\linoh.lib" ^
  "%LIB%\builder.obj" ^
  "%LIB%\connection.obj" ^
  "%LIB%\crypto.obj" ^
  "%LIB%\crypto_provider.obj" ^
  "%LIB%\ed25519_verifier.obj" ^
  "%LIB%\endpoint.obj" ^
  "%LIB%\endpoint_addr.obj" ^
  "%LIB%\handshake_token_key.obj" ^
  "%LIB%\key.obj" ^
  "%LIB%\packet.obj" ^
  "%LIB%\router.obj" ^
  "%LIB%\socket.obj" ^
  "%LIB%\udp_transport.obj" ^
  "%LIB%\evp_stub.obj"
echo Exit code: %ERRORLEVEL%
dir "%LIB%\linoh.lib"
