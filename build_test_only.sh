#!/usr/bin/env bash
set -u
VSROOT="/c/Program Files/Microsoft Visual Studio/2022/Community"
VC="$VSROOT/VC/Tools/MSVC/14.44.35207"
SDK="/c/Program Files (x86)/Windows Kits/10"
SDKVER="10.0.26100.0"
BINDIR="$VC/bin/Hostx64/x64"
export PATH="$BINDIR:$PATH"
export INCLUDE="$(cygpath -w "$VC/include");$(cygpath -w "$SDK/Include/$SDKVER/ucrt");$(cygpath -w "$SDK/Include/$SDKVER/um");$(cygpath -w "$SDK/Include/$SDKVER/shared");$(cygpath -w "$SDK/Include/$SDKVER/winrt")"
export LIB="$(cygpath -w "$VC/lib/x64");$(cygpath -w "$SDK/Lib/$SDKVER/ucrt/x64");$(cygpath -w "$SDK/Lib/$SDKVER/um/x64")"
CL="$BINDIR/cl.exe"
LINK="$BINDIR/link.exe"
CXXFLAGS="/std:c++20 /EHsc /permissive- /O2 /utf-8 /I. /Iinclude /Ithird_party/asio/include /Ithird_party/openssl/include"
"$CL" $CXXFLAGS "$(cygpath -w tests/test_relay_server.cpp)" /c "/Fo:$(cygpath -w build/test_relay_server.obj)" || { echo "TEST COMPILE FAILED"; exit 1; }
"$LINK" /NOLOGO "/OUT:$(cygpath -w build/test_relay_server.exe)" "$(cygpath -w build/test_relay_server.obj)" "$(cygpath -w build/linoh.lib)" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE || { echo "TEST LINK FAILED"; exit 1; }
echo "TEST BUILD OK"
