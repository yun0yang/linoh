@echo off
setlocal enabledelayedexpansion
cd /d %~dp0\build
set PASS=0
set FAIL=0
set FAILED_LIST=
for %%F in (test_*.exe) do (
    %%F >nul 2>&1
    if !ERRORLEVEL! EQU 0 (
        set /a PASS+=1
    ) else (
        set /a FAIL+=1
        set FAILED_LIST=!FAILED_LIST! %%F(exit=!ERRORLEVEL!)
    )
)
echo.
echo === TEST RESULTS ===
echo PASS: !PASS!
echo FAIL: !FAIL!
if not "!FAILED_LIST!"=="" echo FAILED: !FAILED_LIST!
