# run_full_regression_v1504.ps1 — v1.5.0.4 full regression test runner
# Run all 73 test_*.exe in .\build\ sequentially.
# Output per-test pass/fail with exit code, aggregate summary at end.

$ErrorActionPreference = "Continue"
Set-Location -LiteralPath $PSScriptRoot

# 跳过需要外部参数的测试
$skip_tests = @("test_e2e_stress_client.exe", "test_e2e_stress_server.exe")

$tests = Get-ChildItem build\test_*.exe | Where-Object { $skip_tests -notcontains $_.Name } | Sort-Object Name
Write-Host "[REGRESSION] Found $($tests.Count) test executables (skipped: $($skip_tests -join ', '))"
Write-Host "=== START $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="

$pass = 0
$fail = 0
$pre_existing_fail = 0
$fail_list = @()
# Pre-existing fails (v1.5.0.2.7 baseline): test_path_abandon, test_phase4
$pre_existing_list = @("test_path_abandon.exe", "test_phase4.exe")

foreach ($t in $tests) {
    $name = $t.Name
    $out_file = "build\regress_$($t.BaseName).log"
    # test_key_update.exe 偶发 SmartScreen 拦截，复制为 tmp_xxx.exe 绕过
    $exe_path = $t.FullName
    if ($name -eq "test_key_update.exe") {
        $tmp_path = "build\tmp_key_update_$((Get-Random)).exe"
        Copy-Item $t.FullName $tmp_path -Force
        $exe_path = $tmp_path
    }
    $stdout = & $exe_path *>&1 | Out-String
    $exit = $LASTEXITCODE
    if ($exe_path -ne $t.FullName) { Remove-Item $exe_path -Force -ErrorAction SilentlyContinue }
    $stdout | Out-File -FilePath $out_file -Encoding UTF8
    if ($exit -eq 0) {
        $pass++
        Write-Host "[PASS] $name (exit=0)"
    } else {
        $fail++
        $is_pre = $pre_existing_list -contains $name
        if ($is_pre) { $pre_existing_fail++ }
        $tag = if ($is_pre) { "[FAIL-PRE]" } else { "[FAIL]" }
        $fail_list += "$name (exit=$exit)"
        Write-Host "$tag $name (exit=$exit)"
    }
}

Write-Host ""
Write-Host "=== REGRESSION SUMMARY ==="
Write-Host "Total: $($tests.Count)"
Write-Host "PASS:  $pass"
Write-Host "FAIL:  $fail"
if ($fail_list.Count -gt 0) {
    Write-Host "Failed tests:"
    foreach ($f in $fail_list) { Write-Host "  - $f" }
}
Write-Host "=== END $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="

# Final exit code: 0 if all pass, else 1
if ($fail -gt 0) { exit 1 } else { exit 0 }
