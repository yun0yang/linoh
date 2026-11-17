#!/usr/bin/env bash
# Run all linoh regression tests compiled by build_native.sh (default build).
cd "$(dirname "$0")/.." || exit 1
declare -a TESTS=(test_relay_server test_phase4 test_state_machine test_x25519_hkdf \
  test_key_schedule test_handshake_msg test_tls13_handshake test_connection_tls13 \
  test_endpoint_tls13 test_pkarr_server test_integration_e2e)
allok=1
for t in "${TESTS[@]}"; do
  exe="build/$t.exe"
  [ -f "$exe" ] || { printf "%-26s MISSING\n" "$t"; allok=0; continue; }
  out=$(./"$exe" 2>&1); rc=$?
  summary=$(echo "$out" | grep -aE "Results:|passed,|FAILED" | tail -1)
  [ -z "$summary" ] && summary="(no summary; exit=$rc)"
  printf "%-26s exit=%-2d %s\n" "$t" "$rc" "$summary"
  [ "$rc" -ne 0 ] && allok=0
done
echo "ALL_OK=$allok"
