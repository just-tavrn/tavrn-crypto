#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# Tests how build-wasm.sh picks the wasm-bindgen CLI, with stubs instead of the real cargo and wasm-bindgen:
# a stale wasm-bindgen earlier on PATH (as /usr/local/bin in the CI runner image) must not be used once the
# version of Cargo.lock is installed, and an install that still gives another version must fail.
# Usage: scripts/test-build-wasm.sh
set -euo pipefail
cd "$(dirname "$0")/.."

want=$(awk '$0 == "name = \"wasm-bindgen\"" { getline; gsub(/version = |"/, ""); print; exit }' Cargo.lock)
stale=0.2.129
[ "$want" != "$stale" ] || stale=0.2.128

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failures=0

# stub_bindgen DIR VERSION: a wasm-bindgen that only answers --version
stub_bindgen() {
  mkdir -p "$1"
  printf '#!/usr/bin/env bash\necho "wasm-bindgen %s"\n' "$2" >"$1/wasm-bindgen"
  chmod +x "$1/wasm-bindgen"
}

# A cargo whose `install` writes a wasm-bindgen stub of $STUB_INSTALL_VERSION (default: the requested version)
# into --root, or into $CARGO_INSTALL_ROOT / $CARGO_HOME like cargo does, and logs every call.
mkdir -p "$tmp/fake"
cat >"$tmp/fake/cargo" <<'EOF'
#!/usr/bin/env bash
echo "cargo $*" >>"$STUB_LOG"
[ "${1:-}" = install ] || exit 0
root="${CARGO_INSTALL_ROOT:-$CARGO_HOME}" version=
while [ $# -gt 0 ]; do
  case "$1" in
    --root) root=$2; shift ;;
    --version) version=$2; shift ;;
  esac
  shift
done
mkdir -p "$root/bin"
printf '#!/usr/bin/env bash\necho "wasm-bindgen %s"\n' "${STUB_INSTALL_VERSION:-$version}" >"$root/bin/wasm-bindgen"
chmod +x "$root/bin/wasm-bindgen"
EOF
chmod +x "$tmp/fake/cargo"

# fresh: an empty CARGO_HOME and an empty stale directory
fresh() {
  rm -rf "$tmp/home" "$tmp/stale"
  mkdir -p "$tmp/home" "$tmp/stale"
}

# run [VAR=VALUE ...]: build-wasm.sh --install-only with $tmp/stale first on PATH; sets $out, $status and $log
log="$tmp/log"
run() {
  : >"$log"
  status=0
  out=$(env "$@" CARGO_HOME="$tmp/home" STUB_LOG="$log" PATH="$tmp/stale:$tmp/fake:$PATH" \
    ./build-wasm.sh --install-only 2>"$tmp/err") || status=$?
}

check() {
  if eval "$2"; then
    echo "ok: $1"
  else
    echo "FAIL: $1 (stdout: $out; stderr: $(tr '\n' ' ' <"$tmp/err"))" >&2
    failures=$((failures + 1))
  fi
}

# 1. A stale wasm-bindgen first on PATH: the matching version is installed and selected.
fresh
stub_bindgen "$tmp/stale" "$stale"
run
check "stale binary on PATH: exit 0" '[ "$status" -eq 0 ]'
check "stale binary on PATH: the installed $want is selected" '[ "$out" = "$tmp/home/bin/wasm-bindgen" ]'
check "stale binary on PATH: the selected binary reports $want" \
  '[ "$("$tmp/home/bin/wasm-bindgen" --version 2>/dev/null)" = "wasm-bindgen $want" ]'

# 2. The matching version already installed in CARGO_HOME, a stale one first on PATH: no new install.
fresh
stub_bindgen "$tmp/stale" "$stale"
stub_bindgen "$tmp/home/bin" "$want"
run
check "installed in CARGO_HOME: selected" '[ "$status" -eq 0 ] && [ "$out" = "$tmp/home/bin/wasm-bindgen" ]'
check "installed in CARGO_HOME: no cargo install" '! grep -q "cargo install" "$log"'

# 3. The matching version first on PATH: used as it is.
fresh
stub_bindgen "$tmp/stale" "$want"
run
check "matching binary on PATH: selected" '[ "$status" -eq 0 ] && [ "$out" = "$tmp/stale/wasm-bindgen" ]'
check "matching binary on PATH: no cargo install" '! grep -q "cargo install" "$log"'

# 4. An install that still gives another version: a clear error instead of a build with the wrong CLI.
fresh
stub_bindgen "$tmp/stale" "$stale"
run STUB_INSTALL_VERSION=0.0.1
check "wrong version after install: fails" '[ "$status" -ne 0 ]'
check "wrong version after install: says so" 'grep -q "0.0.1" "$tmp/err" && grep -q "$want" "$tmp/err"'

if [ "$failures" -gt 0 ]; then
  echo "test-build-wasm: $failures failed" >&2
  exit 1
fi
echo "test-build-wasm: ok"
