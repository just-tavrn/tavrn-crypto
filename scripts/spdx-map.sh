# SPDX-License-Identifier: MPL-2.0
#
# The license map of scripts/check-spdx.sh (sourced by it): the files it checks and the license of each path, first
# match wins. Keep it in sync with LICENSE.md: everything is MPL-2.0.
# shellcheck shell=bash disable=SC2034 # spdx_files is read by check-spdx.sh

spdx_files=('*.rs' '*.ts' '*.tsx' '*.mjs' '*.js' '*.sh')

license_for() {
  case "$1" in
    pkg/dist/* | */node_modules/* | node_modules/* | target/* | protocol/*) echo skip ;;
    src/* | tests/* | pkg/* | scripts/* | build-wasm.sh) echo MPL-2.0 ;;
    *) echo unmapped ;;
  esac
}
