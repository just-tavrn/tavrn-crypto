// SPDX-License-Identifier: MPL-2.0
// The configuration of scripts/check-js-licenses.mjs: the JavaScript package of this repository. @tavrn/crypto has no
// runtime dependencies today; the check keeps it that way unless a new dependency is allowed on purpose.
export default {
  packages: ["pkg"],
  // Licenses beyond the common allow-list of check-js-licenses.mjs.
  allowed: [],
  // Packages whose metadata carries no SPDX license, verified against their license file.
  verified: {},
  exceptions: {},
};
