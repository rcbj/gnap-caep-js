// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// minimatch 11 is the first release without GHSA-g3hv-75wg-m249 (pattern
// amplification), and it made Minimatch#matchOne private. TypeDoc 0.28.20,
// the latest, still calls it in one place, deciding whether to descend into a
// directory while expanding a glob:
//
//   mini.set.some((row) => mini.matchOne(childPath, row, /* partial */ true))
//
// The public match(path, partial) runs that same test over every row of the
// set, so for TypeDoc's call it gives the same answer. Loaded with
// `node --import` before TypeDoc (package.json's typedoc script). Remove it
// when TypeDoc no longer calls matchOne.
import { Minimatch } from 'minimatch';

if (typeof Minimatch.prototype.matchOne !== 'function') {
  Minimatch.prototype.matchOne = function matchOne(file, _row, partial = false) {
    return this.match(Array.isArray(file) ? file.join('/') : String(file), partial);
  };
}
