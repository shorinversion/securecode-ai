"""Focused ECMAScript CWE-307 discovery behavior."""

from __future__ import annotations

import hashlib

from securecode_ai.adapters.cst import build_javascript_symbol_index
from securecode_ai.adapters.ecmascript_cwe307 import scan_javascript_cwe307
from securecode_ai.core import SymbolIndex


def _index(source: bytes) -> SymbolIndex:
    return build_javascript_symbol_index(
        repository_id="example/ecmascript-cwe307",
        revision="d" * 40,
        path="src/login.js",
        content_sha256=hashlib.sha256(source).hexdigest(),
        source=source,
    )


def test_express_login_route_candidate_is_analysed_without_failing() -> None:
    # Regression: the scanner tuple-unpacked the _RouteCandidate dataclass, so
    # every framework login route raised TypeError instead of being analysed.
    source = b"""const express = require("express");
const bcrypt = require("bcrypt");
const app = express();
app.post("/login", async (req, res) => {
  const ok = await bcrypt.compare(req.body.password, user.passwordHash);
  res.send(ok);
});
"""

    result = scan_javascript_cwe307(_index(source))

    assert result.path == "src/login.js"
