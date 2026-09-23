"""Focused acceptance and negative tests for P7.4 scanner facts."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import replace

import pytest
from securecode_ai.adapters import (
    CwePortfolioScanError,
    CwePortfolioScanErrorCode,
    CwePortfolioScanLimits,
    build_go_symbol_index,
    build_javascript_symbol_index,
    build_python_symbol_index,
    build_typescript_symbol_index,
    scan_cwe_portfolio,
)
from securecode_ai.core import SymbolIndex

REPOSITORY_ID = "example/p7-portfolio"
REVISION = "d" * 40


_IndexBuilder = Callable[..., SymbolIndex]


def _index(builder: _IndexBuilder, path: str, source: bytes) -> SymbolIndex:
    return builder(
        repository_id=REPOSITORY_ID,
        revision=REVISION,
        path=path,
        content_sha256=hashlib.sha256(source).hexdigest(),
        source=source,
    )


@pytest.mark.parametrize(
    ("builder", "path", "source"),
    [
        (
            build_python_symbol_index,
            "api/portfolio.py",
            b"import os, subprocess, requests\n"
            b"def check(request, repo):\n"
            b" subprocess.run(request.args.get('cmd'), shell=True)\n"
            b" open(os.path.join('/srv', request.args.get('file')))\n"
            b" requests.get(request.args.get('url'))\n"
            b" repo.get(request.args.get('id'))\n",
        ),
        (
            build_javascript_symbol_index,
            "api/portfolio.js",
            b"function check(req, repo) {\n"
            b" exec(req.query.cmd);\n"
            b" fs.readFile(path.join(root, req.query.file));\n"
            b" fetch(req.query.url);\n"
            b" repo.get(req.params.id);\n"
            b"}\n",
        ),
        (
            build_typescript_symbol_index,
            "api/portfolio.ts",
            b"function check(req: Request, repo: Repo): void {\n"
            b" exec(req.query.cmd);\n"
            b" fs.readFile(path.join(root, req.query.file));\n"
            b" fetch(req.query.url);\n"
            b" repo.get(req.params.id);\n"
            b"}\n",
        ),
        (
            build_go_symbol_index,
            "api/portfolio.go",
            b'package api\nimport ("os"; "os/exec"; "path/filepath"; "net/http")\n'
            b"func check(r *Request, repo Repo) {\n"
            b' exec.Command("sh", "-c", r.URL.Query().Get("cmd"))\n'
            b' os.ReadFile(filepath.Join(root, r.URL.Query().Get("file")))\n'
            b' http.Get(r.URL.Query().Get("url"))\n'
            b' repo.Find(r.URL.Query().Get("id"))\n'
            b"}\n",
        ),
    ],
)
def test_all_declared_cwes_emit_one_direct_fact_per_language(
    builder: _IndexBuilder, path: str, source: bytes
) -> None:
    index = _index(builder, path, source)
    first = scan_cwe_portfolio(index)
    second = scan_cwe_portfolio(index)
    assert first == second
    assert {signal.cwe for signal in first.signals} == {"CWE-78", "CWE-22", "CWE-918", "CWE-862"}
    assert len(first.signals) == 4
    assert all(
        signal.source.end_byte <= len(source) and signal.sink.end_byte <= len(source)
        for signal in first.signals
    )
    assert b"req.query" not in repr(first).encode("utf-8")


@pytest.mark.parametrize(
    ("builder", "path", "source"),
    [
        (
            build_python_symbol_index,
            "api/safe.py",
            b"import os, subprocess, requests\n"
            b"def check(request, repo):\n"
            b" subprocess.run('date', shell=False)\n"
            b" open(os.path.join('/srv', 'readme.txt'))\n"
            b" requests.get('https://api.example.test')\n"
            b" authorize(current_user, request.args.get('id'))\n"
            b" repo.get(request.args.get('id'))\n",
        ),
        (
            build_javascript_symbol_index,
            "api/safe.js",
            b"function check(req, repo) {\n"
            b" exec('date'); fs.readFile(path.join(root, 'readme.txt')); fetch('https://api.example.test');\n"
            b" authorize(currentUser, req.params.id); repo.get(req.params.id);\n"
            b"}\n",
        ),
        (
            build_typescript_symbol_index,
            "api/safe.ts",
            b"function check(req: Request, repo: Repo): void {\n"
            b" exec('date'); fs.readFile(path.join(root, 'readme.txt')); fetch('https://api.example.test');\n"
            b" authorize(currentUser, req.params.id); repo.get(req.params.id);\n"
            b"}\n",
        ),
        (
            build_go_symbol_index,
            "api/safe.go",
            b"package api\nfunc check(r *Request, repo Repo) {\n"
            b' exec.Command("date"); os.ReadFile(filepath.Join(root, "readme.txt")); http.Get("https://api.example.test")\n'
            b' authorize(currentUser, r.URL.Query().Get("id")); repo.Find(r.URL.Query().Get("id"))\n'
            b"}\n",
        ),
    ],
)
def test_constant_and_guarded_controls_emit_no_fact(
    builder: _IndexBuilder, path: str, source: bytes
) -> None:
    assert scan_cwe_portfolio(_index(builder, path, source)).signals == ()


def test_recovered_forged_and_limited_indexes_fail_closed() -> None:
    malformed = b"function broken( {"
    unhealthy = _index(build_javascript_symbol_index, "api/broken.js", malformed)
    with pytest.raises(CwePortfolioScanError) as recovered:
        scan_cwe_portfolio(unhealthy)
    assert recovered.value.code is CwePortfolioScanErrorCode.ANALYSIS_UNAVAILABLE

    source = b"function x(req) { fetch(req.query.url); }"
    healthy = _index(build_javascript_symbol_index, "api/valid.js", source)
    with pytest.raises(CwePortfolioScanError) as limited:
        scan_cwe_portfolio(healthy, limits=CwePortfolioScanLimits(max_source_bytes=1))
    assert limited.value.code is CwePortfolioScanErrorCode.SOURCE_LIMIT
    with pytest.raises(ValueError):
        replace(healthy, source=b"function y() {}")


@pytest.mark.parametrize(
    ("builder", "path", "source"),
    [
        (
            build_python_symbol_index,
            "api/unrelated.py",
            b"import requests\n"
            b"def check(request, repo):\n"
            b" requests.get('https://api.example.test', headers={'X': request.args.get('header')})\n"
            b" repo.get('constant', request.args.get('audit'))\n",
        ),
        (
            build_javascript_symbol_index,
            "api/unrelated.js",
            b"function check(req, repo) {\n"
            b" fetch('https://api.example.test', {headers: {X: req.query.header}});\n"
            b" repo.get('constant', req.params.audit);\n"
            b"}\n",
        ),
    ],
)
def test_sources_outside_security_relevant_sink_argument_emit_no_fact(
    builder: _IndexBuilder, path: str, source: bytes
) -> None:
    assert scan_cwe_portfolio(_index(builder, path, source)).signals == ()


def test_pathlib_joinpath_with_request_segment_emits_path_traversal_fact() -> None:
    source = (
        b"from pathlib import Path\n"
        b"def read(request, root):\n"
        b" return Path(root).joinpath(request.args.get('file')).read_text()\n"
    )

    result = scan_cwe_portfolio(_index(build_python_symbol_index, "api/read.py", source))

    assert tuple(signal.cwe for signal in result.signals) == ("CWE-22",)


def test_open_with_request_args_subscription_emits_path_traversal_fact() -> None:
    source = (
        b"import os\ndef read(request):\n return open(os.path.join('/srv', request.args['file']))\n"
    )

    result = scan_cwe_portfolio(_index(build_python_symbol_index, "api/read.py", source))

    assert tuple(signal.cwe for signal in result.signals) == ("CWE-22",)


def test_pathlib_joinpath_with_constant_segment_emits_no_path_traversal_fact() -> None:
    source = (
        b"from pathlib import Path\n"
        b"def read(root):\n"
        b" return Path(root).joinpath('readme.txt').read_text()\n"
    )

    assert (
        scan_cwe_portfolio(_index(build_python_symbol_index, "api/read.py", source)).signals == ()
    )


@pytest.mark.parametrize(
    ("builder", "path", "source"),
    [
        (
            build_javascript_symbol_index,
            "api/read.js",
            b"function read(req) { fs.promises.readFile(path.join(root, req.query.file)); }\n",
        ),
        (
            build_typescript_symbol_index,
            "api/read.ts",
            b"function read(req: Request): void { fs.promises.readFile(path.join(root, req.query.file)); }\n",
        ),
    ],
)
def test_fs_promises_read_file_with_request_path_emits_path_traversal_fact(
    builder: _IndexBuilder, path: str, source: bytes
) -> None:
    result = scan_cwe_portfolio(_index(builder, path, source))

    assert tuple(signal.cwe for signal in result.signals) == ("CWE-22",)


@pytest.mark.parametrize(
    ("builder", "path", "source"),
    [
        (
            build_javascript_symbol_index,
            "api/read.js",
            b"function read() { fs.promises.readFile(path.join(root, 'readme.txt')); }\n",
        ),
        (
            build_typescript_symbol_index,
            "api/read.ts",
            b"function read(): void { fs.promises.readFile(path.join(root, 'readme.txt')); }\n",
        ),
    ],
)
def test_fs_promises_read_file_with_constant_path_emits_no_path_traversal_fact(
    builder: _IndexBuilder, path: str, source: bytes
) -> None:
    assert scan_cwe_portfolio(_index(builder, path, source)).signals == ()


def test_go_local_path_flow_from_query_to_read_file_emits_path_traversal_fact() -> None:
    source = (
        b'package api\nimport ("net/http"; "os"; "path/filepath")\n'
        b"func read(w http.ResponseWriter, r *http.Request) {\n"
        b' name := r.URL.Query().Get("file")\n'
        b" path := filepath.Join(root, name)\n"
        b" _, _ = os.ReadFile(path)\n"
        b"}\n"
    )

    result = scan_cwe_portfolio(_index(build_go_symbol_index, "api/read.go", source))

    assert tuple(signal.cwe for signal in result.signals) == ("CWE-22",)


def test_go_local_constant_path_flow_emits_no_path_traversal_fact() -> None:
    source = (
        b'package api\nimport ("net/http"; "os"; "path/filepath")\n'
        b"func read(w http.ResponseWriter, r *http.Request) {\n"
        b' name := "readme.txt"\n'
        b" path := filepath.Join(root, name)\n"
        b" _, _ = os.ReadFile(path)\n"
        b"}\n"
    )

    assert scan_cwe_portfolio(_index(build_go_symbol_index, "api/read.go", source)).signals == ()


def test_os_system_with_request_args_emits_command_injection_fact() -> None:
    source = b"import os\ndef run(request):\n os.system(request.args.get('cmd'))\n"

    result = scan_cwe_portfolio(_index(build_python_symbol_index, "api/run.py", source))

    assert tuple(signal.cwe for signal in result.signals) == ("CWE-78",)


def test_os_system_with_constant_command_emits_no_command_injection_fact() -> None:
    source = b"import os\ndef run():\n os.system('date')\n"

    assert scan_cwe_portfolio(_index(build_python_symbol_index, "api/run.py", source)).signals == ()


@pytest.mark.parametrize(
    ("builder", "path", "post_guard", "unrelated_guard", "matching_guard"),
    [
        (
            build_python_symbol_index,
            "api/guards.py",
            b"def check(request, repo):\n repo.get(request.args.get('id'))\n authorize(current_user, request.args.get('id'))\n",
            b"def check(request, repo):\n authorize(current_user, request.args.get('other'))\n repo.get(request.args.get('id'))\n",
            b"def check(request, repo):\n authorize(current_user, request.args.get('id'))\n repo.get(request.args.get('id'))\n",
        ),
        (
            build_javascript_symbol_index,
            "api/guards.js",
            b"function check(req, repo) { repo.get(req.params.id); authorize(currentUser, req.params.id); }\n",
            b"function check(req, repo) { authorize(currentUser, req.params.other); repo.get(req.params.id); }\n",
            b"function check(req, repo) { authorize(currentUser, req.params.id); repo.get(req.params.id); }\n",
        ),
    ],
)
def test_authorization_suppression_requires_prior_matching_identity(
    builder: _IndexBuilder,
    path: str,
    post_guard: bytes,
    unrelated_guard: bytes,
    matching_guard: bytes,
) -> None:
    assert {
        signal.cwe for signal in scan_cwe_portfolio(_index(builder, path, post_guard)).signals
    } == {"CWE-862"}
    assert {
        signal.cwe for signal in scan_cwe_portfolio(_index(builder, path, unrelated_guard)).signals
    } == {"CWE-862"}
    assert scan_cwe_portfolio(_index(builder, path, matching_guard)).signals == ()
