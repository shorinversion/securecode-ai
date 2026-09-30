"""English slides and narration for docs/media/build_video.py."""

SLIDES_EN: list[tuple[str, str]] = [
    (
        """<div class="pills"><span class="pill">MTS True Tech</span><span class="pill dark">Final project · task 2</span><span class="pill light">Version 1.0</span></div>
<h1>SecureCode AI</h1><p style="font-size:48px;max-width:1400px">A local AI assistant for code security audits: it finds vulnerabilities, proposes fixes and validates them without sending code to the cloud.</p>""",
        "SecureCode AI is a local assistant for code security audits. It finds vulnerabilities, "
        "proposes fixes and validates them, without sending source code to the cloud. "
        "This is the final project, task two, version one point zero.",
    ),
    (
        """<h2>The problem</h2><div class="grid g2"><div class="card"><h3>Problem</h3><p class="muted">Static analyzers follow rigid rules and produce many false positives. Private code must not be sent to public cloud APIs.</p></div>
<div class="card"><h3>Solution</h3><p class="muted">A quantized open-source model runs locally together with code analysis tools: it understands context, finds the vulnerability and writes a safe patch.</p></div></div>""",
        "Classic analyzers follow rigid rules and flood developers with false positives, "
        "while sending private code to external cloud services is forbidden. So we run a "
        "quantized model locally, together with code analysis tools.",
    ),
    (
        """<h2>Architecture</h2><div class="flow"><span>Git snapshot: Python, JS/TS, Go</span><b>→</b><span>Tools: AST, secrets, OSV, rules for 35 CWEs</span><b>+</b><span>Discovery (LLM)</span><b>→</b><span>Evidence graph</span><b>→</b><span>Auditor (LLM)</span><b>→</b><span>Skeptic (LLM)</span><b>→</b><span>Architect: diff</span><b>→</b><span>Validation in a copy</span><b>→</b><span>OWASP Top 10 report</span></div>
<div class="grid g4" style="margin-top:56px"><div class="card"><h3>Discovery</h3><p class="muted">searches independently of the scanners, any of 139 CWEs</p></div><div class="card"><h3>Auditor</h3><p class="muted">checks every candidate against the code</p></div><div class="card"><h3>Skeptic</h3><p class="muted">tries to refute a finding before it is accepted</p></div><div class="card"><h3>Architect</h3><p class="muted">writes a patch only for a confirmed finding</p></div></div>""",
        "The system reads an exact snapshot of the repository. The tools build syntax trees, look "
        "for secrets, vulnerable library versions and thirty-five kinds of vulnerabilities by rule. "
        "In parallel, the Discovery agent searches for vulnerabilities on its own, without being "
        "limited to that list. The Auditor agent checks every candidate against the code, and "
        "the Skeptic agent tries to refute its conclusion. Only a "
        "confirmed finding is fixed by the Architect agent, and the system validates the patch "
        "in a temporary copy and builds the report. In the short demo the deterministic scanner "
        "acts as the second opinion.",
    ),
    (
        """<h2>Live run: Qwen</h2><pre>$ python deploy/docker/quickstart.py --demo --provider local

Model       qwen2.5-coder:7b-instruct-q4_K_M (Ollama)
Auditor     SUCCEEDED     finding matches the scanner
Architect   SUCCEEDED     patch proposed
Validation  PASSED        parse OK, rescan: 0 signals
Outcome     <span class="add">COMPLETED</span></pre>""",
        "One command runs it on the local Qwen 2.5 Coder model with seven billion parameters "
        "and four-bit quantization. The Auditor found an SQL injection that matches the "
        "deterministic scanner. The Architect proposed a fix, and the patch passed parsing and "
        "a rescan. The outcome is completed.",
    ),
    (
        """<h2>Audit report</h2><table><tr><th>CWE</th><th>OWASP Top 10</th><th>Severity</th><th>Location</th><th>Found by</th></tr><tr><td>CWE-89</td><td>A03:2021 Injection</td><td>HIGH</td><td>app.py:5</td><td>scanner + model</td></tr></table>
<pre style="margin-top:36px"><span class="del">-    return conn.execute("SELECT * FROM users WHERE name = '" + name + "'")</span>
<span class="add">+    return conn.execute("SELECT * FROM users WHERE name = ?", (name,))</span></pre>
<p class="muted" style="margin-top:34px">Same result on DeepSeek: 2 calls, $0.00014.</p>""",
        "The report shows the CWE number, the OWASP Top 10 category, the severity, the line and "
        "a ready diff: string concatenation is replaced with a parameterized query. The same "
        "scenario on DeepSeek gave the same result for less than a hundredth of a cent.",
    ),
    (
        """<h2>Tools</h2><div class="grid g4"><div class="card"><h3>Secrets</h3><p class="muted">password in app.py found, value hidden</p></div><div class="card"><h3>Dependencies</h3><p class="muted">requests 2.19.0: 10 vulnerabilities from OSV</p></div><div class="card"><h3>JavaScript</h3><p class="muted">SQL injection and missing authentication</p></div><div class="card"><h3>Contract</h3><p class="muted">file, lines, CWE and hash in one schema</p></div></div>
<p class="muted" style="margin-top:44px">Full run with stored outputs: notebooks/securecode_demo.ipynb on GitHub</p>""",
        "The notebook shows every tool on a small project. A hardcoded password is found and its "
        "value is hidden. For an old version of the requests library, the OSV database returned "
        "ten vulnerabilities. In the JavaScript file, SQL injection and missing authentication "
        "are found. Every finding uses one schema: file, lines, CWE and content hash.",
    ),
    (
        """<h2>Experiments</h2><table><tr><th>600 CVEfixes cases</th><th>Precision</th><th>Recall</th><th>F1</th></tr><tr><td>SecureCode scanners</td><td class="n">49.0%</td><td class="n">25.7%</td><td class="n">33.7%</td></tr><tr><td>DeepSeek, one-shot</td><td class="n">52.0%</td><td class="n">22.7%</td><td class="n">31.6%</td></tr><tr class="hi"><td>Hybrid: scanners + DeepSeek</td><td class="n">49.9%</td><td class="n">35.8%</td><td class="n">41.7%</td></tr><tr><td>Semgrep 1.177.0</td><td class="n">50.0%</td><td class="n">34.3%</td><td class="n">40.7%</td></tr></table>
<p class="muted">On the held-out split the hybrid is on par with Semgrep: 32.8% vs 32.5%, not a significant difference.</p>""",
        "On six hundred CVEfixes cases, the hybrid of scanners and the model finds the most "
        "vulnerabilities, almost thirty-six percent. On the held-out split it is on par with "
        "Semgrep, with no significant advantage. Scanner fixes raised their recall from twenty "
        "to twenty-six percent.",
    ),
    (
        """<h2>Summary</h2><div class="grid g3"><div class="card"><div class="num">1</div><p class="muted">command to run the demo</p></div><div class="card"><div class="num">3292</div><p class="muted">automated tests in CI</p></div><div class="card"><div class="num">2</div><p class="muted">models: local Qwen and DeepSeek</p></div></div>
<pre style="margin-top:48px">git clone https://github.com/shorinversion/securecode-ai
python deploy/docker/quickstart.py --demo</pre>""",
        "The project starts with one command, is covered by more than three thousand automated "
        "tests and works with both a local and a cloud model. Next come detector precision and "
        "an evaluation of the full agent pipeline on a larger corpus. Thank you.",
    ),
]
