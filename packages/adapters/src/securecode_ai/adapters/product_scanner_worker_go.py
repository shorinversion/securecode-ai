"""Scan go rules detector group."""

from __future__ import annotations

from securecode_ai.contracts import ProducerRef, RawSignal
from securecode_ai.core.scanning import ScannerRequest
from securecode_ai.core.symbols import SymbolIndex

from . import (
    go_cwe117,
    go_cwe1333,
    go_cwe209,
    go_cwe22,
    go_cwe295,
    go_cwe307,
    go_cwe327,
    go_cwe338,
    go_cwe352,
    go_cwe367,
    go_cwe400,
    go_cwe476,
    go_cwe502,
    go_cwe521,
    go_cwe532,
    go_cwe598,
    go_cwe601,
    go_cwe613,
    go_cwe614,
    go_cwe776,
    go_cwe78,
    go_cwe79,
    go_cwe798,
    go_cwe_crypto,
    go_cwe90,
    go_cwe918,
)
from .product_scanner_worker_support import _fact_to_raw_signal


def scan_go_rules(
    *,
    index: SymbolIndex,
    request: ScannerRequest,
    producer: ProducerRef,
) -> list[RawSignal]:
    signals = []
    credentials = go_cwe798.scan_go_cwe798(index)
    for ordinal, signal in enumerate(credentials.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=signal.cwe,
                detector=signal.detector,
                location=signal.sink,
                scan_sha256=credentials.scan_sha256,
                ordinal=ordinal,
                rule_id=signal.rule_id,
            )
        )
    password_policy = go_cwe521.scan_go_cwe521(index)
    for ordinal, signal in enumerate(password_policy.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=signal.cwe,
                detector=signal.detector,
                location=signal.sink,
                scan_sha256=password_policy.scan_sha256,
                ordinal=ordinal,
            )
        )
    weak_randomness = go_cwe338.scan_go_cwe338(index)
    for ordinal, signal in enumerate(weak_randomness.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=signal.cwe,
                detector=signal.detector,
                location=signal.sink,
                scan_sha256=weak_randomness.scan_sha256,
                ordinal=ordinal,
            )
        )
    session_expiration = go_cwe613.scan_go_cwe613(index)
    for ordinal, signal in enumerate(session_expiration.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=signal.cwe,
                detector=signal.detector,
                location=signal.sink,
                scan_sha256=session_expiration.scan_sha256,
                ordinal=ordinal,
            )
        )
    error_disclosure = go_cwe209.scan_go_cwe209(index)
    for ordinal, signal in enumerate(error_disclosure.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=signal.cwe,
                detector=signal.detector,
                location=signal.sink,
                scan_sha256=error_disclosure.scan_sha256,
                ordinal=ordinal,
            )
        )
    xml_expansion = go_cwe776.scan_go_cwe776(index)
    for ordinal, signal in enumerate(xml_expansion.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=signal.cwe,
                detector=signal.detector,
                location=signal.sink,
                scan_sha256=xml_expansion.scan_sha256,
                ordinal=ordinal,
            )
        )
    sensitive_logging = go_cwe532.scan_go_cwe532(index)
    for ordinal, signal in enumerate(sensitive_logging.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=signal.cwe,
                detector=signal.detector,
                location=signal.sink,
                scan_sha256=sensitive_logging.scan_sha256,
                ordinal=ordinal,
            )
        )
    rate_limit = go_cwe307.scan_go_cwe307(index)
    for ordinal, signal in enumerate(rate_limit.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=signal.cwe,
                detector=signal.detector,
                location=signal.sink,
                scan_sha256=rate_limit.scan_sha256,
                ordinal=ordinal,
            )
        )
    cookie_security = go_cwe614.scan_go_cwe614(index)
    for ordinal, signal in enumerate(cookie_security.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=signal.cwe,
                detector=signal.detector,
                location=signal.sink,
                scan_sha256=cookie_security.scan_sha256,
                ordinal=ordinal,
                rule_id=signal.rule_id,
            )
        )
    log_injection = go_cwe117.scan_go_cwe117(index)
    for ordinal, signal in enumerate(log_injection.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=signal.cwe,
                detector=signal.detector,
                location=signal.sink,
                scan_sha256=log_injection.scan_sha256,
                ordinal=ordinal,
                rule_id=signal.rule_id,
            )
        )
    sensitive_query_data = go_cwe598.scan_go_cwe598(index)
    for ordinal, signal in enumerate(sensitive_query_data.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=signal.cwe,
                detector=signal.detector,
                location=signal.sink,
                scan_sha256=sensitive_query_data.scan_sha256,
                ordinal=ordinal,
                rule_id=signal.rule_id,
            )
        )
    weak_crypto = go_cwe327.scan_go_cwe327(index)
    for ordinal, signal in enumerate(weak_crypto.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=signal.cwe,
                detector=signal.detector,
                location=signal.sink,
                scan_sha256=weak_crypto.scan_sha256,
                ordinal=ordinal,
            )
        )
    resource_consumption = go_cwe400.scan_go_cwe400(index)
    for ordinal, signal in enumerate(resource_consumption.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=signal.cwe,
                detector=signal.detector,
                location=signal.sink,
                scan_sha256=resource_consumption.scan_sha256,
                ordinal=ordinal,
            )
        )
    toctou = go_cwe367.scan_go_cwe367(index)
    for ordinal, signal in enumerate(toctou.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=signal.cwe,
                detector=signal.detector,
                location=signal.sink,
                scan_sha256=toctou.scan_sha256,
                ordinal=ordinal,
            )
        )
    regex_dos = go_cwe1333.scan_go_cwe1333(index)
    for ordinal, signal in enumerate(regex_dos.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=signal.cwe,
                detector=signal.detector,
                location=signal.sink,
                scan_sha256=regex_dos.scan_sha256,
                ordinal=ordinal,
            )
        )
    tls_validation = go_cwe295.scan_go_cwe295(index)
    for ordinal, signal in enumerate(tls_validation.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=signal.cwe,
                detector=signal.detector,
                location=signal.sink,
                scan_sha256=tls_validation.scan_sha256,
                ordinal=ordinal,
            )
        )
    deserialization = go_cwe502.scan_go_cwe502(index)
    for ordinal, signal in enumerate(deserialization.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=signal.cwe,
                detector=signal.detector,
                location=signal.sink,
                scan_sha256=deserialization.scan_sha256,
                ordinal=ordinal,
            )
        )
    xss = go_cwe79.scan_go_cwe79(index)
    for ordinal, signal in enumerate(xss.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=signal.cwe,
                detector=signal.detector,
                location=signal.sink,
                scan_sha256=xss.scan_sha256,
                ordinal=ordinal,
            )
        )
    redirects = go_cwe601.scan_go_cwe601(index)
    for ordinal, signal in enumerate(redirects.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=signal.cwe,
                detector=signal.detector,
                location=signal.sink,
                scan_sha256=redirects.scan_sha256,
                ordinal=ordinal,
            )
        )
    commands = go_cwe78.scan_go_cwe78(index)
    for ordinal, signal in enumerate(commands.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=signal.cwe,
                detector=signal.detector,
                location=signal.sink,
                scan_sha256=commands.scan_sha256,
                ordinal=ordinal,
                rule_id="portfolio-cwe-78",
            )
        )
    ldap = go_cwe90.scan_go_cwe90(index)
    for ordinal, signal in enumerate(ldap.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=signal.cwe,
                detector=signal.detector,
                location=signal.sink,
                scan_sha256=ldap.scan_sha256,
                ordinal=ordinal,
            )
        )
    crypto = go_cwe_crypto.scan_go_cwe_crypto(index)
    for ordinal, signal in enumerate(crypto.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=signal.cwe,
                detector=signal.detector,
                location=signal.sink,
                scan_sha256=crypto.scan_sha256,
                ordinal=ordinal,
            )
        )
    paths = go_cwe22.scan_go_cwe22(index)
    for ordinal, signal in enumerate(paths.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe="CWE-22",
                detector=signal.detector,
                location=signal.sink,
                scan_sha256=paths.scan_sha256,
                ordinal=ordinal,
                rule_id="portfolio-cwe-22",
            )
        )
    ssrf = go_cwe918.scan_go_cwe918(index)
    for ordinal, signal in enumerate(ssrf.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=signal.cwe,
                detector=signal.detector,
                location=signal.sink,
                scan_sha256=ssrf.scan_sha256,
                ordinal=ordinal,
                rule_id="portfolio-cwe-918",
            )
        )
    csrf = go_cwe352.scan_go_cwe352(index)
    for ordinal, signal in enumerate(csrf.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=signal.cwe,
                detector=signal.detector,
                location=signal.sink,
                scan_sha256=csrf.scan_sha256,
                ordinal=ordinal,
                rule_id=signal.rule_id,
            )
        )
    nil_pointer = go_cwe476.scan_go_cwe476(index)
    for ordinal, signal in enumerate(nil_pointer.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=signal.cwe,
                detector=signal.detector,
                location=signal.sink,
                scan_sha256=nil_pointer.scan_sha256,
                ordinal=ordinal,
                rule_id=signal.rule_id,
            )
        )
    return signals
