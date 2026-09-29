"""Scan go rules detector group."""

from __future__ import annotations

from securecode_ai.contracts import ProducerRef, RawSignal
from securecode_ai.core.scanning import ScannerRequest
from securecode_ai.core.symbols import SymbolIndex

from . import (
    go_cwe22,
    go_cwe78,
    go_cwe79,
    go_cwe90,
    go_cwe117,
    go_cwe209,
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
    go_cwe798,
    go_cwe918,
    go_cwe1333,
    go_cwe_crypto,
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
    for ordinal, credentials_signal in enumerate(credentials.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=credentials_signal.cwe,
                detector=credentials_signal.detector,
                location=credentials_signal.sink,
                scan_sha256=credentials.scan_sha256,
                ordinal=ordinal,
                rule_id=credentials_signal.rule_id,
            )
        )
    password_policy = go_cwe521.scan_go_cwe521(index)
    for ordinal, password_policy_signal in enumerate(password_policy.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=password_policy_signal.cwe,
                detector=password_policy_signal.detector,
                location=password_policy_signal.sink,
                scan_sha256=password_policy.scan_sha256,
                ordinal=ordinal,
            )
        )
    weak_randomness = go_cwe338.scan_go_cwe338(index)
    for ordinal, weak_randomness_signal in enumerate(weak_randomness.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=weak_randomness_signal.cwe,
                detector=weak_randomness_signal.detector,
                location=weak_randomness_signal.sink,
                scan_sha256=weak_randomness.scan_sha256,
                ordinal=ordinal,
            )
        )
    session_expiration = go_cwe613.scan_go_cwe613(index)
    for ordinal, session_expiration_signal in enumerate(session_expiration.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=session_expiration_signal.cwe,
                detector=session_expiration_signal.detector,
                location=session_expiration_signal.sink,
                scan_sha256=session_expiration.scan_sha256,
                ordinal=ordinal,
            )
        )
    error_disclosure = go_cwe209.scan_go_cwe209(index)
    for ordinal, error_disclosure_signal in enumerate(error_disclosure.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=error_disclosure_signal.cwe,
                detector=error_disclosure_signal.detector,
                location=error_disclosure_signal.sink,
                scan_sha256=error_disclosure.scan_sha256,
                ordinal=ordinal,
            )
        )
    xml_expansion = go_cwe776.scan_go_cwe776(index)
    for ordinal, xml_expansion_signal in enumerate(xml_expansion.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=xml_expansion_signal.cwe,
                detector=xml_expansion_signal.detector,
                location=xml_expansion_signal.sink,
                scan_sha256=xml_expansion.scan_sha256,
                ordinal=ordinal,
            )
        )
    sensitive_logging = go_cwe532.scan_go_cwe532(index)
    for ordinal, sensitive_logging_signal in enumerate(sensitive_logging.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=sensitive_logging_signal.cwe,
                detector=sensitive_logging_signal.detector,
                location=sensitive_logging_signal.sink,
                scan_sha256=sensitive_logging.scan_sha256,
                ordinal=ordinal,
            )
        )
    rate_limit = go_cwe307.scan_go_cwe307(index)
    for ordinal, rate_limit_signal in enumerate(rate_limit.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=rate_limit_signal.cwe,
                detector=rate_limit_signal.detector,
                location=rate_limit_signal.sink,
                scan_sha256=rate_limit.scan_sha256,
                ordinal=ordinal,
            )
        )
    cookie_security = go_cwe614.scan_go_cwe614(index)
    for ordinal, cookie_security_signal in enumerate(cookie_security.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=cookie_security_signal.cwe,
                detector=cookie_security_signal.detector,
                location=cookie_security_signal.sink,
                scan_sha256=cookie_security.scan_sha256,
                ordinal=ordinal,
                rule_id=cookie_security_signal.rule_id,
            )
        )
    log_injection = go_cwe117.scan_go_cwe117(index)
    for ordinal, log_injection_signal in enumerate(log_injection.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=log_injection_signal.cwe,
                detector=log_injection_signal.detector,
                location=log_injection_signal.sink,
                scan_sha256=log_injection.scan_sha256,
                ordinal=ordinal,
                rule_id=log_injection_signal.rule_id,
            )
        )
    sensitive_query_data = go_cwe598.scan_go_cwe598(index)
    for ordinal, sensitive_query_data_signal in enumerate(sensitive_query_data.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=sensitive_query_data_signal.cwe,
                detector=sensitive_query_data_signal.detector,
                location=sensitive_query_data_signal.sink,
                scan_sha256=sensitive_query_data.scan_sha256,
                ordinal=ordinal,
                rule_id=sensitive_query_data_signal.rule_id,
            )
        )
    weak_crypto = go_cwe327.scan_go_cwe327(index)
    for ordinal, weak_crypto_signal in enumerate(weak_crypto.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=weak_crypto_signal.cwe,
                detector=weak_crypto_signal.detector,
                location=weak_crypto_signal.sink,
                scan_sha256=weak_crypto.scan_sha256,
                ordinal=ordinal,
            )
        )
    resource_consumption = go_cwe400.scan_go_cwe400(index)
    for ordinal, resource_consumption_signal in enumerate(resource_consumption.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=resource_consumption_signal.cwe,
                detector=resource_consumption_signal.detector,
                location=resource_consumption_signal.sink,
                scan_sha256=resource_consumption.scan_sha256,
                ordinal=ordinal,
            )
        )
    toctou = go_cwe367.scan_go_cwe367(index)
    for ordinal, toctou_signal in enumerate(toctou.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=toctou_signal.cwe,
                detector=toctou_signal.detector,
                location=toctou_signal.sink,
                scan_sha256=toctou.scan_sha256,
                ordinal=ordinal,
            )
        )
    regex_dos = go_cwe1333.scan_go_cwe1333(index)
    for ordinal, regex_dos_signal in enumerate(regex_dos.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=regex_dos_signal.cwe,
                detector=regex_dos_signal.detector,
                location=regex_dos_signal.sink,
                scan_sha256=regex_dos.scan_sha256,
                ordinal=ordinal,
            )
        )
    tls_validation = go_cwe295.scan_go_cwe295(index)
    for ordinal, tls_validation_signal in enumerate(tls_validation.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=tls_validation_signal.cwe,
                detector=tls_validation_signal.detector,
                location=tls_validation_signal.sink,
                scan_sha256=tls_validation.scan_sha256,
                ordinal=ordinal,
            )
        )
    deserialization = go_cwe502.scan_go_cwe502(index)
    for ordinal, deserialization_signal in enumerate(deserialization.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=deserialization_signal.cwe,
                detector=deserialization_signal.detector,
                location=deserialization_signal.sink,
                scan_sha256=deserialization.scan_sha256,
                ordinal=ordinal,
            )
        )
    xss = go_cwe79.scan_go_cwe79(index)
    for ordinal, xss_signal in enumerate(xss.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=xss_signal.cwe,
                detector=xss_signal.detector,
                location=xss_signal.sink,
                scan_sha256=xss.scan_sha256,
                ordinal=ordinal,
            )
        )
    redirects = go_cwe601.scan_go_cwe601(index)
    for ordinal, redirects_signal in enumerate(redirects.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=redirects_signal.cwe,
                detector=redirects_signal.detector,
                location=redirects_signal.sink,
                scan_sha256=redirects.scan_sha256,
                ordinal=ordinal,
            )
        )
    commands = go_cwe78.scan_go_cwe78(index)
    for ordinal, commands_signal in enumerate(commands.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=commands_signal.cwe,
                detector=commands_signal.detector,
                location=commands_signal.sink,
                scan_sha256=commands.scan_sha256,
                ordinal=ordinal,
                rule_id="portfolio-cwe-78",
            )
        )
    ldap = go_cwe90.scan_go_cwe90(index)
    for ordinal, ldap_signal in enumerate(ldap.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=ldap_signal.cwe,
                detector=ldap_signal.detector,
                location=ldap_signal.sink,
                scan_sha256=ldap.scan_sha256,
                ordinal=ordinal,
            )
        )
    crypto = go_cwe_crypto.scan_go_cwe_crypto(index)
    for ordinal, crypto_signal in enumerate(crypto.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=crypto_signal.cwe,
                detector=crypto_signal.detector,
                location=crypto_signal.sink,
                scan_sha256=crypto.scan_sha256,
                ordinal=ordinal,
            )
        )
    paths = go_cwe22.scan_go_cwe22(index)
    for ordinal, paths_signal in enumerate(paths.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe="CWE-22",
                detector=paths_signal.detector,
                location=paths_signal.sink,
                scan_sha256=paths.scan_sha256,
                ordinal=ordinal,
                rule_id="portfolio-cwe-22",
            )
        )
    ssrf = go_cwe918.scan_go_cwe918(index)
    for ordinal, ssrf_signal in enumerate(ssrf.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=ssrf_signal.cwe,
                detector=ssrf_signal.detector,
                location=ssrf_signal.sink,
                scan_sha256=ssrf.scan_sha256,
                ordinal=ordinal,
                rule_id="portfolio-cwe-918",
            )
        )
    csrf = go_cwe352.scan_go_cwe352(index)
    for ordinal, csrf_signal in enumerate(csrf.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=csrf_signal.cwe,
                detector=csrf_signal.detector,
                location=csrf_signal.sink,
                scan_sha256=csrf.scan_sha256,
                ordinal=ordinal,
                rule_id=csrf_signal.rule_id,
            )
        )
    nil_pointer = go_cwe476.scan_go_cwe476(index)
    for ordinal, nil_pointer_signal in enumerate(nil_pointer.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=nil_pointer_signal.cwe,
                detector=nil_pointer_signal.detector,
                location=nil_pointer_signal.sink,
                scan_sha256=nil_pointer.scan_sha256,
                ordinal=ordinal,
                rule_id=nil_pointer_signal.rule_id,
            )
        )
    return signals
