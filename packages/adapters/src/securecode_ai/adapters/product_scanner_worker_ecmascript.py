"""Scan ecmascript rules detector group."""

from __future__ import annotations

from securecode_ai.contracts import ProducerRef, RawSignal
from securecode_ai.core.scanning import ScannerRequest
from securecode_ai.core.symbols import SymbolIndex

from . import (
    ecmascript_cwe22,
    ecmascript_cwe78,
    ecmascript_cwe79,
    ecmascript_cwe90,
    ecmascript_cwe94,
    ecmascript_cwe117,
    ecmascript_cwe209,
    ecmascript_cwe295,
    ecmascript_cwe307,
    ecmascript_cwe338,
    ecmascript_cwe352,
    ecmascript_cwe367,
    ecmascript_cwe377,
    ecmascript_cwe400,
    ecmascript_cwe476,
    ecmascript_cwe502,
    ecmascript_cwe521,
    ecmascript_cwe532,
    ecmascript_cwe601,
    ecmascript_cwe611,
    ecmascript_cwe613,
    ecmascript_cwe614,
    ecmascript_cwe732,
    ecmascript_cwe776,
    ecmascript_cwe798,
    ecmascript_cwe918,
    ecmascript_cwe1321,
    ecmascript_cwe1333,
)
from .product_scanner_worker_support import _fact_to_raw_signal


def scan_ecmascript_rules(
    *,
    index: SymbolIndex,
    request: ScannerRequest,
    producer: ProducerRef,
) -> list[RawSignal]:
    signals = []
    credentials = ecmascript_cwe798.scan_ecmascript_cwe798(index)
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
    password_policy = ecmascript_cwe521.scan_ecmascript_cwe521(index)
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
    weak_randomness = ecmascript_cwe338.scan_ecmascript_cwe338(index)
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
    session_expiration = ecmascript_cwe613.scan_ecmascript_cwe613(index)
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
    cookie_security = ecmascript_cwe614.scan_ecmascript_cwe614(index)
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
    error_disclosure = ecmascript_cwe209.scan_ecmascript_cwe209(index)
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
    xml_expansion = ecmascript_cwe776.scan_ecmascript_cwe776(index)
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
    sensitive_logging = ecmascript_cwe532.scan_ecmascript_cwe532(index)
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
    rate_limit = ecmascript_cwe307.scan_ecmascript_cwe307(index)
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
    resource_consumption = ecmascript_cwe400.scan_ecmascript_cwe400(index)
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
    log_injection = ecmascript_cwe117.scan_ecmascript_cwe117(index)
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
            )
        )
    file_permissions = ecmascript_cwe732.scan_ecmascript_cwe732(index)
    for ordinal, file_permissions_signal in enumerate(file_permissions.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=file_permissions_signal.cwe,
                detector=file_permissions_signal.detector,
                location=file_permissions_signal.sink,
                scan_sha256=file_permissions.scan_sha256,
                ordinal=ordinal,
            )
        )
    toctou = ecmascript_cwe367.scan_ecmascript_cwe367(index)
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
    xml = ecmascript_cwe611.scan_ecmascript_cwe611(index)
    for ordinal, xml_signal in enumerate(xml.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=xml_signal.cwe,
                detector=xml_signal.detector,
                location=xml_signal.sink,
                scan_sha256=xml.scan_sha256,
                ordinal=ordinal,
            )
        )
    temporary_files = ecmascript_cwe377.scan_ecmascript_cwe377(index)
    for ordinal, temporary_files_signal in enumerate(temporary_files.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=temporary_files_signal.cwe,
                detector=temporary_files_signal.detector,
                location=temporary_files_signal.sink,
                scan_sha256=temporary_files.scan_sha256,
                ordinal=ordinal,
            )
        )
    regex_dos = ecmascript_cwe1333.scan_ecmascript_cwe1333(index)
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
    tls_validation = ecmascript_cwe295.scan_ecmascript_cwe295(index)
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
    deserialization = ecmascript_cwe502.scan_ecmascript_cwe502(index)
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
    commands = ecmascript_cwe78.scan_ecmascript_cwe78(index)
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
    xss = ecmascript_cwe79.scan_ecmascript_cwe79(index)
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
    ldap = ecmascript_cwe90.scan_ecmascript_cwe90(index)
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
    ssrf = ecmascript_cwe918.scan_ecmascript_cwe918(index)
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
    redirects = ecmascript_cwe601.scan_ecmascript_cwe601(index)
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
    prototype_pollution = ecmascript_cwe1321.scan_ecmascript_cwe1321(index)
    for ordinal, prototype_pollution_signal in enumerate(prototype_pollution.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=prototype_pollution_signal.cwe,
                detector=prototype_pollution_signal.detector,
                location=prototype_pollution_signal.sink,
                scan_sha256=prototype_pollution.scan_sha256,
                ordinal=ordinal,
            )
        )
    paths = ecmascript_cwe22.scan_ecmascript_cwe22(index)
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
    dynamic_code = ecmascript_cwe94.scan_ecmascript_cwe94(index)
    for ordinal, dynamic_code_signal in enumerate(dynamic_code.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=dynamic_code_signal.cwe,
                detector=dynamic_code_signal.detector,
                location=dynamic_code_signal.sink,
                scan_sha256=dynamic_code.scan_sha256,
                ordinal=ordinal,
            )
        )
    nil_pointer = ecmascript_cwe476.scan_ecmascript_cwe476(index)
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
    csrf_scanner = (
        ecmascript_cwe352.scan_javascript_cwe352
        if index.language == "javascript"
        else ecmascript_cwe352.scan_typescript_cwe352
    )
    csrf = csrf_scanner(index)
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
                rule_id="cwe-352-missing-csrf-protection",
            )
        )
    return signals
