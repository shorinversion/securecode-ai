"""Scan python rules detector group."""

from __future__ import annotations

from securecode_ai.contracts import ProducerRef, RawSignal
from securecode_ai.core.scanning import ScannerRequest
from securecode_ai.core.symbols import SymbolIndex

from . import (
    python_ast,
    python_cwe78,
    python_cwe79,
    python_cwe90,
    python_cwe94,
    python_cwe117,
    python_cwe209,
    python_cwe295,
    python_cwe307,
    python_cwe327,
    python_cwe338,
    python_cwe352,
    python_cwe384,
    python_cwe400,
    python_cwe476,
    python_cwe502,
    python_cwe521,
    python_cwe532,
    python_cwe598,
    python_cwe601,
    python_cwe611,
    python_cwe613,
    python_cwe614,
    python_cwe732,
    python_cwe776,
    python_cwe798,
    python_cwe918,
    python_cwe1333,
)
from .product_scanner_worker_support import _fact_to_raw_signal


def scan_python_rules(
    *,
    index: SymbolIndex,
    request: ScannerRequest,
    producer: ProducerRef,
    analysis: python_ast.PythonAstAnalysis,
) -> list[RawSignal]:
    signals = []
    python_analysis = analysis
    credentials = python_cwe798.scan_python_cwe798(index, python_analysis)
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
    password_policy = python_cwe521.scan_python_cwe521(index, python_analysis)
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
    weak_randomness = python_cwe338.scan_python_cwe338(index, python_analysis)
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
    session_expiration = python_cwe613.scan_python_cwe613(index, python_analysis)
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
    error_disclosure = python_cwe209.scan_python_cwe209(index, python_analysis)
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
    xml_expansion = python_cwe776.scan_python_cwe776(index, python_analysis)
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
    sensitive_logging = python_cwe532.scan_python_cwe532(index, python_analysis)
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
    weak_crypto = python_cwe327.scan_python_cwe327(index, python_analysis)
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
    resource_consumption = python_cwe400.scan_python_cwe400(index, python_analysis)
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
    rate_limit = python_cwe307.scan_python_cwe307(index, python_analysis)
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
    log_injection = python_cwe117.scan_python_cwe117(index, python_analysis)
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
    session_fixation = python_cwe384.scan_python_cwe384(index, python_analysis)
    for ordinal, session_fixation_signal in enumerate(session_fixation.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=session_fixation_signal.cwe,
                detector=session_fixation_signal.detector,
                location=session_fixation_signal.sink,
                scan_sha256=session_fixation.scan_sha256,
                ordinal=ordinal,
            )
        )
    file_permissions = python_cwe732.scan_python_cwe732(index, python_analysis)
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
    cookie_security = python_cwe614.scan_python_cwe614(index, python_analysis)
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
            )
        )
    tls_validation = python_cwe295.scan_python_cwe295(index, python_analysis)
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
    redirects = python_cwe601.scan_python_cwe601(index, python_analysis)
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
    commands = python_cwe78.scan_python_cwe78(index, python_analysis)
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
                command_source=commands_signal.source,
                command_operation=commands_signal.operation.value,
                command_detail=commands_signal.detail,
            )
        )
    xss = python_cwe79.scan_python_cwe79(index, python_analysis)
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
    regex_dos = python_cwe1333.scan_python_cwe1333(index, python_analysis)
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
    deserialization = python_cwe502.scan_python_cwe502(index, python_analysis)
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
    xml = python_cwe611.scan_python_cwe611(index, python_analysis)
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
    ldap = python_cwe90.scan_python_cwe90(index, python_analysis)
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
    ssrf = python_cwe918.scan_python_cwe918(index, python_analysis)
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
    python_scan = python_cwe94.scan_python_cwe94(index, python_analysis)
    for ordinal, python_scan_signal in enumerate(python_scan.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=python_scan_signal.cwe,
                detector=python_scan_signal.detector,
                location=python_scan_signal.sink,
                scan_sha256=python_scan.scan_sha256,
                ordinal=ordinal,
            )
        )
    csrf = python_cwe352.scan_python_cwe352(index, python_analysis)
    for ordinal, csrf_signal in enumerate(csrf.signals):
        signals.append(
            _fact_to_raw_signal(
                request=request,
                producer=producer,
                cwe=csrf_signal.cwe,
                detector=csrf_signal.detector,
                location=csrf_signal.endpoint,
                scan_sha256=csrf.scan_sha256,
                ordinal=ordinal,
                rule_id=csrf_signal.rule_id,
            )
        )
    nil_pointer = python_cwe476.scan_python_cwe476(index, python_analysis)
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
    sensitive_query_data = python_cwe598.scan_python_cwe598(index, python_analysis)
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
    return signals
