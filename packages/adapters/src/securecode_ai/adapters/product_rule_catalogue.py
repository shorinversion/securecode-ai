"""Exact first-party scanner rule IDs and their detector-backed CWE labels."""

from __future__ import annotations

from types import MappingProxyType


# Keep this catalogue aligned with the rule IDs passed or constructed by
# FirstPartyStaticWorker._fact_to_raw_signal.  The suffix form is the worker's
# stable fallback for modules whose signal rule ID is not forwarded directly.
PRODUCT_RULE_CWE = MappingProxyType(
    {
        "securecode-python-cwe798": "CWE-798",
        "securecode-python-cwe521:cwe-521": "CWE-521",
        "securecode-python-cwe338:cwe-338": "CWE-338",
        "securecode-python-cwe613:cwe-613": "CWE-613",
        "securecode-python-cwe209:cwe-209": "CWE-209",
        "securecode-python-cwe776:cwe-776": "CWE-776",
        "securecode-python-cwe532:cwe-532": "CWE-532",
        "securecode-python-cwe327:cwe-327": "CWE-327",
        "securecode-python-cwe400:cwe-400": "CWE-400",
        "securecode-python-cwe307:cwe-307": "CWE-307",
        "securecode-python-cwe117:cwe-117": "CWE-117",
        "securecode-python-cwe384:cwe-384": "CWE-384",
        "securecode-python-cwe732:cwe-732": "CWE-732",
        "securecode-python-cwe614:cwe-614": "CWE-614",
        "securecode-python-cwe295:cwe-295": "CWE-295",
        "securecode-python-cwe601:cwe-601": "CWE-601",
        "securecode-python-cwe79:cwe-79": "CWE-79",
        "securecode-python-cwe1333:cwe-1333": "CWE-1333",
        "securecode-python-cwe502:cwe-502": "CWE-502",
        "securecode-python-cwe611:cwe-611": "CWE-611",
        "securecode-python-cwe90:cwe-90": "CWE-90",
        "securecode-python-cwe94:cwe-94": "CWE-94",
        "securecode-python-cwe352": "CWE-352",
        "securecode-python-cwe476": "CWE-476",
        "securecode-python-cwe598": "CWE-598",
        "securecode-python-cwe639": "CWE-639",
        "securecode-python-cwe306": "CWE-306",
        "securecode-go-cwe798": "CWE-798",
        "securecode-go-cwe521:cwe-521": "CWE-521",
        "securecode-go-cwe338:cwe-338": "CWE-338",
        "securecode-go-cwe613:cwe-613": "CWE-613",
        "securecode-go-cwe209:cwe-209": "CWE-209",
        "securecode-go-cwe776:cwe-776": "CWE-776",
        "securecode-go-cwe532:cwe-532": "CWE-532",
        "securecode-go-cwe307:cwe-307": "CWE-307",
        "securecode-go-cwe614": "CWE-614",
        "securecode-go-cwe117": "CWE-117",
        "securecode-go-cwe598": "CWE-598",
        "securecode-go-cwe327:cwe-327": "CWE-327",
        "securecode-go-cwe400:cwe-400": "CWE-400",
        "securecode-go-cwe367:cwe-367": "CWE-367",
        "securecode-go-cwe1333:cwe-1333": "CWE-1333",
        "securecode-go-cwe295:cwe-295": "CWE-295",
        "securecode-go-cwe502:cwe-502": "CWE-502",
        "securecode-go-cwe79:cwe-79": "CWE-79",
        "securecode-go-cwe601:cwe-601": "CWE-601",
        "securecode-go-cwe352": "CWE-352",
        "securecode-go-cwe476": "CWE-476",
        "securecode-go-cwe639": "CWE-639",
        "securecode-go-cwe306": "CWE-306",
        "securecode-go-cwe90:cwe-90": "CWE-90",
        # Coordinates without a known advisory remain in the dependency-stage
        # receipt, not the finding graph. Only matched OSV advisories enter the
        # CWE-937 interpretation and Finding Gate path.
        "dependency-advisory": "CWE-937",
        # Secret detector projections are value-free metadata candidates.  The
        # matched bytes and keyed fingerprints remain inside the DC4 scanner
        # result and never reach this graph or model evidence package.
        "secret-aws_access_key_id": "CWE-798",
        "secret-private_key": "CWE-798",
        "secret-assigned_credential": "CWE-798",
        "secret-high_entropy_token": "CWE-798",
        "securecode-ecmascript-cwe798": "CWE-798",
        "securecode-ecmascript-cwe521:cwe-521": "CWE-521",
        "securecode-ecmascript-cwe338:cwe-338": "CWE-338",
        "securecode-ecmascript-cwe613:cwe-613": "CWE-613",
        "securecode-ecmascript-cwe614:cwe-614": "CWE-614",
        "securecode-ecmascript-cwe209": "CWE-209",
        "securecode-ecmascript-cwe209:cwe-209": "CWE-209",
        "securecode-ecmascript-cwe776:cwe-776": "CWE-776",
        "securecode-ecmascript-cwe532:cwe-532": "CWE-532",
        "securecode-ecmascript-cwe307:cwe-307": "CWE-307",
        "securecode-ecmascript-cwe400:cwe-400": "CWE-400",
        "securecode-ecmascript-cwe117:cwe-117": "CWE-117",
        "securecode-ecmascript-cwe732:cwe-732": "CWE-732",
        "securecode-ecmascript-cwe367:cwe-367": "CWE-367",
        "securecode-ecmascript-cwe611:cwe-611": "CWE-611",
        "securecode-ecmascript-cwe377:cwe-377": "CWE-377",
        "securecode-ecmascript-cwe1333:cwe-1333": "CWE-1333",
        "securecode-ecmascript-cwe295:cwe-295": "CWE-295",
        "securecode-ecmascript-cwe502:cwe-502": "CWE-502",
        "securecode-ecmascript-cwe79:cwe-79": "CWE-79",
        "securecode-ecmascript-cwe90:cwe-90": "CWE-90",
        "securecode-ecmascript-cwe601:cwe-601": "CWE-601",
        "securecode-ecmascript-cwe1321:cwe-1321": "CWE-1321",
        "securecode-ecmascript-cwe94:cwe-94": "CWE-94",
        "securecode-ecmascript-cwe476": "CWE-476",
        "cwe-352-missing-csrf-protection": "CWE-352",
        "securecode-ecmascript-cwe639": "CWE-639",
        "securecode-ecmascript-cwe306": "CWE-306",
        "portfolio-cwe-22": "CWE-22",
        "portfolio-cwe-78": "CWE-78",
        "portfolio-cwe-862": "CWE-862",
        "securecode-python-cwe862": "CWE-862",
        "securecode-ecmascript-cwe862": "CWE-862",
        "securecode-go-cwe862": "CWE-862",
        "portfolio-cwe-918": "CWE-918",
        "cwe-89-sql-interpolation": "CWE-89",
    }
)


class ProductRuleMappingError(ValueError):
    """A candidate refers to a rule ID outside the exact scanner catalogue."""


__all__ = ["PRODUCT_RULE_CWE", "ProductRuleMappingError"]
