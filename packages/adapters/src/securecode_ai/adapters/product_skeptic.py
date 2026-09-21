"""Authorized, read-only Skeptic product port."""

from __future__ import annotations

from .product_skeptic_contracts import (
    PRODUCT_SKEPTIC_PROMPT_PIN,
    SKEPTIC_WIRE_PIN,
    SKEPTIC_WIRE_SCHEMA_JSON,
)
from .product_skeptic_port import ProductSkepticReviewPort
from .product_skeptic_validator import SkepticPayloadValidator

for _skeptic_type in (SkepticPayloadValidator, ProductSkepticReviewPort):
    _skeptic_type.__module__ = __name__
del _skeptic_type

__all__ = [
    "PRODUCT_SKEPTIC_PROMPT_PIN",
    "SKEPTIC_WIRE_PIN",
    "SKEPTIC_WIRE_SCHEMA_JSON",
    "ProductSkepticReviewPort",
    "SkepticPayloadValidator",
]
