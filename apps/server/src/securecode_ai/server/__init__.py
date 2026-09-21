"""SecureCode AI ASGI server boundary."""

from .application import ServerApp, create_app
from .openapi import API_VERSION, CAPABILITIES, SUPPORTED_MAJOR, build_openapi_document
from .ports import (
    AuthorizationPort,
    ControlPlaneService,
    IdentityVerifier,
    ReadinessPort,
    ServiceRequest,
    ServiceResponse,
    ServiceUnavailableError,
    VerifiedIdentity,
)

__all__ = [
    "API_VERSION",
    "CAPABILITIES",
    "SUPPORTED_MAJOR",
    "AuthorizationPort",
    "ControlPlaneService",
    "IdentityVerifier",
    "ReadinessPort",
    "ServerApp",
    "ServiceRequest",
    "ServiceResponse",
    "ServiceUnavailableError",
    "VerifiedIdentity",
    "build_openapi_document",
    "create_app",
]
