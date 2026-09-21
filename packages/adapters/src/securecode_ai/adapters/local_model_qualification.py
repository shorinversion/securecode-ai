from __future__ import annotations

from .local_model_qualification_models import (
    GpuHardwareSnapshot,
    HardwareMemorySource,
    HardwareSnapshot,
    LocalModelArtifact,
    LocalModelQualificationError,
    LocalModelQualificationEvidence,
    LocalModelQualificationRecord,
    LocalModelQualificationRequest,
    LocalRuntimeSnapshot,
    QualificationErrorCode,
    QualificationState,
)
from .local_model_qualification_record import record_local_model_qualification
from .local_model_qualification_validation import (
    _tool_receipt_sha256 as _tool_receipt_sha256,
)

for _qualification_type in (
    LocalModelQualificationError,
    LocalModelArtifact,
    LocalRuntimeSnapshot,
    GpuHardwareSnapshot,
    HardwareSnapshot,
    LocalModelQualificationRequest,
    LocalModelQualificationEvidence,
    LocalModelQualificationRecord,
):
    _qualification_type.__module__ = __name__
del _qualification_type
__all__ = [
    "GpuHardwareSnapshot",
    "HardwareMemorySource",
    "HardwareSnapshot",
    "LocalModelArtifact",
    "LocalModelQualificationError",
    "LocalModelQualificationEvidence",
    "LocalModelQualificationRecord",
    "LocalModelQualificationRequest",
    "LocalRuntimeSnapshot",
    "QualificationErrorCode",
    "QualificationState",
    "record_local_model_qualification",
]
