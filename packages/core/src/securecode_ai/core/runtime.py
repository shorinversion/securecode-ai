"""Deterministic workflow definition, transition, and replay authority."""

from __future__ import annotations

from .runtime_actions import (
    control_workflow,
    replay_workflow_journal,
    signal_workflow,
)
from .runtime_definition import (
    DEFAULT_POLICY_PIN,
    DEFAULT_STAGE_CATALOGUE_PIN,
    DEFAULT_WORKFLOW_DEFINITION,
    DEFAULT_WORKFLOW_REGISTRY,
    RUNTIME_COMPONENT_PIN,
    WorkflowDecisionError,
    WorkflowDefinitionRegistry,
    WorkflowRuntime,
    build_default_workflow_definition,
)
from .runtime_transition import (
    TransitionDecision,
    canonical_workflow_request_hash,
    start_workflow,
    validate_workflow_signal_preconditions,
)

for _runtime_type in (WorkflowDecisionError, WorkflowDefinitionRegistry):
    _runtime_type.__module__ = __name__
del _runtime_type
__all__ = [
    "DEFAULT_POLICY_PIN",
    "DEFAULT_STAGE_CATALOGUE_PIN",
    "DEFAULT_WORKFLOW_DEFINITION",
    "DEFAULT_WORKFLOW_REGISTRY",
    "RUNTIME_COMPONENT_PIN",
    "TransitionDecision",
    "WorkflowDecisionError",
    "WorkflowDefinitionRegistry",
    "WorkflowRuntime",
    "build_default_workflow_definition",
    "canonical_workflow_request_hash",
    "control_workflow",
    "replay_workflow_journal",
    "signal_workflow",
    "start_workflow",
    "validate_workflow_signal_preconditions",
]
