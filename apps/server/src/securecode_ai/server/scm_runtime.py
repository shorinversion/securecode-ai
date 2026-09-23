"""Environment-backed composition for authenticated SCM webhook admission."""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from securecode_ai.adapters.github_api import GitHubApi
from securecode_ai.adapters.github_writer import GitHubWriter
from securecode_ai.adapters.gitlab_api import GitlabRestAPI
from securecode_ai.adapters.gitlab_writer import GitlabPublicationWriter
from securecode_ai.adapters.scm_head import (
    GithubCommitLineageResolver,
    GithubPullRequestHeadResolver,
    GitlabCommitLineageResolver,
    GitlabMergeRequestHeadResolver,
    SCMHeadUnavailable,
)
from securecode_ai.contracts import ComponentPin

from .scm_state import SqliteSCMRunState
from .scm_webhooks import GithubWebhookAdapter, GitlabWebhookAdapter, WebhookExecutionPins
from .secure_files import decode_ascii_secret, read_json_object, read_secret_bytes

_PIN_NAMES = (
    "stage_catalogue",
    "workflow",
    "policy",
    "configuration",
    "provider_profile",
    "capability_profile",
    "egress_profile",
)
_GITHUB_INSTALLATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


@dataclass(frozen=True, slots=True)
class SCMHandlers:
    github: GithubWebhookAdapter | None = None
    gitlab: GitlabWebhookAdapter | None = None
    pins: WebhookExecutionPins | None = None
    run_state: SqliteSCMRunState | None = None
    github_head: GithubPullRequestHeadResolver | None = None
    github_writer: GitHubWriter | None = None
    gitlab_head: GitlabMergeRequestHeadResolver | None = None
    gitlab_writer: GitlabPublicationWriter | None = None
    lineage_resolver: SCMRunCommitLineageResolver | None = None
    _secret_material: tuple[bytes, ...] = field(default=(), repr=False)


@dataclass(frozen=True, slots=True)
class SCMRunCommitLineageResolver:
    """Resolve commit ancestry through the authenticated provider bound to a run."""

    run_state: SqliteSCMRunState
    github: GithubCommitLineageResolver | None
    gitlab: GitlabCommitLineageResolver | None

    def __call__(
        self,
        *,
        run_id: str,
        execution_identity_hash: str,
        base_sha: str,
        head_sha: str,
    ) -> tuple[str, ...]:
        try:
            target = self.run_state.provider_target(run_id)
            if target.execution_identity_hash != execution_identity_hash:
                raise ValueError
            if target.provider == "github" and self.github is not None:
                return self.github(
                    target.installation_id,
                    target.repository_id,
                    base_sha,
                    head_sha,
                )
            if target.provider == "gitlab" and self.gitlab is not None:
                return self.gitlab(target.repository_id, base_sha, head_sha)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise SCMHeadUnavailable("SCM commit lineage is unavailable") from None
        raise SCMHeadUnavailable("SCM commit lineage is unavailable")


class _FileInstallationTokenProvider:
    __slots__ = ("_installation_id", "_path")

    def __init__(self, path: Path, installation_id: str) -> None:
        if (
            not isinstance(path, Path)
            or not path.is_absolute()
            or type(installation_id) is not str
            or _GITHUB_INSTALLATION_ID.fullmatch(installation_id) is None
        ):
            raise ValueError("GitHub installation credential configuration is invalid")
        self._path = path
        self._installation_id = installation_id
        self._read_token()

    def token(self, installation_id: str) -> str:
        if installation_id != self._installation_id:
            raise ValueError("GitHub installation credential is unavailable")
        return self._read_token()

    def _read_token(self) -> str:
        return decode_ascii_secret(read_secret_bytes(self._path, maximum=8192))


def build_scm_handlers(
    values: Mapping[str, str],
    *,
    tenant_id: str,
    connection: sqlite3.Connection,
) -> SCMHandlers:
    github_enabled = _configured(
        values,
        (
            "SECURECODE_GITHUB_API_URL",
            "SECURECODE_GITHUB_INSTALLATION_ID",
            "SECURECODE_GITHUB_TOKEN_FILE",
            "SECURECODE_GITHUB_WEBHOOK_SECRET_FILE",
        ),
    )
    gitlab_enabled = _configured(
        values,
        (
            "SECURECODE_GITLAB_API_URL",
            "SECURECODE_GITLAB_TOKEN_FILE",
            "SECURECODE_GITLAB_WEBHOOK_SECRET_FILE",
        ),
    )
    if not github_enabled and not gitlab_enabled:
        return SCMHandlers()
    pins_path = values.get("SECURECODE_SCM_PINS_FILE")
    if not pins_path:
        raise ValueError("SCM execution pins are not configured")
    pins = _load_pins(Path(pins_path), tenant_id)
    run_state = SqliteSCMRunState(connection, tenant_id=tenant_id)
    secrets: list[bytes] = []
    github: GithubWebhookAdapter | None = None
    gitlab: GitlabWebhookAdapter | None = None
    github_head: GithubPullRequestHeadResolver | None = None
    github_writer: GitHubWriter | None = None
    gitlab_head: GitlabMergeRequestHeadResolver | None = None
    gitlab_writer: GitlabPublicationWriter | None = None
    github_lineage: GithubCommitLineageResolver | None = None
    gitlab_lineage: GitlabCommitLineageResolver | None = None
    if github_enabled:
        api_url = _required(values, "SECURECODE_GITHUB_API_URL")
        token_path = Path(_required(values, "SECURECODE_GITHUB_TOKEN_FILE"))
        installation_id = _required(values, "SECURECODE_GITHUB_INSTALLATION_ID")
        secret = read_secret_bytes(Path(_required(values, "SECURECODE_GITHUB_WEBHOOK_SECRET_FILE")))
        github_api = GitHubApi(
            api_url,
            _FileInstallationTokenProvider(token_path, installation_id),
        )
        github_head = GithubPullRequestHeadResolver(github_api)
        github_lineage = GithubCommitLineageResolver(github_api)
        github = GithubWebhookAdapter(
            webhook_secret=secret,
            pins=pins,
            run_state=run_state,
            head_resolver=github_head,
        )
        github_writer = GitHubWriter(github_api, pull_request_head=github_head)
        secrets.append(secret)
    if gitlab_enabled:
        api_url = _required(values, "SECURECODE_GITLAB_API_URL")
        token_bytes = read_secret_bytes(Path(_required(values, "SECURECODE_GITLAB_TOKEN_FILE")))
        secret = read_secret_bytes(Path(_required(values, "SECURECODE_GITLAB_WEBHOOK_SECRET_FILE")))
        gitlab_api = GitlabRestAPI(
            base_url=api_url,
            private_token=decode_ascii_secret(token_bytes),
        )
        gitlab_head = GitlabMergeRequestHeadResolver(gitlab_api)
        gitlab_lineage = GitlabCommitLineageResolver(gitlab_api)
        gitlab = GitlabWebhookAdapter(
            webhook_token=secret,
            pins=pins,
            run_state=run_state,
            head_resolver=gitlab_head,
        )
        gitlab_writer = GitlabPublicationWriter(
            api=gitlab_api,
            head_resolver=gitlab_head,
        )
        secrets.extend((token_bytes, secret))
    return SCMHandlers(
        github=github,
        gitlab=gitlab,
        pins=pins,
        run_state=run_state,
        github_head=github_head,
        github_writer=github_writer,
        gitlab_head=gitlab_head,
        gitlab_writer=gitlab_writer,
        lineage_resolver=(
            SCMRunCommitLineageResolver(
                run_state=run_state,
                github=github_lineage,
                gitlab=gitlab_lineage,
            )
            if run_state is not None
            else None
        ),
        _secret_material=tuple(secrets),
    )


def _configured(values: Mapping[str, str], names: tuple[str, ...]) -> bool:
    present = tuple(bool(values.get(name)) for name in names)
    if any(present) and not all(present):
        raise ValueError("SCM integration configuration is incomplete")
    return all(present)


def _required(values: Mapping[str, str], name: str) -> str:
    value = values.get(name)
    if not value:
        raise ValueError("SCM integration configuration is incomplete")
    return value


def _load_pins(path: Path, tenant_id: str) -> WebhookExecutionPins:
    document = read_json_object(path, 32_768)
    if set(document) != set(_PIN_NAMES):
        raise ValueError("SCM execution pins are invalid")
    try:
        pins = {name: ComponentPin.model_validate(document[name]) for name in _PIN_NAMES}
        return WebhookExecutionPins(tenant_id=tenant_id, **pins)
    except (TypeError, ValueError):
        raise ValueError("SCM execution pins are invalid") from None


__all__ = ["SCMHandlers", "build_scm_handlers"]
