"""Environment-backed composition for authenticated SCM webhook admission."""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from securecode_ai.adapters.github_api import GitHubApi
from securecode_ai.adapters.github_comments import GithubCommentPublisher
from securecode_ai.adapters.github_app import github_app_permissions
from securecode_ai.adapters.github_sarif import GithubSarifPublisher
from securecode_ai.adapters.github_writer import GitHubWriter
from securecode_ai.adapters.gitlab_api import GitlabRestAPI
from securecode_ai.adapters.gitlab_writer import GitlabPublicationWriter
from securecode_ai.adapters.scm_head import (
    GithubChangedLinesResolver,
    GithubCommitLineageResolver,
    GithubPullRequestHeadResolver,
    GitlabChangedLinesResolver,
    GitlabCommitLineageResolver,
    GitlabMergeRequestHeadResolver,
    SCMHeadUnavailable,
)
from securecode_ai.contracts import ComponentPin

from .scm_state import SqliteSCMRunState
from .scm_publication_store import SqliteSCMPublicationStore
from .scm_webhooks import (
    ConnectedRunIdentityResolver,
    ConnectedRunIdentityResolverRouter,
    GithubWebhookAdapter,
    GitlabWebhookAdapter,
    WebhookExecutionPins,
)
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
    github_comments: GithubCommentPublisher | None = None
    github_sarif: GithubSarifPublisher | None = None
    gitlab_head: GitlabMergeRequestHeadResolver | None = None
    gitlab_writer: GitlabPublicationWriter | None = None
    gitlab_api: GitlabRestAPI | None = None
    lineage_resolver: SCMRunCommitLineageResolver | None = None
    changed_lines_resolver: SCMRunChangedLinesResolver | None = None
    connected_identity_resolver: (
        ConnectedRunIdentityResolver | ConnectedRunIdentityResolverRouter | None
    ) = None
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


@dataclass(frozen=True, slots=True)
class SCMRunChangedLinesResolver:
    """Resolve changed HEAD locations through the provider bound to a run."""

    run_state: SqliteSCMRunState
    github: GithubChangedLinesResolver | None
    gitlab: GitlabChangedLinesResolver | None

    def __call__(
        self,
        *,
        run_id: str,
        execution_identity_hash: str,
        base_sha: str,
        head_sha: str,
    ) -> tuple[tuple[str, int], ...]:
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
            raise SCMHeadUnavailable("SCM changed lines are unavailable") from None
        raise SCMHeadUnavailable("SCM changed lines are unavailable")


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
    publications: SqliteSCMPublicationStore | None = None,
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
    github_sarif_enabled = _flag(values, "SECURECODE_GITHUB_SARIF_ENABLED")
    if github_sarif_enabled and not github_enabled:
        raise ValueError("GitHub SARIF publication requires the GitHub adapter")
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
    github_comments: GithubCommentPublisher | None = None
    github_sarif: GithubSarifPublisher | None = None
    gitlab_head: GitlabMergeRequestHeadResolver | None = None
    gitlab_writer: GitlabPublicationWriter | None = None
    gitlab_api: GitlabRestAPI | None = None
    github_lineage: GithubCommitLineageResolver | None = None
    gitlab_lineage: GitlabCommitLineageResolver | None = None
    github_changed_lines: GithubChangedLinesResolver | None = None
    gitlab_changed_lines: GitlabChangedLinesResolver | None = None
    github_installation_id: str | None = None
    if github_enabled:
        api_url = _required(values, "SECURECODE_GITHUB_API_URL")
        token_path = Path(_required(values, "SECURECODE_GITHUB_TOKEN_FILE"))
        installation_id = _required(values, "SECURECODE_GITHUB_INSTALLATION_ID")
        github_installation_id = installation_id
        secret = read_secret_bytes(Path(_required(values, "SECURECODE_GITHUB_WEBHOOK_SECRET_FILE")))
        github_api = GitHubApi(
            api_url,
            _FileInstallationTokenProvider(token_path, installation_id),
        )
        github_head = GithubPullRequestHeadResolver(github_api)
        github_lineage = GithubCommitLineageResolver(github_api)
        github_changed_lines = GithubChangedLinesResolver(github_api)
        github = GithubWebhookAdapter(
            webhook_secret=secret,
            pins=pins,
            run_state=run_state,
            head_resolver=github_head,
        )
        github_writer = GitHubWriter(github_api, pull_request_head=github_head)
        github_comments = GithubCommentPublisher(
            github_api,
            pull_request_head=github_head,
        )
        if github_sarif_enabled:
            github_sarif = GithubSarifPublisher(
                github_api,
                pull_request_head=github_head,
                connection=connection,
                permissions=dict(github_app_permissions(enable_sarif=True)),
            )
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
        gitlab_changed_lines = GitlabChangedLinesResolver(gitlab_api)
        gitlab = GitlabWebhookAdapter(
            webhook_token=secret,
            pins=pins,
            run_state=run_state,
            head_resolver=gitlab_head,
        )
        gitlab_writer = GitlabPublicationWriter(
            api=gitlab_api,
            head_resolver=gitlab_head,
            connection=connection,
        )
        secrets.extend((token_bytes, secret))
    if github_enabled and gitlab_enabled:
        connected_identity_resolver = ConnectedRunIdentityResolverRouter(
            github=ConnectedRunIdentityResolver(
                pins=pins,
                scm_provider="github",
                head_resolver=github_head,
                installation_id=github_installation_id,
                publication_store=publications,
                run_state=run_state,
            ),
            gitlab=ConnectedRunIdentityResolver(
                pins=pins,
                scm_provider="gitlab",
                head_resolver=gitlab_head,
                publication_store=publications,
                run_state=run_state,
            ),
        )
    elif github_enabled:
        connected_identity_resolver = ConnectedRunIdentityResolver(
            pins=pins,
            scm_provider="github",
            head_resolver=github_head,
            installation_id=github_installation_id,
            publication_store=publications,
            run_state=run_state,
        )
    elif gitlab_enabled:
        connected_identity_resolver = ConnectedRunIdentityResolver(
            pins=pins,
            scm_provider="gitlab",
            head_resolver=gitlab_head,
            publication_store=publications,
            run_state=run_state,
        )
    else:
        connected_identity_resolver = None
    return SCMHandlers(
        github=github,
        gitlab=gitlab,
        pins=pins,
        connected_identity_resolver=connected_identity_resolver,
        run_state=run_state,
        github_head=github_head,
        github_writer=github_writer,
        github_comments=github_comments,
        github_sarif=github_sarif,
        gitlab_head=gitlab_head,
        gitlab_writer=gitlab_writer,
        gitlab_api=gitlab_api if gitlab_enabled else None,
        lineage_resolver=(
            SCMRunCommitLineageResolver(
                run_state=run_state,
                github=github_lineage,
                gitlab=gitlab_lineage,
            )
            if run_state is not None
            else None
        ),
        changed_lines_resolver=(
            SCMRunChangedLinesResolver(
                run_state=run_state,
                github=github_changed_lines,
                gitlab=gitlab_changed_lines,
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


def _flag(values: Mapping[str, str], name: str) -> bool:
    value = values.get(name, "")
    if value == "":
        return False
    if value.lower() in {"1", "true", "yes", "on"}:
        return True
    if value.lower() in {"0", "false", "no", "off"}:
        return False
    raise ValueError("SCM feature flag is invalid")


def _load_pins(path: Path, tenant_id: str) -> WebhookExecutionPins:
    document = read_json_object(path, 32_768)
    if set(document) != set(_PIN_NAMES):
        raise ValueError("SCM execution pins are invalid")
    try:
        pins = {name: ComponentPin.model_validate(document[name]) for name in _PIN_NAMES}
        return WebhookExecutionPins(tenant_id=tenant_id, **pins)
    except (TypeError, ValueError):
        raise ValueError("SCM execution pins are invalid") from None


__all__ = [
    "SCMHandlers",
    "SCMRunChangedLinesResolver",
    "SCMRunCommitLineageResolver",
    "build_scm_handlers",
]
