"""Transport-neutral tools for agents.

The same registry can be exposed over MCP, HTTP or an in-process SDK. Each tool
opens its own session, executes one real operation, commits, and returns a JSON
object. There is no in-memory campaign store and no fabricated result when the
database is unavailable.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Iterator

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..campaign.service import (
    CampaignError,
    CampaignService,
)
from ..evidence.ledger import EvidenceError, EvidenceLedger
from ..store.models import Campaign, EvidenceRecord
from ..version import __version__


class ToolError(RuntimeError):
    """A tool call was rejected or failed with a caller-visible reason."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[dict[str, Any]], dict[str, Any]]


def _object_schema(
    properties: dict[str, Any],
    required: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": list(required),
        "additionalProperties": False,
    }


class ToolRegistry:
    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory
        self._specs: dict[str, ToolSpec] = {}
        self._register_defaults()

    # ------------------------------------------------------------- transport
    def specs(self) -> list[dict[str, Any]]:
        return [
            {
                "name": spec.name,
                "description": spec.description,
                "inputSchema": spec.input_schema,
            }
            for spec in self._specs.values()
        ]

    def call(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        spec = self._specs.get(name)
        if spec is None:
            raise ToolError(f"unknown tool: {name}")
        args = arguments or {}
        if not isinstance(args, dict):
            raise ToolError("tool arguments must be an object")
        try:
            result = spec.handler(args)
        except ToolError:
            raise
        except (CampaignError, EvidenceError, ValueError) as exc:
            raise ToolError(str(exc)) from exc
        if not isinstance(result, dict):
            raise ToolError(f"tool {name} returned a non-object result")
        return result

    @contextmanager
    def _scope(self) -> Iterator[Session]:
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # --------------------------------------------------------------- helpers
    @staticmethod
    def _required_str(args: dict[str, Any], key: str) -> str:
        value = args.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ToolError(f"{key} must be a non-empty string")
        return value.strip()

    @staticmethod
    def _optional_str(args: dict[str, Any], key: str, default: str = "") -> str:
        if key not in args or args[key] is None:
            return default
        value = args[key]
        if not isinstance(value, str):
            raise ToolError(f"{key} must be a string")
        return value

    @staticmethod
    def _optional_int(args: dict[str, Any], key: str, default: int | None) -> int | None:
        if key not in args or args[key] is None:
            return default
        value = args[key]
        if isinstance(value, bool) or not isinstance(value, int):
            raise ToolError(f"{key} must be an integer")
        return value

    @staticmethod
    def _optional_number(args: dict[str, Any], key: str, default: float | None) -> float | None:
        if key not in args or args[key] is None:
            return default
        value = args[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ToolError(f"{key} must be a number")
        return float(value)

    @staticmethod
    def _optional_bool(args: dict[str, Any], key: str, default: bool) -> bool:
        if key not in args or args[key] is None:
            return default
        value = args[key]
        if not isinstance(value, bool):
            raise ToolError(f"{key} must be a boolean")
        return value

    @staticmethod
    def _optional_dict(args: dict[str, Any], key: str, default: dict[str, Any] | None = None) -> dict[str, Any] | None:
        if key not in args or args[key] is None:
            return default
        value = args[key]
        if not isinstance(value, dict):
            raise ToolError(f"{key} must be an object")
        return value

    @staticmethod
    def _required_dict(args: dict[str, Any], key: str) -> dict[str, Any]:
        value = ToolRegistry._optional_dict(args, key)
        if value is None:
            raise ToolError(f"{key} must be an object")
        return value

    @staticmethod
    def _optional_str_list(args: dict[str, Any], key: str) -> list[str]:
        if key not in args or args[key] is None:
            return []
        value = args[key]
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ToolError(f"{key} must be an array of strings")
        return value

    # ------------------------------------------------------------- registry
    def _register_defaults(self) -> None:
        self._add(
            "redfall_health",
            "Report the database dialect, campaign count and evidence count. Fails if the database is unavailable.",
            _object_schema({}),
            self._health,
        )
        self._add(
            "redfall_campaign_create",
            "Create a draft campaign with an explicit repo, objective, scope and budget.",
            _object_schema(
                {
                    "repo": {"type": "string"},
                    "objective": {
                        "type": "string",
                        "enum": ["discovery", "reproduction", "fix", "regression", "chain", "compliance"],
                    },
                    "commit": {"type": "string"},
                    "scope": {"type": "object"},
                    "policy": {"type": "object"},
                    "budget_usd": {"type": "number", "minimum": 0},
                    "budget_tokens": {"type": "integer", "minimum": 0},
                    "budget_sandbox_minutes": {"type": "number", "minimum": 0},
                    "budget_wall_clock_s": {"type": "integer", "minimum": 0},
                },
                ("repo",),
            ),
            self._campaign_create,
        )
        self._add(
            "redfall_campaign_list",
            "List recent campaigns, newest first.",
            _object_schema({"limit": {"type": "integer", "minimum": 1}}),
            self._campaign_list,
        )
        self._add(
            "redfall_campaign_status",
            "Read campaign state, task counts, evidence counts, budget remaining and chain integrity.",
            _object_schema({"campaign_id": {"type": "string"}}, ("campaign_id",)),
            self._campaign_status,
        )
        self._add(
            "redfall_campaign_scope",
            "Set the campaign scope and move a draft campaign to scoped.",
            _object_schema(
                {"campaign_id": {"type": "string"}, "scope": {"type": "object"}},
                ("campaign_id", "scope"),
            ),
            self._campaign_scope,
        )
        self._add(
            "redfall_campaign_start",
            "Start a scoped campaign by moving it to indexing.",
            _object_schema({"campaign_id": {"type": "string"}}, ("campaign_id",)),
            self._campaign_start,
        )
        self._add(
            "redfall_campaign_transition",
            "Move a campaign to an explicit legal state. The state machine rejects skips.",
            _object_schema(
                {
                    "campaign_id": {"type": "string"},
                    "state": {
                        "type": "string",
                        "enum": [
                            "draft",
                            "scoped",
                            "indexing",
                            "recon",
                            "hypothesis",
                            "probe",
                            "exploit",
                            "impact",
                            "fix",
                            "verify",
                            "reported",
                            "paused",
                            "blocked",
                            "failed",
                            "cancelled",
                        ],
                    },
                    "reason": {"type": "string"},
                },
                ("campaign_id", "state"),
            ),
            self._campaign_transition,
        )
        self._add(
            "redfall_campaign_pause",
            "Pause a campaign and remember the state to resume into.",
            _object_schema({"campaign_id": {"type": "string"}, "reason": {"type": "string"}}, ("campaign_id",)),
            self._campaign_pause,
        )
        self._add(
            "redfall_campaign_resume",
            "Resume a paused or blocked campaign into its recorded previous state.",
            _object_schema({"campaign_id": {"type": "string"}, "reason": {"type": "string"}}, ("campaign_id",)),
            self._campaign_resume,
        )
        self._add(
            "redfall_campaign_cancel",
            "Cancel a campaign. Terminal campaigns cannot be resumed.",
            _object_schema({"campaign_id": {"type": "string"}, "reason": {"type": "string"}}, ("campaign_id",)),
            self._campaign_cancel,
        )
        self._add(
            "redfall_campaign_fail",
            "Mark a campaign failed with a required reason.",
            _object_schema(
                {"campaign_id": {"type": "string"}, "reason": {"type": "string"}},
                ("campaign_id", "reason"),
            ),
            self._campaign_fail,
        )
        self._add(
            "redfall_campaign_report",
            "Move a campaign to reported. Use redfall_report_readiness first.",
            _object_schema({"campaign_id": {"type": "string"}, "reason": {"type": "string"}}, ("campaign_id",)),
            self._campaign_report,
        )
        self._add(
            "redfall_campaign_record_spend",
            "Atomically record model, token or sandbox spend and enforce the campaign budget.",
            _object_schema(
                {
                    "campaign_id": {"type": "string"},
                    "usd": {"type": "number", "minimum": 0},
                    "tokens": {"type": "integer", "minimum": 0},
                    "sandbox_minutes": {"type": "number", "minimum": 0},
                    "source": {"type": "string"},
                },
                ("campaign_id",),
            ),
            self._campaign_record_spend,
        )
        self._add(
            "redfall_task_enqueue",
            "Add a durable campaign task. Dependencies must already belong to the campaign.",
            _object_schema(
                {
                    "campaign_id": {"type": "string"},
                    "kind": {"type": "string"},
                    "payload": {"type": "object"},
                    "priority": {"type": "integer"},
                    "depends_on": {"type": "array", "items": {"type": "string"}},
                    "max_attempts": {"type": "integer", "minimum": 1},
                },
                ("campaign_id", "kind"),
            ),
            self._task_enqueue,
        )
        self._add(
            "redfall_task_claim",
            "Lease the highest-priority ready task to a named worker.",
            _object_schema(
                {
                    "campaign_id": {"type": "string"},
                    "worker": {"type": "string"},
                    "lease_seconds": {"type": "integer", "minimum": 1},
                },
                ("campaign_id", "worker"),
            ),
            self._task_claim,
        )
        self._add(
            "redfall_task_complete",
            "Complete a leased task with a JSON result. The worker must own the lease.",
            _object_schema(
                {
                    "task_id": {"type": "string"},
                    "worker": {"type": "string"},
                    "result": {"type": "object"},
                },
                ("task_id", "worker"),
            ),
            self._task_complete,
        )
        self._add(
            "redfall_task_fail",
            "Fail a leased task with an error. Retry until max_attempts, then fail.",
            _object_schema(
                {
                    "task_id": {"type": "string"},
                    "worker": {"type": "string"},
                    "error": {"type": "string"},
                    "retry": {"type": "boolean"},
                },
                ("task_id", "worker", "error"),
            ),
            self._task_fail,
        )
        self._add(
            "redfall_task_list",
            "List campaign tasks, optionally filtered by status.",
            _object_schema(
                {"campaign_id": {"type": "string"}, "status": {"type": "string"}},
                ("campaign_id",),
            ),
            self._task_list,
        )
        self._add(
            "redfall_evidence_append",
            "Append one hash-chained evidence record. E3/E4 require execution id, observable, reproduction command and environment digest.",
            _object_schema(
                {
                    "campaign_id": {"type": "string"},
                    "grade": {"type": "string", "enum": ["E0", "E1", "E2", "E3", "E4"]},
                    "kind": {
                        "type": "string",
                        "enum": ["static", "dynamic", "execution", "artifact", "human", "environment", "tool", "test", "review"],
                    },
                    "claim": {"type": "string"},
                    "payload": {"type": "object"},
                    "finding_id": {"type": "string"},
                    "artifacts": {"type": "array", "items": {"type": "string"}},
                    "reproduce_command": {"type": "string"},
                    "environment_digest": {"type": "string"},
                },
                ("campaign_id", "grade", "kind", "claim"),
            ),
            self._evidence_append,
        )
        self._add(
            "redfall_evidence_list",
            "List evidence in chain order, optionally only E3/E4.",
            _object_schema(
                {"campaign_id": {"type": "string"}, "reportable_only": {"type": "boolean"}},
                ("campaign_id",),
            ),
            self._evidence_list,
        )
        self._add(
            "redfall_evidence_verify",
            "Recompute the campaign evidence hash chain and report the first broken link.",
            _object_schema({"campaign_id": {"type": "string"}}, ("campaign_id",)),
            self._evidence_verify,
        )
        self._add(
            "redfall_report_readiness",
            "Check that the evidence chain is intact and at least one E3/E4 record exists before reporting.",
            _object_schema({"campaign_id": {"type": "string"}}, ("campaign_id",)),
            self._report_readiness,
        )

    def _add(
        self,
        name: str,
        description: str,
        input_schema: dict[str, Any],
        handler: Callable[[dict[str, Any]], dict[str, Any]],
    ) -> None:
        self._specs[name] = ToolSpec(name, description, input_schema, handler)

    # --------------------------------------------------------------- handlers
    def _health(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._scope() as session:
            campaigns = int(session.execute(select(func.count()).select_from(Campaign)).scalar_one())
            evidence = int(session.execute(select(func.count()).select_from(EvidenceRecord)).scalar_one())
            return {
                "ok": True,
                "version": __version__,
                "database": session.get_bind().dialect.name,
                "campaigns": campaigns,
                "evidence": evidence,
            }

    def _campaign_create(self, args: dict[str, Any]) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "objective": self._optional_str(args, "objective", "discovery"),
            "commit": self._optional_str(args, "commit"),
            "scope": self._optional_dict(args, "scope", {}) or {},
            "policy": self._optional_dict(args, "policy", {}) or {},
        }
        for key in ("budget_usd", "budget_tokens", "budget_sandbox_minutes", "budget_wall_clock_s"):
            if key in args:
                kwargs[key] = (
                    self._optional_number(args, key, None)
                    if key in {"budget_usd", "budget_sandbox_minutes"}
                    else self._optional_int(args, key, None)
                )
        with self._scope() as session:
            campaign = CampaignService(session).create(self._required_str(args, "repo"), **kwargs)
            return campaign.to_wire()

    def _campaign_list(self, args: dict[str, Any]) -> dict[str, Any]:
        limit = self._optional_int(args, "limit", 50)
        if limit is None:
            limit = 50
        with self._scope() as session:
            return {"campaigns": [campaign.to_wire() for campaign in CampaignService(session).list_campaigns(limit=limit)]}

    def _campaign_status(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._scope() as session:
            return CampaignService(session).status(self._required_str(args, "campaign_id"))

    def _campaign_scope(self, args: dict[str, Any]) -> dict[str, Any]:
        scope = self._required_dict(args, "scope")
        with self._scope() as session:
            return CampaignService(session).scope(self._required_str(args, "campaign_id"), scope).to_wire()

    def _campaign_start(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._scope() as session:
            return CampaignService(session).start(self._required_str(args, "campaign_id")).to_wire()

    def _campaign_transition(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._scope() as session:
            return CampaignService(session).transition(
                self._required_str(args, "campaign_id"),
                self._required_str(args, "state"),
                reason=self._optional_str(args, "reason"),
            ).to_wire()

    def _campaign_pause(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._scope() as session:
            return CampaignService(session).pause(
                self._required_str(args, "campaign_id"),
                reason=self._optional_str(args, "reason"),
            ).to_wire()

    def _campaign_resume(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._scope() as session:
            return CampaignService(session).resume(
                self._required_str(args, "campaign_id"),
                reason=self._optional_str(args, "reason"),
            ).to_wire()

    def _campaign_cancel(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._scope() as session:
            return CampaignService(session).cancel(
                self._required_str(args, "campaign_id"),
                reason=self._optional_str(args, "reason"),
            ).to_wire()

    def _campaign_fail(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._scope() as session:
            return CampaignService(session).fail(
                self._required_str(args, "campaign_id"),
                reason=self._required_str(args, "reason"),
            ).to_wire()

    def _campaign_report(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._scope() as session:
            return CampaignService(session).report(
                self._required_str(args, "campaign_id"),
                reason=self._optional_str(args, "reason"),
            ).to_wire()

    def _campaign_record_spend(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._scope() as session:
            return CampaignService(session).record_spend(
                self._required_str(args, "campaign_id"),
                usd=self._optional_number(args, "usd", 0.0) or 0.0,
                tokens=self._optional_int(args, "tokens", 0) or 0,
                sandbox_minutes=self._optional_number(args, "sandbox_minutes", 0.0) or 0.0,
                source=self._optional_str(args, "source"),
            )

    def _task_enqueue(self, args: dict[str, Any]) -> dict[str, Any]:
        priority = self._optional_int(args, "priority", 0)
        if priority is None:
            priority = 0
        max_attempts = self._optional_int(args, "max_attempts", 3)
        if max_attempts is None:
            max_attempts = 3
        with self._scope() as session:
            return CampaignService(session).enqueue_task(
                self._required_str(args, "campaign_id"),
                self._required_str(args, "kind"),
                payload=self._optional_dict(args, "payload", {}),
                priority=priority,
                depends_on=self._optional_str_list(args, "depends_on"),
                max_attempts=max_attempts,
            ).to_wire()

    def _task_claim(self, args: dict[str, Any]) -> dict[str, Any]:
        lease_seconds = self._optional_int(args, "lease_seconds", 300)
        if lease_seconds is None:
            lease_seconds = 300
        with self._scope() as session:
            task = CampaignService(session).claim_task(
                self._required_str(args, "campaign_id"),
                worker=self._required_str(args, "worker"),
                lease_seconds=lease_seconds,
            )
            return {"task": task.to_wire() if task is not None else None}

    def _task_complete(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._scope() as session:
            return CampaignService(session).complete_task(
                self._required_str(args, "task_id"),
                worker=self._required_str(args, "worker"),
                result=self._optional_dict(args, "result", {}),
            ).to_wire()

    def _task_fail(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._scope() as session:
            return CampaignService(session).fail_task(
                self._required_str(args, "task_id"),
                worker=self._required_str(args, "worker"),
                error=self._required_str(args, "error"),
                retry=self._optional_bool(args, "retry", True),
            ).to_wire()

    def _task_list(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._scope() as session:
            return {
                "tasks": [
                    task.to_wire()
                    for task in CampaignService(session).list_tasks(
                        self._required_str(args, "campaign_id"),
                        status=self._optional_str(args, "status", "") or None,
                    )
                ]
            }

    def _evidence_append(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._scope() as session:
            record = EvidenceLedger(session).append(
                self._required_str(args, "campaign_id"),
                grade=self._required_str(args, "grade"),
                kind=self._required_str(args, "kind"),
                claim=self._required_str(args, "claim"),
                payload=self._optional_dict(args, "payload", {}),
                finding_id=self._optional_str(args, "finding_id", "") or None,
                artifacts=self._optional_str_list(args, "artifacts"),
                reproduce_command=self._optional_str(args, "reproduce_command"),
                environment_digest=self._optional_str(args, "environment_digest"),
            )
            return record.to_wire()

    def _evidence_list(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._scope() as session:
            return {
                "evidence": [
                    record.to_wire()
                    for record in EvidenceLedger(session).list(
                        self._required_str(args, "campaign_id"),
                        reportable_only=self._optional_bool(args, "reportable_only", False),
                    )
                ]
            }

    def _evidence_verify(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._scope() as session:
            return EvidenceLedger(session).verify(self._required_str(args, "campaign_id")).to_wire()

    def _report_readiness(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._scope() as session:
            campaign_id = self._required_str(args, "campaign_id")
            ledger = EvidenceLedger(session)
            chain = ledger.verify(campaign_id)
            reportable = ledger.reportable(campaign_id)
            if not chain.ok:
                return {"ready": False, "reason": f"evidence chain is broken: {chain.reason}", "chain": chain.to_wire()}
            if not reportable:
                return {"ready": False, "reason": "no E3/E4 evidence", "chain": chain.to_wire()}
            return {
                "ready": True,
                "reason": "",
                "chain": chain.to_wire(),
                "evidence_ids": [record.id for record in reportable],
            }
