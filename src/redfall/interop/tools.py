"""Transport-neutral tools for agents.

The same registry can be exposed over MCP, HTTP or an in-process SDK. Each tool
opens its own session, executes one real operation, commits, and returns a JSON
object. There is no in-memory campaign store and no fabricated result when the
database is unavailable.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Callable, Iterator

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..campaign.handlers import record_scan_evidence
from ..campaign.policy import (
    PolicyError,
    check_campaign_path,
    check_os_path,
    require_campaign_path,
    require_os_path,
)
from ..campaign.runner import CampaignRunner
from ..campaign.service import (
    ACTIVE_STATES,
    CampaignBudgetExceeded,
    CampaignError,
    CampaignService,
)
from ..config import PrerequisiteError, load_config
from ..evidence.ledger import EvidenceError, EvidenceLedger
from ..graph.indexer import GraphIndexError, GraphIndexer
from ..graph.query import GraphQuery, GraphQueryError
from ..orchestrator import run_scan
from ..reporting.campaign_report import ReportError, build_campaign_report
from ..store.models import AdapterCertification, Campaign, EvidenceRecord, Finding, Scan
from ..validation.reproducer import (
    ReproductionBlocked,
    ReproductionError,
    Reproducer,
)
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
        except (
            CampaignError,
            EvidenceError,
            GraphIndexError,
            GraphQueryError,
            PolicyError,
            ReportError,
            ReproductionError,
            ValueError,
        ) as exc:
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
                {
                    "campaign_id": {"type": "string"},
                    "reportable_only": {"type": "boolean"},
                    "finding_id": {"type": "string"},
                },
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
        self._add(
            "redfall_campaign_run",
            "Run the resumable worker for this campaign. Executes real registered task handlers, reserves budget before work, and stops on blocked prerequisites.",
            _object_schema(
                {
                    "campaign_id": {"type": "string"},
                    "worker": {"type": "string"},
                    "max_tasks": {"type": "integer", "minimum": 0},
                    "lease_seconds": {"type": "integer", "minimum": 1},
                },
                ("campaign_id",),
            ),
            self._campaign_run,
        )
        self._add(
            "redfall_campaign_reserve",
            "Hold budget before a task executes. Reservations count against remaining budget and are settled or released.",
            _object_schema(
                {
                    "campaign_id": {"type": "string"},
                    "task_id": {"type": "string"},
                    "usd": {"type": "number", "minimum": 0},
                    "tokens": {"type": "integer", "minimum": 0},
                    "sandbox_minutes": {"type": "number", "minimum": 0},
                    "source": {"type": "string"},
                },
                ("campaign_id",),
            ),
            self._campaign_reserve,
        )
        self._add(
            "redfall_campaign_release_reservation",
            "Release a held budget reservation without recording spend.",
            _object_schema(
                {"reservation_id": {"type": "string"}, "reason": {"type": "string"}},
                ("reservation_id",),
            ),
            self._campaign_release_reservation,
        )
        self._add(
            "redfall_campaign_settle_reservation",
            "Replace a held reservation with measured spend. The budget ceiling is still enforced.",
            _object_schema(
                {
                    "reservation_id": {"type": "string"},
                    "usd": {"type": "number", "minimum": 0},
                    "tokens": {"type": "integer", "minimum": 0},
                    "sandbox_minutes": {"type": "number", "minimum": 0},
                    "source": {"type": "string"},
                    "allow_overage": {"type": "boolean"},
                },
                ("reservation_id",),
            ),
            self._campaign_settle_reservation,
        )
        self._add(
            "redfall_graph_index",
            "Parse a local repository with the real ingestion pipeline and persist an immutable code-graph snapshot. No finding is produced.",
            _object_schema(
                {
                    "target": {"type": "string"},
                    "campaign_id": {"type": "string"},
                    "label": {"type": "string"},
                },
                ("target",),
            ),
            self._graph_index,
        )
        self._add(
            "redfall_graph_latest",
            "Return the newest graph snapshot, optionally filtered to a campaign.",
            _object_schema(
                {"campaign_id": {"type": "string"}, "root": {"type": "string"}, "limit": {"type": "integer", "minimum": 1}},
            ),
            self._graph_latest,
        )
        self._add(
            "redfall_graph_stats",
            "Return node and edge counts by kind, plus file, route, source, sink and taint totals.",
            _object_schema(
                {"snapshot_id": {"type": "string"}, "campaign_id": {"type": "string"}},
            ),
            self._graph_stats,
        )
        self._add(
            "redfall_graph_search",
            "Search graph nodes by name, key or file, optionally filtered by node kind.",
            _object_schema(
                {
                    "snapshot_id": {"type": "string"},
                    "query": {"type": "string"},
                    "kind": {"type": "string"},
                    "file": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1},
                    "offset": {"type": "integer", "minimum": 0},
                },
            ),
            self._graph_search,
        )
        self._add(
            "redfall_graph_node",
            "Return one node with its incoming and outgoing edges and provenance.",
            _object_schema(
                {"snapshot_id": {"type": "string"}, "node": {"type": "string"}},
                ("node",),
            ),
            self._graph_node,
        )
        self._add(
            "redfall_graph_neighbors",
            "Traverse stored edges from a node with an explicit direction, kind filter, depth and node limit.",
            _object_schema(
                {
                    "snapshot_id": {"type": "string"},
                    "node": {"type": "string"},
                    "direction": {"type": "string", "enum": ["out", "in", "both"]},
                    "edge_kinds": {"type": "array", "items": {"type": "string"}},
                    "depth": {"type": "integer", "minimum": 1, "maximum": 6},
                    "limit": {"type": "integer", "minimum": 1},
                },
                ("node",),
            ),
            self._graph_neighbors,
        )
        self._add(
            "redfall_graph_paths",
            "Find bounded directed paths between two stored nodes, returning the full node and edge provenance.",
            _object_schema(
                {
                    "snapshot_id": {"type": "string"},
                    "source": {"type": "string"},
                    "target": {"type": "string"},
                    "max_depth": {"type": "integer", "minimum": 1, "maximum": 8},
                    "edge_kinds": {"type": "array", "items": {"type": "string"}},
                    "limit": {"type": "integer", "minimum": 1},
                },
                ("source", "target"),
            ),
            self._graph_paths,
        )
        self._add(
            "redfall_graph_routes",
            "List resolved HTTP routes from the graph, optionally filtered by method or path substring.",
            _object_schema(
                {
                    "snapshot_id": {"type": "string"},
                    "campaign_id": {"type": "string"},
                    "method": {"type": "string"},
                    "path_contains": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1},
                },
            ),
            self._graph_routes,
        )
        self._add(
            "redfall_graph_diff",
            "Compare two snapshots by stable node and edge keys, including changed provenance and properties.",
            _object_schema(
                {
                    "base_snapshot": {"type": "string"},
                    "head_snapshot": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1},
                },
                ("base_snapshot", "head_snapshot"),
            ),
            self._graph_diff,
        )
        self._add(
            "redfall_graph_sources",
            "List taint sources, sinks and stored taint flows. Optional role=source or sink filters the node lists.",
            _object_schema(
                {
                    "snapshot_id": {"type": "string"},
                    "campaign_id": {"type": "string"},
                    "role": {"type": "string", "enum": ["both", "source", "sink"]},
                    "limit": {"type": "integer", "minimum": 1},
                },
            ),
            self._graph_sources,
        )
        self._add(
            "redfall_graph_inventory",
            "Return a bounded route, dependency and secret inventory from a stored snapshot.",
            _object_schema(
                {
                    "snapshot_id": {"type": "string"},
                    "campaign_id": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1},
                },
            ),
            self._graph_inventory,
        )
        self._add(
            "redfall_scan_run",
            "Execute a full scan with the real orchestrator. Returns ok=false with blocked_reason when LLM, sandbox, Redis or database prerequisites are missing.",
            _object_schema(
                {
                    "target": {"type": "string"},
                    "campaign_id": {"type": "string"},
                },
                ("target",),
            ),
            self._scan_run,
        )
        self._add(
            "redfall_findings",
            "List stored findings and the evidence records linked to them. Optional campaign, scan or reportable filters.",
            _object_schema(
                {
                    "campaign_id": {"type": "string"},
                    "scan_id": {"type": "string"},
                    "finding_id": {"type": "string"},
                    "reportable": {"type": "boolean"},
                    "limit": {"type": "integer", "minimum": 1},
                },
            ),
            self._findings,
        )
        self._add(
            "redfall_finding",
            "Return one stored finding with its linked evidence, reproduction run and exact result.",
            _object_schema({"finding_id": {"type": "string"}}, ("finding_id",)),
            self._finding,
        )
        self._add(
            "redfall_reproduce",
            "Replay a stored finding's PoC in the gVisor sandbox. Returns blocked_reason when the sandbox is unavailable; never fabricates a verdict.",
            _object_schema(
                {
                    "finding_id": {"type": "string"},
                    "campaign_id": {"type": "string"},
                    "target": {"type": "string"},
                },
                ("finding_id",),
            ),
            self._reproduce,
        )
        self._add(
            "redfall_report",
            "Build an evidence-gated campaign report or SARIF log. Refuses when the chain is broken or no evidence-linked finding is reportable.",
            _object_schema(
                {
                    "campaign_id": {"type": "string"},
                    "format": {"type": "string", "enum": ["json", "sarif"]},
                },
                ("campaign_id",),
            ),
            self._report,
        )
        self._add(
            "redfall_policy_check",
            "Check whether a filesystem action is inside campaign scope or REDFALL_ALLOWED_ROOTS. Denials include the resolved roots and reason.",
            _object_schema(
                {
                    "action": {
                        "type": "string",
                        "enum": ["index", "scan", "reproduce", "report", "fix"],
                    },
                    "campaign_id": {"type": "string"},
                    "target": {"type": "string"},
                },
                ("action",),
            ),
            self._policy_check,
        )
        self._add(
            "redfall_adapter_certifications",
            "List measured adapter contract results. A certified row covers only the recorded server version, tool count and timestamp.",
            _object_schema({"limit": {"type": "integer", "minimum": 1}}),
            self._adapter_certifications,
        )
        self._add(
            "redfall_agents_list",
            "List the agent drivers RedFall can borrow reasoning from, and which are installed on this host. Certification rows cover only the recorded run.",
            _object_schema({}),
            self._agents_list,
        )
        self._add(
            "redfall_reasoning_describe",
            "Describe the reasoning backend that would be built from the effective config: a provider key, an installed agent, an OpenAI-compatible endpoint, or a router.",
            _object_schema({}),
            self._reasoning_describe,
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
        finding_id = self._optional_str(args, "finding_id")
        with self._scope() as session:
            records = EvidenceLedger(session).list(
                self._required_str(args, "campaign_id"),
                reportable_only=self._optional_bool(args, "reportable_only", False),
            )
            if finding_id:
                records = [record for record in records if record.finding_id == finding_id]
            return {"evidence": [record.to_wire() for record in records]}

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

    # -------------------------------------------------------- phase 2 helpers
    def _database_url(self) -> str:
        session = self._session_factory()
        try:
            return session.get_bind().url.render_as_string(hide_password=False)
        finally:
            session.close()

    def _campaign_or_error(self, session: Session, campaign_id: str) -> Campaign:
        campaign = session.get(Campaign, campaign_id)
        if campaign is None:
            raise ToolError(f"campaign not found: {campaign_id}")
        return campaign

    def _require_active(self, service: CampaignService, campaign: Campaign) -> None:
        if service.state(campaign) not in ACTIVE_STATES:
            raise ToolError(f"campaign {campaign.id} is {campaign.status}, not active")

    def _authorized_target(
        self,
        session: Session,
        target: str,
        *,
        campaign_id: str,
        action: str,
    ) -> Path:
        if campaign_id:
            campaign = self._campaign_or_error(session, campaign_id)
            self._require_active(CampaignService(session), campaign)
            return require_campaign_path(campaign, target, action=action)
        return require_os_path(target, action=action)

    def _snapshot_id(self, session: Session, args: dict[str, Any], *, campaign_id: str = "") -> str:
        snapshot_id = self._optional_str(args, "snapshot_id")
        if snapshot_id:
            return snapshot_id
        return GraphQuery(session).snapshot(campaign_id=campaign_id or None).id

    # --------------------------------------------------------- phase 2 tools
    def _campaign_run(self, args: dict[str, Any]) -> dict[str, Any]:
        max_tasks = self._optional_int(args, "max_tasks", 5)
        lease_seconds = self._optional_int(args, "lease_seconds", 300)
        if max_tasks is None:
            max_tasks = 5
        if lease_seconds is None:
            lease_seconds = 300
        config = replace(load_config(), database_url=self._database_url())
        runner = CampaignRunner(
            self._session_factory,
            worker=self._optional_str(args, "worker", "mcp-worker") or "mcp-worker",
            config=config,
            lease_seconds=lease_seconds,
            max_tasks=max_tasks,
        )
        return runner.run(self._required_str(args, "campaign_id"), max_tasks=max_tasks)

    def _campaign_reserve(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._scope() as session:
            reservation = CampaignService(session).reserve_spend(
                self._required_str(args, "campaign_id"),
                task_id=self._optional_str(args, "task_id") or None,
                usd=self._optional_number(args, "usd", 0.0) or 0.0,
                tokens=self._optional_int(args, "tokens", 0) or 0,
                sandbox_minutes=self._optional_number(args, "sandbox_minutes", 0.0) or 0.0,
                source=self._optional_str(args, "source"),
            )
            return reservation.to_wire()

    def _campaign_release_reservation(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._scope() as session:
            return CampaignService(session).release_reservation(
                self._required_str(args, "reservation_id"),
                reason=self._optional_str(args, "reason"),
            ).to_wire()

    def _campaign_settle_reservation(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._scope() as session:
            return CampaignService(session).settle_reservation(
                self._required_str(args, "reservation_id"),
                usd=self._optional_number(args, "usd", 0.0) or 0.0,
                tokens=self._optional_int(args, "tokens", 0) or 0,
                sandbox_minutes=self._optional_number(args, "sandbox_minutes", 0.0) or 0.0,
                source=self._optional_str(args, "source"),
                allow_overage=self._optional_bool(args, "allow_overage", False),
            )

    def _graph_index(self, args: dict[str, Any]) -> dict[str, Any]:
        target = self._required_str(args, "target")
        campaign_id = self._optional_str(args, "campaign_id")
        with self._scope() as session:
            if campaign_id:
                campaign = self._campaign_or_error(session, campaign_id)
                self._require_active(CampaignService(session), campaign)
                resolved = require_campaign_path(campaign, target, action="index")
            else:
                resolved = require_os_path(target, action="index")
            snapshot = GraphIndexer(session).index(
                resolved,
                campaign_id=campaign_id or None,
                label=self._optional_str(args, "label"),
            )
            stats = GraphQuery(session).stats(snapshot.id)
            return {
                "ok": True,
                "snapshot": snapshot.to_wire(),
                "stats": stats,
                "scan_id": snapshot.scan_id,
            }

    def _graph_latest(self, args: dict[str, Any]) -> dict[str, Any]:
        campaign_id = self._optional_str(args, "campaign_id")
        limit = self._optional_int(args, "limit", 1)
        if limit is None:
            limit = 1
        with self._scope() as session:
            query = GraphQuery(session)
            root = self._optional_str(args, "root")
            snapshots = query.list_snapshots(
                campaign_id=campaign_id or None,
                root=root or None,
                limit=limit,
            )
            return {"snapshots": snapshots, "snapshot": snapshots[0] if snapshots else None}

    def _graph_stats(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._scope() as session:
            return GraphQuery(session).stats(
                self._optional_str(args, "snapshot_id") or None,
                campaign_id=self._optional_str(args, "campaign_id") or None,
            )

    def _graph_search(self, args: dict[str, Any]) -> dict[str, Any]:
        limit = self._optional_int(args, "limit", 50)
        offset = self._optional_int(args, "offset", 0)
        with self._scope() as session:
            return GraphQuery(session).search(
                snapshot_id=self._optional_str(args, "snapshot_id") or None,
                query=self._optional_str(args, "query"),
                kind=self._optional_str(args, "kind"),
                file=self._optional_str(args, "file"),
                limit=limit if limit is not None else 50,
                offset=offset if offset is not None else 0,
            )

    def _graph_node(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._scope() as session:
            snapshot_id = self._snapshot_id(session, args)
            return GraphQuery(session).node_detail(snapshot_id, self._required_str(args, "node"))

    def _graph_neighbors(self, args: dict[str, Any]) -> dict[str, Any]:
        depth = self._optional_int(args, "depth", 1)
        limit = self._optional_int(args, "limit", 200)
        with self._scope() as session:
            snapshot_id = self._snapshot_id(session, args)
            return GraphQuery(session).neighbors(
                snapshot_id,
                self._required_str(args, "node"),
                direction=self._optional_str(args, "direction", "both") or "both",
                edge_kinds=self._optional_str_list(args, "edge_kinds") or None,
                depth=depth if depth is not None else 1,
                limit=limit if limit is not None else 200,
            )

    def _graph_paths(self, args: dict[str, Any]) -> dict[str, Any]:
        max_depth = self._optional_int(args, "max_depth", 5)
        limit = self._optional_int(args, "limit", 10)
        with self._scope() as session:
            snapshot_id = self._snapshot_id(session, args)
            return GraphQuery(session).paths(
                snapshot_id,
                self._required_str(args, "source"),
                self._required_str(args, "target"),
                max_depth=max_depth if max_depth is not None else 5,
                edge_kinds=self._optional_str_list(args, "edge_kinds") or None,
                limit=limit if limit is not None else 10,
            )

    def _graph_routes(self, args: dict[str, Any]) -> dict[str, Any]:
        limit = self._optional_int(args, "limit", 200)
        with self._scope() as session:
            return GraphQuery(session).routes(
                self._optional_str(args, "snapshot_id") or None,
                campaign_id=self._optional_str(args, "campaign_id") or None,
                method=self._optional_str(args, "method"),
                path_contains=self._optional_str(args, "path_contains"),
                limit=limit if limit is not None else 200,
            )

    def _graph_diff(self, args: dict[str, Any]) -> dict[str, Any]:
        limit = self._optional_int(args, "limit", 200)
        with self._scope() as session:
            return GraphQuery(session).diff(
                self._required_str(args, "base_snapshot"),
                self._required_str(args, "head_snapshot"),
                limit=limit if limit is not None else 200,
            )

    def _graph_sources(self, args: dict[str, Any]) -> dict[str, Any]:
        limit = self._optional_int(args, "limit", 200)
        role = self._optional_str(args, "role", "both") or "both"
        with self._scope() as session:
            data = GraphQuery(session).sources_sinks(
                self._optional_str(args, "snapshot_id") or None,
                campaign_id=self._optional_str(args, "campaign_id") or None,
                limit=limit if limit is not None else 200,
            )
        if role == "source":
            return {
                "snapshot_id": data["snapshot_id"],
                "sources": data["sources"],
                "truncated": data["truncated"],
            }
        if role == "sink":
            return {
                "snapshot_id": data["snapshot_id"],
                "sinks": data["sinks"],
                "truncated": data["truncated"],
            }
        return data

    def _graph_inventory(self, args: dict[str, Any]) -> dict[str, Any]:
        limit = self._optional_int(args, "limit", 200)
        with self._scope() as session:
            return GraphQuery(session).inventory(
                self._optional_str(args, "snapshot_id") or None,
                campaign_id=self._optional_str(args, "campaign_id") or None,
                limit=limit if limit is not None else 200,
            )

    def _scan_run(self, args: dict[str, Any]) -> dict[str, Any]:
        target = self._required_str(args, "target")
        campaign_id = self._optional_str(args, "campaign_id")
        with self._scope() as session:
            campaign: Campaign | None = None
            if campaign_id:
                campaign = self._campaign_or_error(session, campaign_id)
                self._require_active(CampaignService(session), campaign)
                resolved = require_campaign_path(campaign, target, action="scan")
            else:
                resolved = require_os_path(target, action="scan")
            database_url = session.get_bind().url.render_as_string(hide_password=False)
            config = replace(load_config(), database_url=database_url)
            try:
                report = run_scan(config, resolved)
            except PrerequisiteError as exc:
                return {"ok": False, "blocked_reason": str(exc), "failures": list(exc.failures)}
            except RuntimeError as exc:
                return {"ok": False, "blocked_reason": str(exc), "failures": []}
            evidence: dict[str, Any] | None = None
            if campaign is not None:
                evidence = record_scan_evidence(session, campaign, report, target=resolved)
            return {
                "ok": True,
                "scan": asdict(report),
                "evidence": evidence,
            }

    def _findings(self, args: dict[str, Any]) -> dict[str, Any]:
        limit = self._optional_int(args, "limit", 100)
        if limit is None:
            limit = 100
        limit = min(max(limit, 1), 1000)
        with self._scope() as session:
            statement = select(Finding)
            campaign_id = self._optional_str(args, "campaign_id")
            scan_id = self._optional_str(args, "scan_id")
            finding_id = self._optional_str(args, "finding_id")
            if finding_id:
                statement = statement.where(Finding.id == finding_id)
            if scan_id:
                statement = statement.where(Finding.scan_id == scan_id)
            if campaign_id:
                campaign = self._campaign_or_error(session, campaign_id)
                linked = session.scalars(
                    select(EvidenceRecord.finding_id).where(
                        EvidenceRecord.campaign_id == campaign_id,
                        EvidenceRecord.finding_id.is_not(None),
                    )
                ).all()
                ids = {str(item) for item in linked if item}
                if campaign.scan_id:
                    statement = statement.where(
                        or_(Finding.scan_id == campaign.scan_id, Finding.id.in_(ids) if ids else Finding.id == "")
                    )
                elif ids:
                    statement = statement.where(Finding.id.in_(ids))
                else:
                    statement = statement.where(Finding.id == "")
            if self._optional_bool(args, "reportable", False):
                evidence_ids = select(EvidenceRecord.finding_id).where(
                    EvidenceRecord.grade.in_(("E3", "E4")),
                    EvidenceRecord.finding_id.is_not(None),
                )
                if campaign_id:
                    evidence_ids = evidence_ids.where(EvidenceRecord.campaign_id == campaign_id)
                statement = statement.where(Finding.id.in_(evidence_ids))
            total = int(
                session.execute(
                    select(func.count()).select_from(statement.order_by(None).subquery())
                ).scalar_one()
            )
            rows = session.scalars(
                statement.order_by(Finding.discovered_at.desc()).limit(limit)
            ).all()
            evidence_statement = select(EvidenceRecord).where(
                EvidenceRecord.finding_id.in_([row.id for row in rows])
            )
            if campaign_id:
                evidence_statement = evidence_statement.where(
                    EvidenceRecord.campaign_id == campaign_id
                )
            evidence_rows = session.scalars(evidence_statement).all() if rows else []
            by_finding: dict[str, list[EvidenceRecord]] = {}
            for record in evidence_rows:
                if record.finding_id:
                    by_finding.setdefault(record.finding_id, []).append(record)
            findings = []
            for row in rows:
                wire = row.to_wire()
                records = by_finding.get(row.id, [])
                wire["evidence_ids"] = [record.id for record in records]
                wire["verified_by_evidence"] = any(record.grade in {"E3", "E4"} for record in records)
                findings.append(wire)
            return {
                "findings": findings,
                "returned": len(findings),
                "total": total,
                "truncated": total > len(findings),
            }

    def _finding(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._scope() as session:
            finding = session.get(Finding, self._required_str(args, "finding_id"))
            if finding is None:
                raise ToolError(f"finding not found: {args.get('finding_id')}")
            records = session.scalars(
                select(EvidenceRecord)
                .where(EvidenceRecord.finding_id == finding.id)
                .order_by(EvidenceRecord.created_at)
            ).all()
            wire = finding.to_wire()
            wire["evidence_records"] = [record.to_wire() for record in records]
            return {"finding": wire}

    def _reproduce(self, args: dict[str, Any]) -> dict[str, Any]:
        finding_id = self._required_str(args, "finding_id")
        campaign_id = self._optional_str(args, "campaign_id")
        with self._scope() as session:
            finding = session.get(Finding, finding_id)
            if finding is None:
                raise ToolError(f"finding not found: {finding_id}")
            scan = session.get(Scan, finding.scan_id)
            if scan is None:
                raise ToolError(f"finding {finding_id} has no scan target")
            raw_target = self._optional_str(args, "target") or scan.repo
            if campaign_id:
                campaign = self._campaign_or_error(session, campaign_id)
                self._require_active(CampaignService(session), campaign)
                target = require_campaign_path(campaign, raw_target, action="reproduce")
            else:
                target = require_os_path(raw_target, action="reproduce")
            config = load_config()
            try:
                outcome = Reproducer(
                    session,
                    workdir=config.workdir / "workspaces",
                    timeout_s=config.sandbox_timeout_s,
                ).reproduce(finding_id, campaign_id=campaign_id or None, target=target)
            except ReproductionBlocked as exc:
                return {
                    "ok": False,
                    "blocked_reason": exc.reason,
                    "details": exc.details,
                }
            except ReproductionError as exc:
                raise ToolError(str(exc)) from exc
            return {"ok": True, **outcome.to_wire()}

    def _report(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._scope() as session:
            report = build_campaign_report(
                session,
                self._required_str(args, "campaign_id"),
                report_format=self._optional_str(args, "format", "json") or "json",
            )
            return {"ok": True, **report}

    def _policy_check(self, args: dict[str, Any]) -> dict[str, Any]:
        action = self._required_str(args, "action")
        target = self._optional_str(args, "target")
        campaign_id = self._optional_str(args, "campaign_id")
        if not target:
            return {
                "allowed": action in {"report"},
                "action": action,
                "target": "",
                "roots": [],
                "reason": "no filesystem path requested" if action == "report" else "a target path is required",
            }
        with self._scope() as session:
            if campaign_id:
                campaign = self._campaign_or_error(session, campaign_id)
                decision = check_campaign_path(campaign, target, action=action)
            else:
                decision = check_os_path(target, action=action)
            return decision.to_wire()

    def _adapter_certifications(self, args: dict[str, Any]) -> dict[str, Any]:
        limit = self._optional_int(args, "limit", 20)
        if limit is None:
            limit = 20
        limit = min(max(limit, 1), 100)
        with self._scope() as session:
            rows = session.scalars(
                select(AdapterCertification)
                .order_by(AdapterCertification.certified_at.desc())
                .limit(limit)
            ).all()
            return {"certifications": [row.to_wire() for row in rows]}

    def _agents_list(self, args: dict[str, Any]) -> dict[str, Any]:
        from ..agents import driver_registry

        registry = driver_registry()
        return {
            "supported": len(registry.names()),
            "installed": registry.detected(),
            "agents": registry.describe_all(),
        }

    def _reasoning_describe(self, args: dict[str, Any]) -> dict[str, Any]:
        from ..reasoning import load_backend_config
        from ..reasoning.factory import make_backend

        config = load_backend_config()
        out: dict[str, Any] = {"config": config.as_dict()}
        try:
            backend = make_backend(config, session_factory=None, budget=None)
            out["backend"] = backend.describe()
        except Exception as exc:  # noqa: BLE001 - describe reports, it does not crash
            out["backend"] = None
            out["error"] = str(exc)
        return out

