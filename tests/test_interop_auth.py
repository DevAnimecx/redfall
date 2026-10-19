"""Phase 3 agent identity: explicit scopes, quotas, revocation and audit."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from redfall.interop.audit import record_call
from redfall.interop.auth import (
    AuthError,
    QuotaError,
    ScopeError,
    TOOL_SCOPES,
    authenticate,
    authorize_tool,
    create_token,
    grant_satisfies,
    hash_token,
    list_tokens,
    revoke_token,
    used_this_hour,
)
from redfall.interop.tools import ToolRegistry
from redfall.store.models import Base


@pytest.fixture()
def session(tmp_path):
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'auth.db'}", future=True
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    with Session() as db:
        yield db
    engine.dispose()


def test_tool_scope_map_covers_every_advertised_tool(session):
    registry = ToolRegistry(lambda: session)
    advertised = {spec["name"] for spec in registry.specs()}
    assert advertised == set(TOOL_SCOPES), (
        f"unmapped tools: {sorted(advertised - set(TOOL_SCOPES))}, "
        f"stale mappings: {sorted(set(TOOL_SCOPES) - advertised)}"
    )


def test_token_plaintext_is_never_the_stored_value(session):
    row, token = create_token(session, name="ci", scopes=["read", "execute"])
    assert token.startswith("rfl_")
    assert row.token_sha256 == hash_token(token)
    assert row.token_sha256 != token
    found = authenticate(session, token)
    assert found.id == row.id
    assert found.last_used_at is not None
    with pytest.raises(AuthError, match="unknown token"):
        authenticate(session, token + "tampered")


def test_scopes_are_explicit_and_admin_implies_all(session):
    reader, _ = create_token(session, name="reader", scopes=["read"])
    authorize_tool(session, reader, "redfall_graph_latest")
    with pytest.raises(ScopeError, match="requires scope 'execute'"):
        authorize_tool(session, reader, "redfall_graph_index")

    admin, _ = create_token(session, name="admin", scopes=["admin"])
    authorize_tool(session, admin, "redfall_campaign_create")
    assert grant_satisfies({"admin"}, "write") is True
    assert grant_satisfies({"read"}, "write") is False


def test_quota_counts_audited_calls_in_the_rolling_hour(session):
    row, _ = create_token(session, name="quota", scopes=["read"], quota_per_hour=1)
    authorize_tool(session, row, "redfall_health")
    assert used_this_hour(session, row.id) == 0
    record_call(
        session,
        protocol="http",
        agent=row.name,
        token_id=row.id,
        tool="redfall_health",
        ok=True,
    )
    assert used_this_hour(session, row.id) == 1
    with pytest.raises(QuotaError, match="1/1"):
        authorize_tool(session, row, "redfall_health")


def test_zero_quota_means_unlimited(session):
    row, _ = create_token(session, name="unlimited", scopes=["read"], quota_per_hour=0)
    for _ in range(5):
        record_call(
            session,
            protocol="http",
            agent=row.name,
            token_id=row.id,
            tool="redfall_health",
            ok=True,
        )
    authorize_tool(session, row, "redfall_health")


def test_revocation_is_immediate(session):
    row, token = create_token(session, name="old-ci", scopes=["read"])
    authenticate(session, token)
    revoke_token(session, token_id=row.id)
    with pytest.raises(AuthError, match="revoked"):
        authenticate(session, token)
    assert list_tokens(session)[0].to_wire()["revoked"] is True


def test_invalid_tokens_are_rejected_at_creation(session):
    with pytest.raises(ValueError, match="unknown scope"):
        create_token(session, name="bad", scopes=["root"])
    with pytest.raises(ValueError, match="at least one scope"):
        create_token(session, name="empty", scopes=[])
    with pytest.raises(ValueError, match="quota_per_hour"):
        create_token(session, name="bad-quota", scopes=["read"], quota_per_hour=-1)
    with pytest.raises(AuthError, match="missing bearer"):
        authenticate(session, "")
