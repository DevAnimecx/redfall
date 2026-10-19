"""Filesystem scope is resolved before any real operation starts."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from redfall.campaign.policy import (
    PolicyError,
    check_campaign_path,
    check_os_path,
    require_campaign_path,
    require_os_path,
)
from redfall.campaign.service import CampaignService
from redfall.store.models import Base, Campaign
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


@pytest.fixture()
def campaign(tmp_path):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'policy.db'}", future=True)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    target = tmp_path / "allowed"
    target.mkdir()
    with Session() as session:
        row = CampaignService(session).create(str(target), scope={"repos": [str(target)]})
        session.commit()
        campaign_id = row.id
    with Session() as session:
        yield session.get(Campaign, campaign_id)
    engine.dispose()


def test_campaign_scope_allows_descendants_and_denies_others(campaign, tmp_path):
    inside = Path(campaign.repo)
    (inside / "src").mkdir()
    allowed = check_campaign_path(campaign, inside / "src", action="index")
    assert allowed.allowed is True
    assert allowed.target == str((inside / "src").resolve())

    outside = tmp_path / "outside"
    outside.mkdir()
    denied = check_campaign_path(campaign, outside, action="index")
    assert denied.allowed is False
    assert "outside every allowed root" in denied.reason
    with pytest.raises(PolicyError):
        require_campaign_path(campaign, outside, action="index")


def test_operator_roots_are_required_for_unscoped_operations(tmp_path, monkeypatch):
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    target = allowed_root / "repo"
    target.mkdir()
    monkeypatch.setenv("REDFALL_ALLOWED_ROOTS", str(allowed_root))
    decision = check_os_path(target, action="scan")
    assert decision.allowed is True

    monkeypatch.delenv("REDFALL_ALLOWED_ROOTS", raising=False)
    denied = check_os_path(target, action="scan")
    assert denied.allowed is False
    assert denied.roots == []
    with pytest.raises(PolicyError):
        require_os_path(target, action="scan")


def test_directory_requirement_is_reported(campaign, tmp_path):
    file_path = Path(campaign.repo) / "app.py"
    file_path.write_text("print('real file')\n", encoding="utf-8")
    denied = check_campaign_path(campaign, file_path, action="index")
    assert denied.allowed is False
    assert denied.reason == "target is not a directory"


def test_symlink_is_resolved_before_the_check(tmp_path, monkeypatch):
    root = tmp_path / "allowed"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = root / "link"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"host cannot create directory symlinks: {exc}")
    monkeypatch.setenv("REDFALL_ALLOWED_ROOTS", str(root))
    decision = check_os_path(link, action="index")
    assert decision.allowed is False
    assert decision.target == str(outside.resolve())
