"""The deployment artifacts: the image, the compose stack and their invariants.

There is no Docker on the build host, so these tests cannot build the image or
bring the stack up. What they can do is check the properties that a broken
deployment would violate — a compose file that does not parse, a stack that
publishes Postgres to the world, an image that runs as root, a healthcheck that
is not the capability check.

That is a real limit and it is stated rather than papered over: these verify the
manifests, not the deployment. Anything about what the image actually does when
built is unverified here.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

DEPLOY = ROOT / "deploy"


def test_the_deploy_directory_ships_what_it_says():
    assert (DEPLOY / "Dockerfile").is_file()
    assert (DEPLOY / "docker-compose.yml").is_file()
    assert (DEPLOY / "README.md").is_file()


def test_the_compose_file_parses_as_yaml():
    """A compose file with a tab or a stray colon fails before anything runs."""
    yaml = pytest.importorskip("yaml")
    document = yaml.safe_load((DEPLOY / "docker-compose.yml").read_text(encoding="utf-8"))
    assert document["name"] == "redfall"
    assert set(document["services"]) == {"db", "cache", "engine"}


def test_the_engine_builds_from_the_repository_root():
    yaml = pytest.importorskip("yaml")
    document = yaml.safe_load((DEPLOY / "docker-compose.yml").read_text(encoding="utf-8"))
    build = document["services"]["engine"]["build"]
    assert build["context"] == ".."
    assert build["dockerfile"] == "deploy/Dockerfile"


def test_the_database_is_not_published_to_the_host():
    """A Postgres port open to the host is open to whatever else shares it."""
    yaml = pytest.importorskip("yaml")
    document = yaml.safe_load((DEPLOY / "docker-compose.yml").read_text(encoding="utf-8"))
    assert "ports" not in document["services"]["db"]
    assert "ports" not in document["services"]["cache"]


def test_the_console_binds_loopback_by_default():
    yaml = pytest.importorskip("yaml")
    document = yaml.safe_load((DEPLOY / "docker-compose.yml").read_text(encoding="utf-8"))
    published = document["services"]["engine"]["ports"][0]
    assert published.startswith("${REDFALL_BIND:-127.0.0.1}:"), published


def test_the_data_volumes_are_named_not_bind_mounted():
    """A bind mount that later moves breaks every recorded reproduction."""
    yaml = pytest.importorskip("yaml")
    document = yaml.safe_load((DEPLOY / "docker-compose.yml").read_text(encoding="utf-8"))
    assert "redfall-db" in document["volumes"]
    assert "redfall-state" in document["volumes"]
    engine_mounts = document["services"]["engine"]["volumes"]
    assert any(m.startswith("redfall-state:") for m in engine_mounts)


def test_the_socket_mount_is_present_and_documented_as_a_risk():
    """The socket is root-equivalent; the choice must be visible, not hidden."""
    yaml = pytest.importorskip("yaml")
    text = (DEPLOY / "docker-compose.yml").read_text(encoding="utf-8")
    document = yaml.safe_load(text)
    mounts = document["services"]["engine"]["volumes"]
    assert any("docker.sock" in m for m in mounts)
    assert "socket-proxy" in text, "the safer alternative must be documented in the stack"


def test_the_readme_documents_the_socket_proxy_alternative():
    text = (DEPLOY / "README.md").read_text(encoding="utf-8")
    assert "socket-proxy" in text
    assert "docker.sock" in text
    # The risk must be stated in plain words, not implied.
    assert "root" in text.lower()


def test_no_credential_is_committed_in_the_stack():
    """Everything sensitive comes from the environment."""
    text = (DEPLOY / "docker-compose.yml").read_text(encoding="utf-8")
    yaml = pytest.importorskip("yaml")
    document = yaml.safe_load(text)
    for service in document["services"].values():
        for value in (service.get("environment") or {}).values():
            if not isinstance(value, str):
                continue
            # Every credential-shaped value must be a ${...} substitution.
            assert "sk-" not in value, value
    assert "sk-ant-" not in text and "sk-proj-" not in text


def test_the_image_builds_from_the_packaging_metadata():
    text = (DEPLOY / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY pyproject.toml" in text
    assert "pip install" in text


def test_the_image_runs_as_a_non_root_user():
    text = (DEPLOY / "Dockerfile").read_text(encoding="utf-8")
    assert "useradd" in text
    assert "USER redfall" in text
    # And the user is not uid 0 under another name.
    assert "--uid 10001" in text


def test_the_healthcheck_is_the_capability_check():
    """A container that cannot scan is unhealthy, not merely busy."""
    text = (DEPLOY / "Dockerfile").read_text(encoding="utf-8")
    assert "HEALTHCHECK" in text
    assert "redfall" in text and "doctor" in text
    assert "--quiet" in text


def test_state_is_on_a_declared_volume():
    text = (DEPLOY / "Dockerfile").read_text(encoding="utf-8")
    assert "VOLUME" in text
    assert "/var/lib/redfall" in text


def test_the_orchestrator_image_does_not_contain_the_sandbox_image():
    """The engine stays outside the boundary it drives."""
    text = (DEPLOY / "Dockerfile").read_text(encoding="utf-8")
    assert "sandbox" not in text.lower().split("#")[0]
    # The sandbox image keeps its own Dockerfile, untouched by this one.
    assert (ROOT / "src" / "redfall" / "sandbox" / "images" / "redfall-sandbox" / "Dockerfile").is_file()


# -- the doctor flag the healthcheck depends on -----------------------------

def test_doctor_has_a_quiet_flag_the_healthcheck_uses():
    from click.testing import CliRunner

    from redfall.cli import main

    result = CliRunner().invoke(main, ["doctor", "--help"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "--quiet" in result.output


def test_quiet_doctor_prints_only_failures():
    """The exit code is the answer; the table is noise in a healthcheck."""
    from unittest import mock

    from click.testing import CliRunner

    from redfall.cli import main

    with mock.patch("redfall.cli.check_prerequisites"):
        with mock.patch("redfall.cli.ping", return_value=(True, "PostgreSQL 17")):
            result = CliRunner().invoke(main, ["doctor", "--quiet"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "Redfall prerequisites" not in result.output
    assert "all prerequisites satisfied" not in result.output


# -- the version the image reports ------------------------------------------

def test_the_image_version_matches_the_package():
    """A tag and a wheel that disagree is behaviour nobody tested."""
    from redfall import __version__

    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["version"] == __version__
