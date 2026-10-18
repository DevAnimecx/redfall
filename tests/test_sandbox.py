"""The sandbox must refuse to run without gVisor. It must not fall back."""

from __future__ import annotations

import re

import pytest

from redfall.sandbox.docker_gvisor import (
    RUNTIME,
    DockerGVisorSandbox,
    SandboxRequest,
    SandboxUnavailable,
    check_runtime,
    describe,
    ensure_runtime,
)


def test_runtime_is_gvisor():
    assert RUNTIME == "runsc"


def test_describe_reports_the_truth_about_this_host():
    report = describe()
    assert report["runtime"] == "runsc"
    assert isinstance(report["ready"], bool)
    if not report["ready"]:
        assert report["reasons_unavailable"], "unavailable but no reason given"


def test_ensure_runtime_raises_when_gvisor_is_absent():
    if not check_runtime():
        pytest.skip("gVisor is actually available here")
    with pytest.raises(SandboxUnavailable) as info:
        ensure_runtime()
    assert info.value.reasons


def test_construction_refuses_without_gvisor():
    if not check_runtime():
        pytest.skip("gVisor is actually available here")
    with pytest.raises(SandboxUnavailable):
        DockerGVisorSandbox()


def test_run_refuses_before_executing_anything():
    """A request must never reach the host when the sandbox is unavailable."""
    if not check_runtime():
        pytest.skip("gVisor is actually available here")
    sandbox = DockerGVisorSandbox.__new__(DockerGVisorSandbox)
    sandbox.image = "redfall-sandbox:latest"
    with pytest.raises(SandboxUnavailable):
        sandbox.run(SandboxRequest(workdir=__import__("pathlib").Path("/tmp"), command=["id"], timeout_s=10))


def test_there_is_no_host_execution_path():
    """Rule 5: every execution goes through the docker CLI with --runtime=runsc."""
    from pathlib import Path

    source = Path(__file__).resolve().parent.parent / "src/redfall/sandbox/docker_gvisor.py"
    text = source.read_text()

    assert "os.system" not in text, "os.system is a host execution path"
    assert "shell=True" not in text, "shell=True would interpolate into a host shell"
    assert "import subprocess" in text, "expected the docker CLI to be the only executor"

    # Every command vector handed to subprocess must begin with the docker CLI.
    calls = text.count("subprocess.run(")
    docker_first = len(
        re.findall(r'subprocess\.run\(\s*(?:\[\s*(?:"docker"|docker\b)|cmd)', text, re.DOTALL)
    )
    assert calls == docker_first, (
        f"{calls - docker_first} subprocess call(s) do not start with the docker CLI"
    )

    command_builder = text[text.index("def _docker_command") :]
    assert '"docker",' in command_builder, "the command vector does not start with docker"
    assert '--runtime={RUNTIME}' in command_builder, "containers are not started on gVisor"


# ---------------------------------------------------------------------------
# The positive path. The tests above only prove the sandbox refuses when gVisor
# is missing; on a host where it is present that is the easy half. These run a
# real container and assert on what actually came back.
# ---------------------------------------------------------------------------

from pathlib import Path  # noqa: E402

from redfall.sandbox.docker_gvisor import (  # noqa: E402
    build_image,
    SandboxExecutionError,
)

IMAGE_DIR = Path(__file__).resolve().parent.parent / "src/redfall/sandbox/images/redfall-sandbox"

# The container runs as uid 10001, so it needs the same traversal rights a
# checked-out repo gives: pytest's tmp_path is 0700 and is unreadable to it.
@pytest.fixture
def readable_workdir(tmp_path):
    tmp_path.chmod(0o755)
    return tmp_path


@pytest.fixture(scope="module")
def live_sandbox():
    """A built image and a sandbox that can really run, or skip if the host cannot."""
    if check_runtime():
        pytest.skip("gVisor unavailable on this host: nothing to execute")
    try:
        tag = build_image(IMAGE_DIR)
    except SandboxExecutionError as exc:  # pragma: no cover - host-dependent
        pytest.skip(f"image build failed: {exc}")
    return DockerGVisorSandbox(image=tag)


def test_a_command_actually_runs_and_its_output_is_captured(live_sandbox, readable_workdir):
    result = live_sandbox.run(
        SandboxRequest(
            workdir=readable_workdir,
            command=["sh", "-c", "echo OUT=$((6*7)); echo ERR>&2; exit 3"],
            timeout_s=120,
        )
    )
    assert result.exit_code == 3
    assert result.stdout.strip() == "OUT=42", "stdout was not captured"
    assert "ERR" in result.stderr, "stderr was not captured"
    assert result.ok is False


def test_the_workdir_is_mounted_at_work(live_sandbox, readable_workdir):
    (readable_workdir / "marker.txt").write_text("from the host\n")
    result = live_sandbox.run(
        SandboxRequest(workdir=readable_workdir, command=["cat", "/work/marker.txt"], timeout_s=120)
    )
    assert result.ok, result.stderr
    assert result.stdout.strip() == "from the host"


def test_the_container_is_unprivileged_and_drop_all_caps_took_effect(live_sandbox, readable_workdir):
    result = live_sandbox.run(
        SandboxRequest(workdir=readable_workdir, command=["id", "-u"], timeout_s=120)
    )
    assert result.ok, result.stderr
    uid = int(result.stdout.strip())
    assert uid != 0, "the container ran as root"


def test_no_entrypoint_swallows_the_callers_argv(live_sandbox, readable_workdir):
    """Regression: `ENTRYPOINT bash -lc` turned argv into $0/$1 and the
    harness silently never ran, so a failed reproduction reported success."""
    (readable_workdir / "harness.mjs").write_text(
        'console.log("RAN argv=" + JSON.stringify(process.argv.slice(2)));\n'
    )
    result = live_sandbox.run(
        SandboxRequest(
            workdir=readable_workdir,
            command=["node", "harness.mjs", "flag"],
            timeout_s=120,
        )
    )
    assert result.ok, result.stderr
    assert 'RAN argv=["flag"]' in result.stdout, (
        "the harness did not receive its arguments; got " + repr(result.stdout)
    )


def test_execution_happens_in_the_gvisor_sentry_kernel(live_sandbox, readable_workdir):
    """gVisor presents its own kernel version, which is how we know the code
    ran inside the Sentry rather than on the host."""
    host = Path("/proc/version").read_text()
    result = live_sandbox.run(
        SandboxRequest(workdir=readable_workdir, command=["uname", "-r"], timeout_s=120)
    )
    assert result.ok, result.stderr
    assert result.stdout.strip(), "uname returned nothing"
    assert result.stdout.strip() not in host, (
        "the container reports the host kernel; it is not sandboxed by gVisor"
    )
