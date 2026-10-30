# The RedFall deployment image: the orchestrator, not the sandbox.
#
# Two images exist and the distinction matters. `src/redfall/sandbox/images/`
# builds the *sandbox* image — what an exploit runs inside, with the harness and
# a target's runtime. This builds the *orchestrator*: the process that reads
# source, plans, and drives the sandbox over the Docker socket. Mixing them
# would put the engine that must stay trusted inside the boundary it is meant to
# be outside of.
#
# The orchestrator is given no capabilities and a read-only root; everything it
# needs to write lives on a named volume. To start a sandbox it talks to the
# host's Docker daemon through a mounted socket. That socket is root-equivalent
# on the host, which is a real risk and is stated rather than hidden: see
# deploy/README.md for the socket-proxy alternative and why a deployment that
# cares should use it.

FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="RedFall" \
      org.opencontainers.image.description="Autonomous, evidence-gated vulnerability discovery and verified repair" \
      org.opencontainers.image.source="https://github.com/DevAnimecx/redfall" \
      org.opencontainers.image.licenses="Apache-2.0"

# git: a campaign checks out a target revision. ca-certificates: the model
# transport. No docker CLI — the Python SDK talks to the socket, and a CLI in
# the image would suggest a shell path that is not the supported one.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --create-home --shell /usr/sbin/nologin redfall

# Pull dependencies in their own layer so an engine change does not re-resolve
# the whole tree on every build.
WORKDIR /opt/redfall
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . \
 && rm -rf /opt/redfall/src

# State that must survive a restart: the clone cache, evidence bundles, scan
# artefacts. Declared as volumes so a `docker run` without them is a warning
# rather than a silent loss of the evidence ledger.
RUN mkdir -p /var/lib/redfall/work /var/lib/redfall/evidence \
 && chown -R redfall:redfall /var/lib/redfall
VOLUME ["/var/lib/redfall"]

ENV REDFALL_HOME=/var/lib/redfall \
    REDFALL_DATABASE_URL="" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER redfall
WORKDIR /opt/redfall

# The engine has no fallback execution path, so an image that cannot reach a
# sandbox must say so before it is asked to scan. `redfall doctor` exits
# nonzero when a prerequisite is missing; in container mode that failure is the
# image's own smoke test.
HEALTHCHECK --interval=30s --timeout=20s --start-period=10s --retries=3 \
    CMD ["redfall", "doctor", "--quiet"]

ENTRYPOINT ["redfall"]
CMD ["--help"]
