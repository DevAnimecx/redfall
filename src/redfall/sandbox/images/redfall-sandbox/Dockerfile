# Image used for every exploit execution and fix verification run.
# Started with --runtime=runsc, --cap-drop=ALL, --no-new-privileges, pids-limit.
FROM node:20-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates postgresql-client jq python3 python3-pip git \
 && rm -rf /var/lib/apt/lists/*

# The harness that runs inside the container. It is the only thing that talks to
# the target app, so exploit evidence comes from real HTTP traffic.
RUN useradd --uid 10001 --create-home runner
WORKDIR /work
USER runner

# No ENTRYPOINT. A `bash -lc` entrypoint swallows the argv the caller passes:
# `docker run img node harness.mjs` makes bash exec `node` with $0="harness.mjs"
# and no arguments, so the harness silently never runs and the run reports
# success with empty stdout. Callers pass their own vector, including the
# `bash -lc` wrapper when they want shell semantics.
ENTRYPOINT []
