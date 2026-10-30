---
title: Tenancy, roles and policy
seoTitle: "Multi-Tenant Vulnerability Scanning with RBAC | RedFall Enterprise"
description: "RedFall's enterprise control plane: tenant isolation derived from a credential, five roles, per-tenant policy-as-code rules, and a gap-free audit export for a SIEM."
path: docs/enterprise/
group: Trust and evidence
kind: cluster
pillar: security
order: 22
updated: 2026-10-30
keywords: multi-tenant vulnerability scanner, security scanner RBAC, policy as code security, audit export SIEM, tenant isolation
sources: https://github.com/DevAnimecx/redfall/blob/main/src/redfall/enterprise/tenancy.py, https://github.com/DevAnimecx/redfall/blob/main/src/redfall/enterprise/policy.py
related: security, interop, dashboard
---

**RedFall 0.5.0 grows an enterprise control plane.** A team can be put behind an
isolation boundary, given roles that decide what each member may do, and
governed by policy rules an operator writes. It is **off unless
`REDFALL_TENANCY` is set**: a single-operator install creates no tenant and has
no rule evaluated against it, so nothing about the earlier behaviour changes.

> **What this page does not claim.** No OIDC or SAML provider is wired up. An
> `idp_subject` column exists and nothing authenticates against it. The identity
> half of SSO is stored, not enforced. Read [Security](/docs/security/) alongside
> this page.

## The rule the whole layer enforces

**A tenant is derived, never accepted.**

A caller presents a credential. The credential resolves to a tenant on a
persisted row. The scope object built from that tenant is the only thing queries
filter on:

```python
scope = resolve_scope(session, token)          # tenant comes from token.tenant_id
clause = scope.filter_column(Campaign.tenant_id)
session.scalars(select(Campaign).where(clause)) # only this tenant's rows
```

No API takes a `tenant_id` a client can choose. That is deliberate, and it is
the difference between a control you can misconfigure and one you cannot: "read
another tenant's campaign by guessing its id" is not a policy setting, because
the id never reaches the query as anything but a value to match *within* the
resolved tenant.

Two behaviours fall out of this and both are tested:

- A token belonging to tenant A that names tenant B is refused outright —
  `token belongs to tenant A and cannot act as B`.
- A read of another tenant's campaign by its real id returns `None`, *and the
  row is still present*. The test asserts both halves, because deleting the row
  would make the check pass for the wrong reason.

## Roles

Five roles, each carrying an explicit permission set rather than a rank. An
operator adds a role by editing a table, not by picking a number on a ladder:

| Role | Can |
| --- | --- |
| `viewer` | Read campaigns, findings and evidence |
| `analyst` | Triage findings, propose fixes, read policy |
| `engineer` | Run campaigns, apply fixes, manage agents |
| `owner` | Everything, including policy and member management |
| `auditor` | Read and export evidence, audit and policy. Change nothing |

`owner` is the only role holding `tenant:admin`, and a test asserts it — so a
future edit that quietly hands administration to `analyst` fails the suite.

An unknown role grants nothing rather than raising. A row carrying a stale role
string refuses the action instead of crashing the request, because a denial is
the safe direction and a 500 is not.

## Policy as code

A rule is a small statement — effect, action pattern, condition — stored per
tenant:

```json
{
  "rules": [
    {
      "effect": "deny",
      "action": "redfall_fix_apply*",
      "name": "no-auto-fix",
      "priority": 10
    },
    {
      "effect": "deny",
      "action": "redfall_scan_run",
      "name": "classified-frozen",
      "condition": {"arg.target": {"prefix": "/srv/classified"}}
    }
  ]
}
```

Load it with `redfall tenant policy-load <slug> policy.json`. A malformed file
changes nothing: it is parsed and validated before anything is written, so a
typo on line 20 cannot leave a tenant with no policy at all.

**Conditions are data, not code.** A condition is a mapping of field, operator
and value. There is no expression language and no `eval` — which the no-mock
contract forbids in `src/` for the same reason, and a policy engine is exactly
where the temptation to add one lives. Operators are `equals`, `not_equals`,
`prefix`, `suffix`, `contains`, `in`, `not_in`, `exists`, `matches`, `gt`, `lt`.
A `matches` pattern is anchored at both ends, because an unanchored pattern in a
policy rule is far more likely a mistake that widens the rule than an intent.

### The three-way default, which is the part to understand

The engine's answer when nothing matches depends on *why* nothing matched, and
the two cases are opposite on purpose:

| Situation | Verdict | Why |
| --- | --- | --- |
| The tenant has **no rules at all** | **Deny** | The operator turned policy on without writing any. An empty policy that allowed everything would be a no-op that looks like enforcement. `REDFALL_POLICY=open` flips this. |
| **No rule's pattern covers** this action | **Allow** | The policy is silent about it. Silence is not a prohibition. |
| A rule's pattern covers it and its **condition did not hold** | **Allow** | That is what writing a condition means. |

The second and third rows are why a conditional rule is usable. An operator
narrowing "deny scans of `/srv/classified`" must leave `/srv/public` alone. If
"no match" denied, narrowing a rule would silently deny everything it was not
written about, and operators would learn not to write conditions at all.

At equal priority a **deny outranks an allow**, so a broad wildcard permission
cannot swallow an explicit prohibition.

Run `redfall tenant policy-check <slug> <action> --context-json '{...}'` to see
the verdict *and* every rule considered with the clause that decided it.

## Audit export

Every authenticated gateway call is already recorded, including denials —
an audit trail that hides failures cannot answer "who tried to widen their
scope".

```bash
redfall tenant audit-export acme --format jsonl --out audit.jsonl
```

Two properties matter:

- **The resume point is the last record written, not the wall clock.** A barrier
  taken as "now" is *later* than every row in the export, so resuming from it
  skips every call that landed during the read. Anchoring to the last exported
  row means the next export resumes exactly where this one stopped — no gap, no
  overlap.
- **Credential-shaped text is redacted by default.** `--no-redact` is an
  explicit choice, recorded on the export row, rather than something a format
  implies.

`verify_coverage` answers whether a range would truncate before producing a
file, because a truncated compliance export is a false statement.

## Adopting rows written before tenancy

A database written before 0.5.0 has `tenant_id = ''` on every campaign and
token. Left alone, an enforced deployment shows an empty console and refuses
every existing credential — which reads as data loss even though nothing was
dropped.

```bash
redfall tenant adopt --check     # count what predates tenancy
redfall tenant adopt             # claim it into the default tenant
```

Idempotent, counted, and never silent.

## What is not here

- **No identity provider.** OIDC and SAML are not implemented. Authentication is
  a bearer token; the tenancy layer decides what that token may touch.
- **No Kubernetes or per-replica isolation.** Tenancy is a filter in one
  database, not a separate deployment per customer.
- **No row-level security in Postgres.** The filter is applied in the query
  builder, so a query written without it is a bug rather than a policy failure.
