Several findings have already been reproduced against the running application.
Your job is to say whether any of them can be wired into a chain: one step's
output becoming the next step's input, so the attacker finishes somewhere none
of the findings reaches alone.

You are given only reproduced findings. Each carries its working PoC request,
its predicate, and the response the harness actually observed when the PoC
reproduced. Read that observed response: the field names you extract must be
fields it really contains.

Model the attack as states. A state is `kind:resource`, where `kind` is one of:

- none — no access at all
- user_creds — holds a low-privilege identity
- admin_creds — holds an administrative identity
- session_token — holds someone else's live session token
- db_read / db_write — can read or write rows they should not
- file_read / file_write — can read or write files on the server
- secret — holds a key, token or password taken from the application
- code_exec — can run code in the application's context
- ssrf_reach — can make the server issue requests of the attacker's choosing

A chain is valid only when:
- it has at least 2 and at most 6 steps, each one a different finding;
- the first step's `state_before` is `none:*`;
- each step's `state_after` equals the next step's `state_before`;
- every `{{VALUE}}` a step's request needs was extracted by an earlier step;
- the chain reaches a state worth reaching: code execution, administrative
  identity, arbitrary rows, or a secret that unlocks one of those.

To move data between steps, each step may declare `extract`, a map from an
upper-case name to a selector. The next steps write that name as `{{NAME}}`.
Selectors:

- {"from": "json", "path": "user.token"} — dotted path into the parsed body;
  `[*]` walks an array and `[0]` picks an index
- {"from": "json", "path": "rows[*].value", "pick": "first_starts_with", "starts_with": "sk-"}
  — choose among the matches; other picks are first, last, longest,
  first_contains (with `contains`), first_matching (with `pattern`)
- {"from": "json_text", "path": "body", "field": "AccessKeyId"} — for a body
  that is itself a JSON string
- {"from": "header", "name": "x-session"}
- {"from": "body"}, {"from": "status"}
- {"from": "base64", "value": "{{SOMETHING}}"}
- {"from": "jwt_hs256", "secret": "{{SIGNING_KEY}}", "claims": {"sub": 1, "role": "admin"}}
  — sign a token with a key an earlier step stole; use this when the finding
  you are chaining through is about a weak or leaked signing key

Return JSON:
{
  "chains": [
    {
      "title": "one line naming the impact",
      "rationale": "why each step follows from the last, citing the observed responses",
      "steps": [
        {
          "finding_id": "<id from the input>",
          "state_before": "none:*",
          "state_after": "user_creds:alice",
          "description": "what this step does",
          "expect_expr": "optional stronger predicate; defaults to the finding's own",
          "extract": {"AUTH_TOKEN": {"from": "json", "path": "token"}},
          "setup": null,
          "followup": null
        }
      ]
    }
  ]
}

Return an empty `chains` list when no two findings connect. A chain that is
proposed but does not replay is evidence the scan did not do its job; an honest
empty list is respected.
