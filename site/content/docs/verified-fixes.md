---
title: Verified fixes: how RedFall proves a repair
seoTitle: "Verified Fixes: Patch, Test and Replay the PoC"
description: "A RedFall fix is verified only when the target's own tests pass and the original proof of concept stops reproducing. Three attempts, then a human with the transcript."
path: docs/verified-fixes/
group: How it works
kind: cluster
pillar: architecture
order: 6
updated: 2026-10-21
keywords: verified vulnerability fix, automated patch verification, security fix testing
sources: https://github.com/DevAnimecx/redfall, https://github.com/DevAnimecx/redfall/blob/main/BLOCKED.md
related: verified-findings, output, release-verification
---

**A fix is verified only when two independent checks pass: the target's own test suite still passes, and the original proof of concept no longer produces the effect.** Either check alone is insufficient. A patch that breaks the app is not a fix, and a patch that leaves the exploit working is not a fix.

The fix loop is the second half of RedFall's claim. The scanner proves a finding by executing it; the fixer proves a repair by re-executing both the finding and the target's tests.

## What does the fix loop do?

The loop runs against one finding and one target:

1. Read the finding, its location, its evidence and the target state.
2. Generate a candidate patch on a branch.
3. Apply the patch to a scratch checkout.
4. Run the target's own test suite.
5. Replay the original PoC against the patched build.
6. Mark the fix verified only if the tests pass and the PoC stops reproducing.
7. If not verified, feed the real failure text into the next attempt.

The loop makes at most three attempts. After three failures, the finding goes to a human with the full transcript: the patch, the test output and the PoC result. It does not keep trying indefinitely, and it does not mark a failed attempt as a partial success.

## Why require both tests and the PoC?

Because each check answers a different question.

| Check | What it catches | What it misses |
| --- | --- | --- |
| Target test suite | A patch that breaks existing behaviour | A patch that leaves the vulnerability intact |
| Original PoC | A patch that does not stop the exploit | A patch that breaks the app in a way the tests do not cover |

A patch that deletes the route might stop the PoC and still fail the tests. A patch that adds a guard the tests do not exercise might pass the suite and still be bypassable. Requiring both narrows the space of false fixes.

The PoC is the same request and predicate that produced the finding. It is not regenerated from the patch, and it is not weakened to make the fix look successful.

## What does a fix record contain?

`redfall fix <finding-id> --target <dir> --out fixes.json` appends one record per finding. The record carries:

- `finding_id`
- `verified`
- `status`
- the test outcome
- the PoC outcome

Re-running the command for the same finding replaces that record instead of duplicating it. The range runner reads the file and scores the fix. The [CLI reference](/docs/cli/) lists the exact command.

The [SARIF export](/docs/output/) is separate: it reports the scan findings, not the fix records. A fix record is evidence about a repair, and it stays with the target's fix history.

## What was measured?

The range targets carry their own patch verification. `range/vulnbank` reports **32/32 patches verified** through its `verify_patches.sh` script, and its test suite reports 76 passed. The range's ground truth includes the patch for each seeded vulnerability, so the verification is against the target's real tests, not a synthetic checker.

That number is about the range's patch set. It is not a claim that the agent-driven fix loop ran on this host. The fix loop needs a live model call to generate patches, and the development host has no provider key. The [blocked page](/docs/blocked/) records the missing credential and the smallest real unblock.

The distinction matters: the patch verification path was exercised, and the model-driven generation path is written but blocked. Both facts belong in the evidence table.

## Why three attempts?

Three is enough to handle a bad first patch and a correctable second one without turning a failed fix into an unbounded loop. The important part is not the number; it is that each attempt receives the real failure text rather than a generic "try again."

After the third failure, the human gets the transcript. A reviewer can see what was tried, what the tests said and what the PoC did. That is more useful than a confident "fix failed" message.

## What does a verified fix not prove?

A verified fix proves that this patch, on this build, passed the target's tests and stopped the original PoC. It does not prove:

- That no variant of the vulnerability remains.
- That the patch is stylistically or architecturally the best repair.
- That the target's test suite is complete.
- That the fix will apply cleanly to a different branch.

The loop is evidence, not a guarantee. The [evidence page](/evidence/) separates the measured patch counts from the unmeasured agent path.

## How do you review a fix?

Start with the finding and the PoC. Then read the patch, the test output and the PoC result together. Ask three questions:

1. Does the patch address the sink or the source, not just the specific payload?
2. Do the tests exercise the changed behaviour?
3. Does the original PoC fail for the right reason, not because the route was removed or the target stopped booting?

A verified flag is a summary of two checks. The transcript is the evidence.

## Frequently asked questions

### Can RedFall fix a finding without a model provider key?

The patch generation path requires a live model call. It fails rather than returning a canned patch. The range's own patch verification can run independently, but that is not the agent fix loop.

### Does a verified fix mean the vulnerability class is eliminated?

No. It means the original PoC no longer works and the target's tests pass. A variant may still exist.

### Where do fix records go?

`--out fixes.json` appends or replaces the record for that finding. The range runner reads it for scoring. See the [CLI reference](/docs/cli/).
