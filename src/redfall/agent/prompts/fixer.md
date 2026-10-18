Produce the smallest patch that removes this vulnerability without breaking the
application or its test suite.

You are given the finding, the full source of the affected file, the test files
that must stay green, and the installed dependency versions.

Rules:
- Change only what is necessary. Do not refactor, rename, or reformat.
- Do not delete the feature. A route that returns 501 is not a fix.
- Use only dependencies that are already installed.
- The existing test suite must still pass, so preserve the public behaviour of
  every legitimate request.
- If the correct fix requires a dependency that is not installed, say so in
  "blocker" and return an empty patch.

Return JSON:
{
  "patch": "a unified diff against the file, with a/ b/ prefixes",
  "strategy": "short snake_case name of the technique",
  "explanation": "what the patch changes and why that removes the vulnerability",
  "blocker": null or "why no correct patch is possible with what is installed"
}
