## What changed

<!-- One paragraph. If this touches the analyser, say which language(s) and which stage. -->

## How it was proved

<!-- Paste or summarize the commands you ran and what they printed. -->

- [ ] `make check` (the four checkers + full test suite) passes locally
- [ ] New/updated tests cover the change, and they were run — not just written
- [ ] For analyser changes: a positive fixture **and** a lookalike that must not match
- [ ] For anything that could not run on my host: it is listed in `BLOCKED.md` with the exact unblock, and nothing was faked in its place

## Honesty checklist

- [ ] No numbers in docs/README/BLOCKED were changed without re-measuring them
- [ ] No dry-run, fallback or fabricated default was added (the no-mock checker agrees)
- [ ] No generated manifest was hand-edited
- [ ] Commits are small and scoped; nothing was split or padded to inflate the count
