# flaglab

Audit feature flags across many repositories and emit **reviewable**
removal candidates.

## The gap this fills

Uber's [Piranha](https://www.infoq.com/presentations/piranha-refactoring)
removes flag-gated dead code using AST analysis plus partial program
evaluation. It is good at that part. But Piranha's input is "this flag is
stale," and by Uber's own account that input comes from a scheduled job
that queries the flag management system.

Nobody ships that job well, and the research explains why:

- A [CMU study of feature-flag practice](https://www.cs.cmu.edu/~ckaestne/pdf/icseseip20.pdf)
  found that removal of obsolete flags was *consistently identified as the
  key challenge*, and that "removing feature flags is still a mostly manual
  process, if done at all."
- [Harness](https://webflow.com/cdn.prod.website-files.com/6222ca42ea87e1bd1aa1d10c/6a0f0a84582d5b16400c3d5e_Evolving%20FME%20Whitepaper.pdf)
  reports that 80% of flag removals touch more than one file, so manual
  cleanup does not scale.
- [Datadog](https://docs.datadoghq.com/feature_flags/concepts/stale_flags.md)
  notes that surfacing a stale flag is only half the job: "removing a flag
  safely still means finding every reference to it in your codebase."

So the missing piece is not the refactoring engine. It is an honest
staleness verdict, computed the same way in CI and in review, across every
repository.

## What it does not do

It does not delete code. It produces candidates **with the evidence
attached**, because an automated refactor driven by an unverified verdict
is worse than no automation: it removes working paths and blames the flag.

## One policy, two consumers

The verdict comes from `flag_kit::FlagPolicy` — the same code
CivitForge's `GET /api/v1/admin/feature-flags/stale` uses. A disagreement
between CI and production review is impossible by construction rather than
prevented by convention.

Staleness signals, per [Datadog's model](https://docs.datadoghq.com/feature_flags/concepts/stale_flags.md)
and per-kind lifetimes from [stale-flag-detector](https://github.com/kromiii/stale-flag-detector):

| Signal | Meaning |
| --- | --- |
| `aged_past_deadline` | Older than the deadline for its kind (release 30d, experiment 40d, operational 90d) |
| `fully_rolled_out` | `percentage == 100` while the flag still exists — the gated branch is now unconditional dead code |
| `never_evaluated` | No recorded evaluation since creation |

`permission` kind flags are exempt: kill switches and authorization gates
are intentionally permanent.

Verdicts are `fresh`, `aging` (past half the deadline — review before it
becomes a candidate), `stale`, `permanent`.

## Install

```bash
cargo install --git https://github.com/WyattAu/flaglab
```

## Use

```bash
# Audit a CivitForge export
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/admin/feature-flags \
  | jq -c '.flags[] | {repo:"civitforge", name, kind, owner, enabled,
                        percentage, age_days: 0}' \
  | flaglab -i -

# Gate CI on cleanup debt (exit 2 when candidates exist)
flaglab -i flags.jsonl --json --fail-on-stale

# Find flags referenced in code but absent from the flag system
flaglab -s ./crates --scan ./apps
```

`--scan` walks a tree for flag call sites and merges the references into the
report. Code references prove a flag **exists**, never that it is finished,
so a code-only audit reports phantom flags but never a removal candidate.

## Estate dogfooding

This crate is the second consumer of the WyattAu kits, alongside
CivitForge. It uses:

| Kit | Use |
| --- | --- |
| `flag-kit` | `FlagPolicy`, `FlagKind`, `Staleness`, `StaleSignal` — the verdict |
| `serde`/`serde_json` | JSONL ingest and CI output |

Every kit bug found here is a bug that would have reached every other
consumer. That is the point of a second consumer.

## License

MIT OR Apache-2.0