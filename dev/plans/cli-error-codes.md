# Plan: CLI Error Codes

**Status:** implemented
**Date:** 2026-09-30
**Related:** [dev/ideas.md](../ideas.md) ("CLI Error Codes"), [cli.clj](../src/sbom_tool/adapter/ui/cli.clj), [errors.clj](../src/sbom_tool/adapter/ui/errors.clj)

Give CLI usage errors their own exit code instead of sharing status `1` with
`--fail-on-violations` policy violations.

## Problem

Today the tool only distinguishes two non-zero exit codes:

- `1` is used for two unrelated situations: a bad/missing CLI argument (or
  `--help` failing to print, though `--help` itself exits `0`) via the
  hardcoded status in [cli.clj:232](../src/sbom_tool/adapter/ui/cli.clj#L232),
  *and* `--fail-on-violations` finding a blacklisted license or
  policy-blocked vulnerability, via `dispatch`'s `{:exit-code 1}`
  ([cli.clj:195-196](../src/sbom_tool/adapter/ui/cli.clj#L195-L196)).
- `2` is `errors/runtime-error-exit-code`
  ([errors.clj:6-9](../src/sbom_tool/adapter/ui/errors.clj#L6-L9)), a
  runtime/data error (unreadable/malformed SBOM or policy file, failed
  report rendering).

This collision means a CI pipeline gating on "exit code `1` = policy
violation, fail the build" cannot tell that outcome apart from "you typo'd a
flag" -- both look identical on exit code alone, even though only one of
them means the SBOMs actually violate policy. [dev/ideas.md](../ideas.md)
calls this out directly: exit `1` should mean policy violations only, and
CLI usage errors should move to a code of their own (either reusing `2` or
a new `3`), kept distinct from runtime/data errors.

## Design

Reusing `2` for CLI usage errors would recreate the same ambiguity one level
over -- a caller could no longer tell "bad flag" apart from "SBOM file
missing" -- which is exactly what the idea note says to avoid ("to separate
them from program errors"). So this plan introduces a fourth, dedicated
code instead of overloading an existing one:

| Code | Meaning |
|------|---------|
| `0`  | Success (including `--help`) |
| `1`  | `--fail-on-violations` found a blacklisted license or a policy-blocked vulnerability, for usage in CI/CD |
| `2`  | A runtime/data error (unreadable/malformed SBOM/policy/VEX/API-key/SPDX-license-list file, or a report failed to render) |
| `3`  | A CLI usage error: bad or missing arguments |

### `sbom_tool.adapter.ui.cli/cli-usage-error-exit-code`

Add a new public constant next to `exit`, mirroring
`errors/runtime-error-exit-code`'s shape:

```clojure
(def cli-usage-error-exit-code
  "Process exit code for a CLI usage error (bad/missing arguments, or a
   failed --validate check) -- distinct from both a policy violation (1)
   and a runtime/data error (errors/runtime-error-exit-code, 2)."
  3)
```

It lives in `cli.clj`, not `errors.clj`: `errors.clj`'s docstring scopes it
to "exceptions raised while reading SBOMs/policies or rendering reports",
which a CLI argument-parsing failure is not -- `validate-args` never throws
or touches `errors/friendly-message`, it just inspects `clojure.tools.cli`'s
parse result.

### `-main`

[cli.clj:229-237](../src/sbom_tool/adapter/ui/cli.clj#L229-L237) currently
hardcodes the failure status:

```clojure
(if exit-message
  ; a CLI usage error, or --help: print and exit without running anything
  (exit (if success 0 1) exit-message)
  ...)
```

Change the `1` to `cli-usage-error-exit-code`:

```clojure
(exit (if success 0 cli-usage-error-exit-code) exit-message)
```

`--help` is unaffected (`success` is `true`, so it still exits `0`).

### `errors.clj`

Update `runtime-error-exit-code`'s docstring, which currently claims a CLI
usage error "exits with status 1":

```clojure
(def runtime-error-exit-code
  "Process exit code for a runtime/data error (as opposed to a CLI usage
   error, sbom-tool.adapter.ui.cli/cli-usage-error-exit-code, or a policy
   violation, both of which use different codes)."
  2)
```

### Testability

`-main` itself stays untested directly (it calls `System/exit`, same as
today), but the exit-code choice it makes is a one-line `if` with no other
logic, so no extra indirection is needed to cover it -- a new test can call
`validate-args` with a bad flag and a `--help` flag and assert on the
`:success`/`:exit-message` shape it returns, then separately assert
`cli/cli-usage-error-exit-code` equals `3` (mirroring
`errors_test.clj`'s existing `runtime-error-exit-code-test`). That matches
how `validate-args` is already exercised only indirectly today (there is no
existing `validate-args`-specific test), so this plan adds the first one
rather than restructuring `-main`.

### Documentation

- [README.md](../README.md) "Exit codes" table
  ([README.md:69-75](../README.md#L69-L75)): split the current `1` row into
  a `1` row (policy violations only) and a new `3` row (CLI usage errors),
  and reword the `--help` mention to note it exits `0`.
- `-f, --fail-on-violations` row's help text
  ([README.md:65](../README.md#L65)) already says "Exit with status 1" --
  no change needed there, it was already accurate.

## Touch points

| File | Change |
|---|---|
| [src/sbom_tool/adapter/ui/cli.clj](../src/sbom_tool/adapter/ui/cli.clj) | Add `cli-usage-error-exit-code` (3); use it in `-main` instead of the hardcoded `1` |
| [src/sbom_tool/adapter/ui/errors.clj](../src/sbom_tool/adapter/ui/errors.clj) | Update `runtime-error-exit-code`'s docstring to reflect the new CLI usage error code |
| [README.md](../README.md) | Update the "Exit codes" table: `1` = policy violations only, new `3` row for CLI usage errors |
| test/sbom_tool/adapter/ui/cli_test.clj | New test(s): `validate-args` with a bad/missing flag returns a non-success `:exit-message`; `cli/cli-usage-error-exit-code` equals `3` |
| test/sbom_tool/adapter/ui/errors_test.clj | No functional change; existing `runtime-error-exit-code-test` still passes (value unchanged) |

## Decisions

- **New code `3`, not reusing `2` for CLI usage errors.** The idea note
  offers both options, but reusing `2` would just move the ambiguity from
  "usage error vs. policy violation" to "usage error vs. runtime error" --
  a CI pipeline still couldn't distinguish "you passed a bad flag" from "an
  SBOM file was unreadable" on exit code alone. A fourth code keeps all
  three failure modes (policy violation, runtime/data error, usage error)
  independently distinguishable.
- **`cli-usage-error-exit-code` lives in `cli.clj`, not `errors.clj`.**
  `errors.clj` is specifically about formatting exceptions raised while
  reading SBOMs/policies or rendering reports (its docstring says so); CLI
  argument validation is a different, unrelated failure path (`validate-args`
  never raises or touches that multimethod), so its exit code belongs next
  to where it's used (`-main`/`exit`), not bundled into `errors.clj`'s
  concern.
- **No change to `--fail-on-violations`'s exit code (1) or its help text.**
  It already exits `1` today and its `--help` string already said "Exit
  with status 1"; this plan only removes the *other* thing that used to
  share that code.
