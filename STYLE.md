# EspreSSHo Style Guide

This guide applies to all code in this repository. Other AI assistants should read this
before making changes.

---

## Go (Barista)

Follow the [Go standard style guide](https://go.dev/doc/effective_go) with one deviation:
**prefer descriptive variable names over 1–2 character abbreviations**. `slotIndex`
beats `i`, `readerName` beats `r`, `digest` beats `d`.

### Formatting

- `gofmt` / `goimports` enforced. No exceptions.
- Line length: soft limit 100, hard limit 120.

### Naming

- Exported symbols have doc comments (`// FunctionName does X`).
- Unexported helpers do not need comments unless the logic is non-obvious.
- Acronyms follow Go convention: `APDU`, `PIN`, `SSH`, `DER` — all caps.
- Error variables: `ErrXxx` pattern, e.g. `ErrPINBlocked`.

### Errors

- Wrap with `fmt.Errorf("context: %w", err)` — never discard error context.
- Return errors up; only log at the boundary (main / command handlers).

### Package layout

```
card/       Pure card-interface layer. No CLI, no prompting, no SSH protocol.
sshagent/   SSH agent implementation. Wraps card/. PIN prompting lives here.
cmd/        Cobra commands. Thin glue only — parse flags, call card/ or sshagent/.
```

No package may import a package above it in this list. `card/` has no knowledge of
`sshagent/` or `cmd/`.

---

## Java (Mokapot / JavaCard)

Follow BSD Kernel Normal Form brace style adapted for Java:
- Opening braces on the same line for methods and classes.
- All constants `UPPER_SNAKE_CASE`.
- Local variables and parameters `lowerCamelCase`.
- Instance fields `lowerCamelCase`.

### JavaCard specifics

- Buffer manipulation uses `short` offsets/lengths — never `int`.
- No object allocation after `install()` completes (everything in constructor or static).
- Transient arrays (`JCSystem.makeTransientByteArray`) for scratch space that must
  not survive a deselect/power-cycle.
- All key-erasing operations wrapped in `JCSystem.beginTransaction()` /
  `JCSystem.commitTransaction()` for atomicity.
- APDU constants (INS bytes, flag masks, status words) live only in `APDUConstants.java`.
- P-256 curve parameters live only in `ECParams.java`.

### Comments

Non-trivial APDU logic should include a comment referencing the relevant section of the
CLAUDE.md spec (e.g. `// SIGN instruction — CLAUDE.md §SIGN Instruction Detail`).
