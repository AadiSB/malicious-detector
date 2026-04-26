# Tape-Based Payload De-obfuscator (Turing Machine Implementation)

## 1. Theoretical Concept
In addressing advanced payload obfuscation, standard Regular Expressions (DFA) or Stack Checkers (PDA) are insufficient. They cannot process input by moving back and forth to dynamically alter the read string based on contextual clues.

To solve this, we implemented a **Turing Machine (TM)** architecture natively in C.
* **The Tape:** A character array (`char *tape`) representing the malicious payload string.
* **The Read/Write Head:** An integer index pointer (`int head`) that traverses the tape.
* **State Transitions:** While-loop conditions that read characters, execute tape mutations (shifting memory, erasing, and replacing characters), and move the head left (`head--`) or right (`head++`).

## 2. The 7 Obfuscation Rewriting Rules
The TM has 7 strict rules embedded in its state logic. If the head encounters one of these, it alters the tape and manages the head position to re-scan for recursively formed patterns.

1. **Rule 1: Caret Erasure (`^`)** - Erases `^` (e.g., `c^m^d`) by shifting left by 1. Head stays in place (`continue`) to read the newly shifted character.
2. **Rule 2: Backtick Erasure (`` ` ``)** - Erases `` ` `` (e.g., `p`o`w`) by shifting left by 1. Head stays in place.
3. **Rule 3: Single-Quote Concat (`'+'`)** - Collapses `'pow'+'ershell'` into `'powershell'`. Shifts tape left by 3 bytes, moves head **left** by 1 (`head--`) to re-evaluate boundaries.
4. **Rule 4: Double-Quote Concat (`"+"`)** - Same as Rule 3, but for `"+"`.
5. **Rule 5: Empty Quote Blocks (`""` or `''`)** - Attackers inject `""` mid-string (`c""md`). TM erases both quotes, shifts tape left by 2 bytes, moves head **left** by 1.
6. **Rule 6: Hex Escapes (`\x63`)** - Converts ASCII hex into characters. Decodes `63` into `c`, writes it under the head, shifts the rest of the tape left by 3, moves head **left** by 1.
7. **Rule 7: URL Encoding (`%63`)** - Decodes HTTP percent encoding identically to Rule 6, shifting left by 2, moving head **left** by 1.

## 3. Exact Dry Run
Let's perform a manual trace on a multi-technique obfuscated payload exactly as the C code executes it.

**Input Payload:** `p^o""w\x65r` (Intended command: `power`)

**Initial Tape State:** `[ 'p', '^', 'o', '"', '"', 'w', '\', 'x', '6', '5', 'r', '\0' ]`

| Step | Head (`H`) | Read (`tape[H]`) | Rule Triggered | TM Action & Tape Mutation | Next Head Movement | Tape State Generated |
|---|---|---|---|---|---|---|
| 1 | `H=0` | `p` | None | None | `head++` | `p^o""w\x65r` |
| 2 | `H=1` | `^` | **Rule 1 (Caret)** | `memmove` shifts tape left 1 | `continue` (Hold) | `po""w\x65r` |
| 3 | `H=1` | `o` | None | None | `head++` | `po""w\x65r` |
| 4 | `H=2` | `"` | **Rule 5 (Empty "")** | `memmove` shifts tape left 2 | `head--` & `continue` | `pow\x65r` |
| 5 | `H=1` | `o` | None | None | `head++` | `pow\x65r` |
| 6 | `H=2` | `w` | None | None | `head++` | `pow\x65r` |
| 7 | `H=3` | `\` | **Rule 6 (Hex \x65)** | Decodes `65`->`e`, overwrites `\`, shifts left 3 | `head--` & `continue` | `power` |
| 8 | `H=2` | `w` | None | None | `head++` | `power` |
| 9 | `H=3` | `e` | None | None | `head++` | `power` |
| 10 | `H=4` | `r` | None | None | `head++` | `power` |
| 11 | `H=5` | `\0`| **End of Tape** | TM Halts | N/A | **`power`** |

*Notice how moving `head--` dynamically checks the newly shifted boundaries. If erasing `""` accidentally synthesized another obfuscation pattern at the seam, the TM head will immediately step back and process it!*

## 4. Pipeline Execution Order
It's crucial that this Turing Machine acts **after** the structural parsing, but **before** the signature matching.

1. **(PDA) Stack Checker:** Ensures operators like `(` `)` `{` `}` aren't misaligned (structural malware traits).
2. **(TM) Tape De-obfuscator (Here):** Scrubs, decodes, and rewrites the string dynamically back to its pure form.
3. **(DFA) Signature Matcher:** Safely reads clear strings like `power` to assign exact severity points without needing 10,000 regex permutations to account for every possible evasion structure.
