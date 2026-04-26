# Malicious Pattern Detector

This project detects malicious or suspicious patterns in:

- File names
- Domain names
- Email addresses
- Usernames
- Mobile numbers
- Command or script payload strings

## Features

- C core logic for fast detection
- Flask backend
- Interactive web GUI with animations
- Rule-based scoring
- PDA-inspired payload analysis using stack-based delimiter validation

## Tech Stack

- C (core logic)
- Python Flask (backend)
- HTML/CSS/JS (frontend)
- Bootstrap (UI framework)

## Run Locally

1. Compile C program:
	```bash
	cd malicious-detector
	gcc detector.c -o detector
	```

2. Install dependencies and requirements
	```bash
	pip install -r requirements.txt
	```

3. Run Flask app
	```bash
	python app.py
	```

4. Open browser at given url
	```
	http://127.0.0.1:5000
	```

## New Payload Detector (PDA-Inspired & TM-De-obfuscator)

Use input type `payload` to inspect suspicious command/script strings.

Detailed implementation notes are in:
- `PAYLOAD_PDA_EXPLAIN.md` (Stack-based token mapping)
- `PAYLOAD_TM_EXPLAIN.md` (Tape-based Turing Machine de-obfuscation)

The detector applies pushdown-automaton style checks using a stack:
- Delimiter balancing for `()`, `{}`, `[]` and quote boundaries
- Deep nesting and chained operators (for obfuscation patterns)
- Suspicious execution token clusters (for example `powershell`, `curl`, `base64`, `eval(`)

It also uses a real-time Turing Machine tape rewriter to de-obfuscate inline evasion techniques:
- Command inline escape characters (`^`, `` ` ``)
- String concatenation (`'x'+'y'`)

Example payloads to test:
- `powershell -enc SGVsbG8= ; curl http://10.0.0.1`
- `<script>eval(atob("YWxlcnQoMSk="))</script>`
