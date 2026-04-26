from flask import Flask, render_template, request, jsonify
import subprocess

app = Flask(__name__)
SUPPORTED_TYPES = {"file", "domain", "email", "username", "mobile", "payload"}


def parse_detector_output(output):
    parts = output.strip().split("|", 2)
    if len(parts) != 3:
        return 0, "Invalid", "Malformed detector response"

    try:
        score = int(parts[0])
    except ValueError:
        score = 0

    score = max(0, min(score, 100))
    status = parts[1] if parts[1] else "Invalid"
    rules = parts[2] if parts[2] else "None"
    return score, status, rules

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/check", methods=["POST"])
def check():
    data = request.get_json(silent=True) or {}
    input_value = str(data.get("input", "")).strip()
    input_type = str(data.get("type", "")).strip().lower()

    if not input_value:
        return jsonify({"score": 0, "status": "Invalid", "rules": "Empty input"}), 400

    if input_type not in SUPPORTED_TYPES:
        return jsonify({"score": 0, "status": "Invalid", "rules": "Unsupported type"}), 400

    try:
        result = subprocess.run(
            ["./detector", input_type, input_value],  # Use "detector.exe" on Windows
            capture_output=True,
            text=True,
            timeout=5,
        )
    except subprocess.TimeoutExpired:
        return jsonify({"score": 0, "status": "Invalid", "rules": "Detector timed out"}), 504

    if not result.stdout:
        return jsonify({"score": 0, "status": "Invalid", "rules": "Detector execution failed"}), 500

    score, status, rules = parse_detector_output(result.stdout)

    return jsonify({
        "score": score,
        "status": status,
        "rules": rules
    })

if __name__ == "__main__":
    app.run(debug=True)