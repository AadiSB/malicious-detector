from flask import Flask, render_template, request, jsonify
import subprocess

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/check", methods=["POST"])
def check():
    data = request.json
    input_value = data["input"]
    input_type = data["type"]

    result = subprocess.run(
        ["./detector", input_type, input_value],  # Use "detector.exe" on Windows
        capture_output=True,
        text=True
    )

    output = result.stdout.strip()
    score, status, rules = output.split("|")

    return jsonify({
        "score": int(score),
        "status": status,
        "rules": rules
    })

if __name__ == "__main__":
    app.run(debug=True)