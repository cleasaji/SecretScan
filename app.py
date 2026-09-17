from flask import Flask, render_template, request, jsonify
from scanner.detector import scan_text

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    filename = data.get("filename", "input.txt")

    if not isinstance(text, str) or not text.strip():
        return jsonify({"error": "Please enter some text to scan."}), 400

    findings = scan_text(text, filename)
    return jsonify({
        "filename": filename,
        "findings": findings,
        "count": len(findings)
    })

if __name__ == "__main__":
    app.run(debug=True)
