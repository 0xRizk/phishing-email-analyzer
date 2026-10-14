"""
app.py - the web part of the Phishing Email Analyzer.

This file does three things and nothing else:
    1. Serves the web page (templates/index.html) when you open the site.
    2. Receives the email the user uploads or pastes.
    3. Passes it to analyzer.py and sends the results back to the page as JSON.

All the actual phishing detection lives in analyzer.py.

Run it with:   py app.py
Then open:     http://127.0.0.1:5000
"""

# Flask is the small web framework that turns Python functions into web pages.
#   Flask           - creates the web app
#   jsonify         - turns a Python dictionary into JSON the browser can read
#   render_template - loads an HTML file from the "templates" folder
#   request         - holds whatever the browser sent us (files, form fields)
from flask import Flask, jsonify, render_template, request

# Our own analyzer - the one function this web app needs from it.
from analyzer import analyze

# Create the web app. __name__ tells Flask where to find the "templates" folder.
app = Flask(__name__)

# Keep JSON keys in the order we wrote them, so headers show From, To, Subject...
# instead of being sorted alphabetically.
app.json.sort_keys = False

# Refuse uploads bigger than 10 MB. Without a limit, someone could send a
# huge file and tie up the server. (A small but real security control.)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024


# ---------------------------------------------------------------------------
# Route 1: the home page.
# "@app.route('/')" means: when someone visits the main address, run home().
# ---------------------------------------------------------------------------
@app.route("/")
def home():
    # Sends templates/index.html to the browser.
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Route 2: the analysis endpoint.
# The page's JavaScript sends the email here with a POST request when you
# click "Run Threat Analysis". Only POST is allowed, since we're receiving data.
# ---------------------------------------------------------------------------
@app.route("/analyze", methods=["POST"])
def analyze_route():
    # The page sends EITHER an uploaded file (field "file")
    # OR pasted text (field "raw"). Check which one we got.
    if "file" in request.files:
        # .read() gives the raw bytes of the uploaded .eml file.
        raw = request.files["file"].read()
    else:
        # Pasted text arrives as a string; the email parser wants bytes,
        # so encode it as UTF-8.
        raw = request.form.get("raw", "").encode("utf-8")

    # Nothing (or only spaces) was sent - tell the page with a 400 "bad request".
    if not raw.strip():
        return jsonify({"error": "No email received."}), 400

    try:
        # Hand the email to analyzer.py and send its results back as JSON.
        result = analyze(raw)
        return jsonify(result)
    except ValueError as e:
        # analyze() raises ValueError for input that isn't an email.
        return jsonify({"error": str(e)}), 400
    except Exception:
        # Anything unexpected: show a friendly message instead of crashing.
        # We don't send the technical details to the browser, since error
        # messages can leak information about the server.
        app.logger.exception("Analysis failed")
        return jsonify({"error": "Something went wrong reading that email."}), 500


# ---------------------------------------------------------------------------
# If an upload is over the 10 MB limit, Flask raises a 413 error.
# This turns it into a clear message for the page instead of an HTML error page.
# ---------------------------------------------------------------------------
@app.errorhandler(413)
def too_large(_error):
    return jsonify({"error": "That file is too large. The limit is 10 MB."}), 413


# This only runs when you start the file directly ("py app.py"),
# not when another file imports it.
if __name__ == "__main__":
    # debug=True reloads the server automatically when you save a file and
    # shows detailed errors in the terminal. Only for running on your own
    # computer - never turn debug on for a public website.
    app.run(debug=True)