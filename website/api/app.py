"""
Friday Night Poker - origin API.

This is deliberately a permissive test origin: every route accepts every HTTP
method and returns 200 with an echo of the request. It performs NO filtering,
so a GoTestWAF scan measures the WAF sitting in front of it, not this server.
Do not add validation/blocking here.
"""
from flask import Flask, request, jsonify

app = Flask(__name__)

ALL_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]


def echo(resource):
    """Return a 200 JSON echo of the incoming request."""
    # Parse a body if one was sent, in whatever form it arrived.
    body = request.get_json(silent=True)
    if body is None:
        body = request.form.to_dict() or (request.get_data(as_text=True) or None)

    return jsonify({
        "resource": resource,
        "method": request.method,
        "path": request.path,
        "query": request.args.to_dict(flat=False),
        "body": body,
        "content_type": request.headers.get("Content-Type"),
        "user_agent": request.headers.get("User-Agent"),
    }), 200


# ---- Realistic poker REST endpoints (all accept every method) -----------
@app.route("/api/players", methods=ALL_METHODS)
def players():
    return echo("players")


@app.route("/api/tables", methods=ALL_METHODS)
def tables():
    return echo("tables")


@app.route("/api/games", methods=ALL_METHODS)
def games():
    return echo("games")


@app.route("/api/login", methods=ALL_METHODS)
def login():
    return echo("login")


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


# ---- Catch-all: any /api/* path, any method -> 200 echo -----------------
@app.route("/api/<path:subpath>", methods=ALL_METHODS)
def catch_all(subpath):
    return echo(subpath)


if __name__ == "__main__":
    # Dev only; in the container gunicorn serves the app (see Dockerfile).
    app.run(host="0.0.0.0", port=5000)
