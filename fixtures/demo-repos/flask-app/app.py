"""Demo fixture: a small Flask API. Intentionally contains patterns that
static analysis should flag. It is never executed by UnboxAnyRepo."""
import os

import psycopg2
from flask import Flask, jsonify, request

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev")


def db():
    return psycopg2.connect(os.environ["DATABASE_URL"])


@app.get("/items")
def items():
    name = request.args.get("name", "")
    cur = db().cursor()
    cur.execute(f"SELECT id, name FROM items WHERE name = '{name}'")
    return jsonify(cur.fetchall())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=True)
