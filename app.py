import os
import secrets
import smtplib
import sqlite3
import ssl
from datetime import timedelta
from email.message import EmailMessage
from email.utils import parseaddr

from flask import Flask, g, jsonify, redirect, render_template, request, send_from_directory, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from markupsafe import escape

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.environ.get("DATABASE_PATH", os.path.join(BASE_DIR, "pixel_pulse.db"))
SECRET_FILE = os.path.join(BASE_DIR, ".secret_key")

app = Flask(__name__, template_folder="templates", static_folder=None)

if os.environ.get("SECRET_KEY"):
    app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
else:
    if not os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, "w", encoding="utf-8") as key_file:
            key_file.write(secrets.token_hex(32))
    with open(SECRET_FILE, "r", encoding="utf-8") as key_file:
        app.config["SECRET_KEY"] = key_file.read().strip()

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "false").strip().lower()
    in {"1", "true", "yes"},
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT NOT NULL,
            game TEXT NOT NULL,
            console TEXT NOT NULL,
            rating INTEGER NOT NULL,
            review TEXT NOT NULL,
            cheats TEXT,
            difficulty TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS memories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT NOT NULL,
            game TEXT NOT NULL,
            console TEXT NOT NULL,
            year TEXT,
            story TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )
    db.commit()


@app.before_request
def before_request():
    init_db()


def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_hex(32)
        session["csrf_token"] = token
    return token


@app.context_processor
def template_helpers():
    return {
        "csrf_token": csrf_token,
        "current_user": session.get("username"),
    }


def validate_csrf():
    submitted = request.form.get("csrf_token", "")
    return secrets.compare_digest(submitted, session.get("csrf_token", ""))


@app.route("/")
def home():
    return redirect(url_for("index_page"))


@app.route("/index.html")
def index_page():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/feedback", methods=["POST"])
def send_feedback():
    if not validate_csrf():
        return redirect(url_for("index_page", feedback="session_error", _anchor="feedback"))

    name = request.form.get("name", "").strip()
    sender_email = request.form.get("email", "").strip()
    suggestions = request.form.get("suggestions", "").strip()
    if (
        not name
        or not sender_email
        or not suggestions
        or len(name) > 200
        or len(sender_email) > 320
        or len(suggestions) > 5000
        or parseaddr(sender_email)[1] != sender_email
        or "@" not in sender_email
    ):
        return redirect(url_for("index_page", feedback="invalid", _anchor="feedback"))

    smtp_username = os.environ.get("SMTP_USERNAME", "").strip()
    smtp_password = os.environ.get("SMTP_PASSWORD", "")
    if not smtp_username or not smtp_password:
        return redirect(url_for("index_page", feedback="setup", _anchor="feedback"))

    message = EmailMessage()
    message["Subject"] = "Pixel Pulse website feedback"
    message["From"] = os.environ.get("MAIL_FROM", smtp_username)
    message["To"] = "askingjoshua1994@gmail.com"
    message["Reply-To"] = sender_email
    message.set_content(
        f"Feedback from {name}\nEmail: {sender_email}\n\nSuggestions:\n{suggestions}\n"
    )

    try:
        smtp_port = int(os.environ.get("SMTP_PORT", "587"))
        with smtplib.SMTP(os.environ.get("SMTP_HOST", "smtp.gmail.com"), smtp_port, timeout=15) as server:
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
            server.login(smtp_username, smtp_password)
            server.send_message(message)
    except (OSError, smtplib.SMTPException, ValueError):
        app.logger.exception("Unable to send homepage feedback email")
        result = "failed"
    else:
        result = "sent"

    return redirect(url_for("index_page", feedback=result, _anchor="feedback"))


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        if not validate_csrf():
            error = "Invalid form session. Please try again."
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            if len(username) < 3:
                error = "Username must be at least 3 characters."
            elif len(password) < 8:
                error = "Password must be at least 8 characters."
            else:
                db = get_db()
                try:
                    db.execute(
                        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                        (username, generate_password_hash(password)),
                    )
                    db.commit()
                except sqlite3.IntegrityError:
                    error = "That username is already taken."
                else:
                    session.clear()
                    session.permanent = True
                    session["user_id"] = db.execute(
                        "SELECT id FROM users WHERE username = ?", (username,)
                    ).fetchone()["id"]
                    session["username"] = username
                    return redirect(url_for("index_page"))

    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if not validate_csrf():
            error = "Invalid form session. Please try again."
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = get_db().execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()

            if user is None or not check_password_hash(user["password_hash"], password):
                error = "Invalid username or password."
            else:
                session.clear()
                session.permanent = True
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                return redirect(url_for("index_page"))

    return render_template("login.html", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    if validate_csrf():
        session.clear()
    return redirect(url_for("index_page"))


@app.route("/api/session")
def api_session():
    return jsonify({
        "logged_in": bool(session.get("user_id")),
        "username": session.get("username"),
        "csrf_token": csrf_token(),
    })


@app.route("/CSS/<path:filename>")
def css_file(filename):
    return send_from_directory(os.path.join(BASE_DIR, "CSS"), filename)


@app.route("/Images/<path:filename>")
def image_file(filename):
    return send_from_directory(os.path.join(BASE_DIR, "Images"), filename)


@app.route("/<page>.html")
def html_page(page):
    return send_from_directory(BASE_DIR, f"{page}.html")


@app.route("/BitsandBytes.html", methods=["GET", "POST"])
def bits_and_bytes():
    error = None
    submitted = False

    if request.method == "POST":
        if not validate_csrf():
            error = "Invalid form session. Please try again."
        else:
            name = request.form.get("name", "").strip()
            game = request.form.get("game", "").strip()
            console = request.form.get("console", "").strip()
            rating_text = request.form.get("rating", "").strip()
            review = request.form.get("review", "").strip()
            cheats = request.form.get("cheats", "").strip()
            difficulty = request.form.get("difficulty", "").strip()

            try:
                rating = int(rating_text)
            except ValueError:
                rating = 0

            if not name or not game or not review:
                error = "Please enter your name, game name, and review."
            elif console in ("", "Pick One"):
                error = "Please select a console."
            elif not 1 <= rating <= 10:
                error = "Rating must be from 1 to 10."
            else:
                get_db().execute(
                    """
                    INSERT INTO reviews
                        (user_id, name, game, console, rating, review, cheats, difficulty)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        session.get("user_id"),
                        name,
                        game,
                        console,
                        rating,
                        review,
                        cheats,
                        difficulty,
                    ),
                )
                get_db().commit()
                submitted = True

    reviews = get_db().execute(
        "SELECT * FROM reviews ORDER BY created_at DESC, id DESC"
    ).fetchall()

    template_path = os.path.join(BASE_DIR, "BitsandBytes.html")
    with open(template_path, "r", encoding="utf-8") as template_file:
        template_text = template_file.read()

    review_html = ""
    if not reviews:
        review_html = '<p class="no-reviews">No reviews yet. Be the first to write one!</p>'
    else:
        cards = []
        for item in reviews:
            cards.append(
                '<article class="review-card">'
                f'<h3>{escape(item["game"])} — {item["rating"]}/10</h3>'
                f'<p><strong>{escape(item["console"])}</strong> | Difficulty: {escape(item["difficulty"] or "Not specified")}</p>'
                f'<p>{escape(item["review"])}</p>'
                f'<p><strong>Cheats:</strong> {escape(item["cheats"] or "None submitted")}</p>'
                f'<p class="review-by">Reviewed by {escape(item["name"])} </p>'
                '</article>'
            )
        review_html = "".join(cards)

    message = f'<p class="review-success">Review submitted successfully!</p>' if submitted else ""
    if error:
        message = f'<p class="review-error">{error}</p>'

    replacement = '<div class="form-box">'
    section = (
        replacement
        + '<h2>Community Reviews</h2>'
        + message
        + review_html
        + '<h2>Write a Game Review!</h2>'
    )
    template_text = template_text.replace(replacement, section, 1)

    template_text = template_text.replace(
        '<form>',
        '<form method="post">\n            <input type="hidden" name="csrf_token" value="' + csrf_token() + '">',
        1,
    )

    template_text = template_text.replace('<h2>Write a Game Review!</h2>', '<h2>Write a Game Review!</h2>', 1)

    return template_text, 200, {"Content-Type": "text/html; charset=utf-8"}


@app.route("/FlashBacks.html", methods=["GET", "POST"])
def flashbacks():
    error = None
    submitted = False

    if request.method == "POST":
        if not validate_csrf():
            error = "Invalid form session. Please try again."
        else:
            name = request.form.get("name", "").strip()
            game = request.form.get("game", "").strip()
            console = request.form.get("console", "").strip()
            year = request.form.get("year", "").strip()
            story = request.form.get("story", "").strip()

            if not name or not game or not story:
                error = "Please enter your name, game title, and memory."
            else:
                get_db().execute(
                    """
                    INSERT INTO memories
                        (user_id, name, game, console, year, story)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (session.get("user_id"), name, game, console, year, story),
                )
                get_db().commit()
                submitted = True

    memories = get_db().execute(
        "SELECT * FROM memories ORDER BY created_at DESC, id DESC"
    ).fetchall()

    template_path = os.path.join(BASE_DIR, "FlashBacks.html")
    with open(template_path, "r", encoding="utf-8") as template_file:
        template_text = template_file.read()

    memory_html = ""
    if not memories:
        memory_html = '<p class="no-memories">No memories yet. Share yours below!</p>'
    else:
        cards = []
        for item in memories:
            cards.append(
                '<article class="memory-card">'
                f'<h3>{escape(item["game"])} — {escape(item["console"])}'
                f'{escape(" (" + item["year"] + ")" if item["year"] else "")}</h3>'
                f'<p>{escape(item["story"])}</p>'
                f'<p class="memory-by">Shared by {escape(item["name"])}</p>'
                '</article>'
            )
        memory_html = "".join(cards)

    message = '<p class="review-success">Memory submitted successfully!</p>' if submitted else ""
    if error:
        message = f'<p class="review-error">{escape(error)}</p>'

    replacement = '<h2>Tell Me Your Memory!</h2>'
    section = (
        '<h2>Community Memories</h2>'
        + message
        + memory_html
        + replacement
    )
    template_text = template_text.replace(replacement, section, 1)

    template_text = template_text.replace(
        '<form>',
        '<form method="post">\n        <input type="hidden" name="csrf_token" value="' + csrf_token() + '">',
        1,
    )

    return template_text, 200, {"Content-Type": "text/html; charset=utf-8"}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False, use_reloader=False)
