from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash
import smtplib
from email.message import EmailMessage

from helpers import login_required


# Configure application
app = Flask(__name__)


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///rusia2018vip.db")



@app.route("/")
@login_required
def index():

    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return render_template("apology.html", code=403, message="must provide username")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return render_template("apology.html", code=403, message="must provide password")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE user_username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["user_hash"], request.form.get("password")):
            return render_template("apology.html", code=403, message="invalid username and/or password")

        # Remember which user has logged in
        session["user_id"] = rows[0]["user_id"]
        session["user-username"] = rows[0]["user_username"]

        # Redirect user to home page
        #return redirect("/")
        return render_template("index.html")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return render_template("apology.html", code=400, message="missing username")

        if not request.form.get("name"):
            return render_template("apology.html", code=400, message="missing name")

        if not request.form.get("lastname"):
            return render_template("apology.html", code=400, message="missing lastname")

        # Ensure email was submitted
        if not request.form.get("email"):
            return render_template("apology.html", code=400, message="missing email")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return render_template("apology.html", code=400, message="missing password")

        # Ensure password confirmation was submitted
        elif not request.form.get("confirmation"):
            return render_template("apology.html", code=400, message="missing confirmation")

        # Ensure password match password confirmation
        elif request.form.get("confirmation") != request.form.get("password"):
            return render_template("apology.html", code=400, message="password don't match")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE user_name = :username OR user_email = :useremail",
                          username=request.form.get("username"), useremail=request.form.get("email"))

        if len(rows) == 1:
            return render_template("apology.html", code=400, message="username/email taken")

        db.execute("INSERT INTO users (user_username, user_name, user_lastname, user_email, user_hash) VALUES (:username, :name, :lastname, :email, :hash)", username=request.form.get("username"),
                   name=request.form.get("name"), lastname=request.form.get("lastname"), email=request.form.get("email"), hash=generate_password_hash(request.form.get("password")))

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE user_username = :username",
                          username=request.form.get("username"))

        # Remember which user has logged in
        session["user_id"] = rows[0]["user_id"]

        # Redirect user to home page
        return redirect("/")

    return render_template("register.html")


@app.route("/comofunciona", methods=["GET", "POST"])
def comofunciona():
    """Instrucciones"""

    return render_template("comofunciona.html")