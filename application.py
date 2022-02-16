import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    shares = db.execute("SELECT * FROM shares WHERE user_id = ?", session["user_id"])
    user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
    cash = user[0]["cash"]
    total = 0
    # loop over shares to add more values (shares is a list of dicts)
    for share in shares:
        price = lookup(share["symbol"])["price"]
        share["price"] = price
        # share["shares"] = float(share["shares"])
        share["total"] = price * share["shares"]
        total += share["total"]

    return render_template("index.html", shares=shares, cash=cash, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        # Ensure correct symbol was submitted
        if not request.form.get("symbol"):
            return apology("must provide stock symbol", 400)
        elif lookup(request.form.get("symbol")) == None:
            return apology("invalid symbol", 400)
        if not request.form.get("shares"):
            return apology("must provide number of shares to buy", 400)
        shares = request.form.get("shares")
        if shares.isdecimal() == False:
            return apology("must provide an integer", 400)
        if int(shares) < 1:
            return apology("must provide a positive integer", 400)
        # Query database to chech how much money user currently logged in has
        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        user_cash = rows[0]["cash"]
        # Check current price
        stock = lookup(request.form.get("symbol"))
        symbol = stock["symbol"]
        name = stock["name"]
        price = stock["price"]
        cost = price * float(shares)
        transaction_type = "Purchase"
        # TEST:
        # return render_template("bought.html", cash=user_cash, price=price)

        # Ensure user has enough money to complete the purchase
        if user_cash < cost:
            return apology("not enough money to complete purchase", 400)
        # Add timestamp
        timestamp = datetime.now().strftime("%d %B %Y %H:%M:%S")
        db.execute("INSERT INTO transactions (user_id, symbol, name, shares, price, date, type) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   session["user_id"], symbol, name, shares, price, timestamp, transaction_type)
        cash_new = user_cash - cost
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash_new, session["user_id"])

        # Check if the user already owns that stock, if yes update table "shares", if not insert into it
        # This way I'm able to store information about how many shares of a given stock user owns
        # Later I can use this information in the index function

        user_account = db.execute("SELECT * FROM shares WHERE user_id = ? AND symbol = ?", session["user_id"], symbol)
        if len(user_account) == 1:
            # Add new shares to already owned
            owned = user_account[0]["shares"]
            amount = owned + int(shares)
            db.execute("UPDATE shares SET shares = ? WHERE user_id = ? AND symbol = ?", amount, session["user_id"], symbol)
        else:
            db.execute("INSERT INTO shares (user_id, symbol, name, shares) VALUES (?, ?, ?, ?)",
                       session["user_id"], symbol, name, shares)
        # Redirect user to home page
        flash('Purchase completed!')
        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = ?", session["user_id"])
    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        flash('You were successfully logged in')
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/login")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("must provide stock symbol", 400)
        elif lookup(request.form.get("symbol")) == None:
            return apology("invalid symbol", 400)
        # Quote using lookup
        quoted = lookup(request.form.get("symbol"))
        name = quoted["name"]
        price = usd(quoted["price"])
        return render_template("quoted.html", name=name, price=price)
        # return jsonify(name, price)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Check if username already exists
        if len(rows) == 1:
            return apology("username already exists", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure confirmation was submitted
        elif not request.form.get("confirmation"):
            return apology("must confirm your password", 400)

        # Ensure second password match the first
        elif not request.form.get("confirmation") == request.form.get("password"):
            return apology("password and confirmation must be the same", 400)

        # Insert user data into database
        username = request.form.get("username")
        password = request.form.get("password")
        hashed = generate_password_hash(password)
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hashed)

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    """User Account"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide current password", 400)

        # Ensure correct password was submitted
        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

        if not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid password", 400)

        # Ensure new password was submitted
        elif not request.form.get("password-new"):
            return apology("must provide new password", 400)

        # Ensure confirmation of new password was submitted
        elif not request.form.get("confirmation"):
            return apology("must confirm your new password", 400)

        # Ensure second password match the first
        elif not request.form.get("confirmation") == request.form.get("password-new"):
            return apology("password and confirmation must be the same", 400)

        # Ensure new password is not the same as the first one
        elif request.form.get("password-new") == request.form.get("password"):
            return apology("you must choose a different password!", 400)

        # Update user data
        password = request.form.get("password-new")
        hashed = generate_password_hash(password)
        db.execute("UPDATE users SET hash = ? WHERE id = ?", hashed, session["user_id"])

        # Redirect user to home page
        flash("Your password has been changed!")
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("account.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":

        # Make sure user provides correct data
        if not request.form.get("symbol") or request.form.get("symbol") == "Symbol":
            return apology("must provide stock symbol", 400)
        if not request.form.get("shares"):
            return apology("must provide number of shares to sell", 400)
        shares = int(request.form.get("shares"))
        if shares < 1:
            return apology("must provide a positive number", 400)

        # Check if user has enough shares to complete transaction
        symbol = request.form.get("symbol")
        user = db.execute("SELECT * FROM shares WHERE user_id = ? AND symbol = ?", session["user_id"], symbol)
        user_shares = user[0]["shares"]
        if shares > user_shares:
            return apology("not enough shares in your account", 400)

        # Transaction
        stock = lookup(request.form.get("symbol"))
        name = stock["name"]
        price = stock["price"]
        profit = price * float(shares)
        transaction_type = "Sell"
        timestamp = datetime.now().strftime("%d %B %Y %H:%M:%S")
        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        user_cash = rows[0]["cash"]
        db.execute("INSERT INTO transactions (user_id, symbol, name, shares, price, date, type) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   session["user_id"], symbol, name, shares, price, timestamp, transaction_type)
        cash_new = user_cash + profit
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash_new, session["user_id"])

        # Update shares table, if user sold all his shares delete stock from table
        amount = user_shares - shares
        if amount > 0:
            db.execute("UPDATE shares SET shares = ? WHERE user_id = ? AND symbol = ?", amount, session["user_id"], symbol)
        else:
            db.execute("DELETE FROM shares WHERE user_id = ? AND symbol = ?", session["user_id"], symbol)

        flash('Sold!')
        return redirect("/")
    else:

        # Get all stocks user currently owns
        symbols = db.execute("SELECT symbol FROM shares WHERE user_id = ?", session["user_id"])
        return render_template("sell.html", symbols=symbols)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
