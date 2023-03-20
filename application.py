import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

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

    # Retrieve stocks and cash balance from database
    rows = db.execute("SELECT symbol, name, sum(shares) FROM transactions WHERE id=? GROUP BY symbol HAVING sum(shares) > 0", session["user_id"])
    cash = db.execute("SELECT cash FROM users WHERE id=?", session["user_id"])[0]["cash"]

    # Add current price of shares to 'rows' list and calculate total balance using cash balance plus current values of stocks
    total = float(cash)
    for x in rows:
        x["price"] = lookup(x["symbol"])["price"]
        total += x["price"] * x["sum(shares)"]

    # Return page with portfolio of stocks extracted from the database
    return render_template("index.html", rows=rows, cash=cash, total=total, usd=usd)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # When buying stock via POST
    if request.method == "POST":

        # Search for stock
        stock = lookup(request.form.get("stock_symbol"))

        # Check if stock exists, return apology if it does not
        if not stock:
            return apology("Could not find stock")

        # Check if enough cash is available and add the purchase to the database if it is
        cash = db.execute("SELECT cash FROM users WHERE id=?", session["user_id"])[0]["cash"]
        price = stock["price"]
        cost = price * float(request.form.get("number_of_shares"))

        if cost > cash:
            return apology("Not enough cash")
        else:
            db.execute("INSERT INTO transactions (id, symbol, name, shares, price) VALUES (?, ?, ?, ?, ?)",
                       session["user_id"], stock["symbol"], stock["name"], request.form.get("number_of_shares"), price)

        # Update total cash
        updated_cash = cash - cost
        db.execute("UPDATE users SET cash=? WHERE id=?", updated_cash, session["user_id"])

        # Redirect to index upon successful purchase
        if int(request.form.get("number_of_shares")) > 1:
            flash("Successfully purchased " + request.form.get("number_of_shares") + " shares of " + request.form.get("stock_symbol").upper())
        else:
            flash("Successfully purchased 1 share of " + request.form.get("stock_symbol").upper())
        return redirect("/")

    # When reaching route with GET
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Retrieve transaction history for the current user
    rows = db.execute("SELECT symbol, shares, price, datetime FROM transactions WHERE id=?",
                      session["user_id"])

    # Return history page with table of transaction history
    return render_template("history.html", rows=rows, usd=usd)


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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        flash("Successfully logged in")
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
    flash("Successfully logged out")
    return render_template("login.html")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # When submitting search with POST
    if request.method == "POST":

        # Search for stock
        stock = lookup(request.form.get("stock_quote"))

        # Check if stock symbol exists
        if stock:
            return render_template("quoted.html", name=stock["name"], price=usd(stock["price"]), symbol=stock["symbol"])
        else:
            return apology("Could not find stock")

    # When reaching route with GET
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # When submitting form with POST
    if request.method == "POST":

        # Check if username is entered
        if not request.form.get("username"):
            return apology("Please enter a username", 403)

        # Check if password and password confirmation match
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("Password did not match", 403)

        # Query database to check if username is already taken
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))
        if len(rows) == 1:
            return apology("Sorry, that username is already taken", 403)

        # After passing all the above checks, add name and password hash to database
        # First hash the password
        hashedpassword = generate_password_hash(request.form.get("password"))

        # Insert username and hashed password into database
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)",
                   username=request.form.get("username"), hash=hashedpassword)

        # Redirect to login page after successful registration
        flash("Registration successful!")
        return render_template("login.html")

    # When reaching the route via GET
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # When submitting via POST
    if request.method == "POST":

        # Check which shares are available to sell
        available = db.execute("SELECT id, symbol, name, sum(shares) FROM transactions WHERE symbol=:symbol AND id=:id GROUP BY symbol HAVING sum(shares) > 0",
                               symbol=request.form.get("stock"), id=session["user_id"])

        # If there are enough shares held, then get current price and sell the stock by updating the database
        if int(request.form.get("number_of_shares")) <= available[0]["sum(shares)"]:

            # Get current price of share
            price = lookup(request.form.get("stock"))["price"]

            # Insert the sell transaction into the transactions table
            db.execute("INSERT INTO transactions (id, symbol, name, shares, price) VALUES (:id, :symbol, :name, :shares, :price)",
                       id=session["user_id"], symbol=available[0]["symbol"], name=available[0]["name"], shares=-int(request.form.get("number_of_shares")), price=price)

            # Update cash balance
            updated_cash = db.execute("SELECT cash FROM users WHERE id=?", session["user_id"])[0]["cash"] + price * float(request.form.get("number_of_shares"))
            db.execute("UPDATE users SET cash=? WHERE id=?", updated_cash, session["user_id"])

            # Redirect back to index upon successful selling
            if int(request.form.get("number_of_shares")) > 1:
                flash("Successfully sold " + request.form.get("number_of_shares") + " shares of " + request.form.get("stock").upper())
            else:
                flash("Successfully sold 1 share of " + request.form.get("stock").upper())
            return redirect("/")

        # return apology if trying to sell more shares than available
        else:
            if int(available[0]["sum(shares)"]) > 1:
                return apology("You only hold " + str(available[0]["sum(shares)"]) + " shares of " + str(available[0]["symbol"]))
            else:
                return apology("You only hold 1 share of " + str(available[0]["symbol"]))

    # When reaching the route via GET
    else:

        # Get the available stocks from database for selection to sell
        rows = db.execute("SELECT symbol, name, sum(shares) FROM transactions WHERE id=? GROUP BY symbol HAVING sum(shares) > 0",
                          session["user_id"])

        return render_template("sell.html", rows=rows)


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    """Account settings"""

    # When submitting via POST
    if request.method == "POST":

        # When changing password
        if "old_password" in request.form:

            # Check if old password is correct by comparing hash
            if not check_password_hash(db.execute("SELECT hash FROM users WHERE id=?", session["user_id"])[0]["hash"], request.form.get("old_password")):
                return apology("Old password is incorrect")

            # Check if new password has been entered
            if not request.form.get("new_password"):
                return apology("Please enter a new password")

            # Check if new password and confirmation match
            if request.form.get("new_password") != request.form.get("confirm_new_password"):
                return apology("Password and confirmation did not match")

            # After passing above checks, replace old password hash with new password hash
            hashedpassword = generate_password_hash(request.form.get("new_password"))
            db.execute("UPDATE users SET hash=? WHERE id=?", hashedpassword, session["user_id"])

            # Flash successful message and return to settings page
            flash("Successfully changed password")
            return render_template("settings.html")

        # When adding cash
        elif "cash" in request.form:

            # Add entered amount of cash to total cash
            updated_cash = db.execute("SELECT cash FROM users WHERE id=?", session["user_id"])[0]["cash"] + float(request.form.get("cash"))
            db.execute("UPDATE users SET cash=?", updated_cash)

            # Flash successful message and return to settings page
            flash("Successfully added cash!")
            return render_template("settings.html")

    # When reaching route via GET
    return render_template("settings.html")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
