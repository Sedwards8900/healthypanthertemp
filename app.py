import os
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    # logout_user,
    # login_required,
    # current_user,
)

# App initiation via Flask
app = Flask(__name__)

uri = os.getenv("DATABASE_URL")
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
# Point SQLAlchemy to Heroku database
app.config["SQLALCHEMY_DATABASE_URI"] = uri
# Gets rid of warning
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# Initiate database for app
db = SQLAlchemy(app)
db.init_app(app)


# Database model definition containing User credentials/ids
class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), unique=True, nullable=False)

    def __repr__(self):
        return "<User %r>" % self.username


# Index page route
@app.route("/")
def index():
    return render_template("index.html")


# Route for User Registration redirect from main
@app.route("/registration", methods=["GET"])
def signup():
    return render_template("registration.html")


# Route for User Login redirect from main
@app.route("/login", methods=["GET"])
def login():
    return render_template("login.html")


# Route for the creation of new account
@app.route("/register", methods=["POST"])
def new_account():
    # If method is post and user plans to sign up
    if request.method == "POST":
        input_username = request.form.get("username")
        input_password = request.form.get("password")
        # If username is found on database, prompt user to provide a new username
        if Users.query.filter_by(username=input_username).first():
            flash("Username is already taken")
            return render_template("registration.html")

        # If name available, create new user and hash the password so the plaintext version isn't saved
        new_user = Users(
            username=input_username,
            password=generate_password_hash(input_password, method="sha256"),
        )
        db.session.add(new_user)
        db.session.commit()
        flash("Your account has been created. Please login!")
        return redirect(url_for("login"))


# Route to Login
@app.route("/account", methods=["POST"])
def account():
    if request.method == "POST":
        # The user data is stored for comparison
        input_username = request.form["username"]
        input_password = request.form["password"]
        # Pull database data for comparison
        user_account = Users.query.filter_by(username=input_username).first()
        # If the below passess, allow user into their profile
        if user_account and check_password_hash(user_account.password, input_password):
            # Set up browser ability to remember user data
            remember_me = True if request.form.get("remember") else False
            login_user(user_account, remember=remember_me)
            # Redirect user to profile page
            return redirect(url_for("profile"))

        # If user provides wrong information for login, redirect back to login page again
        flash("The username or password provided don't match. Please try again.")
        return redirect(url_for("login"))


@app.route("/authorize", method=["GET"])
def authorize():
    # INPUT CODE HERE
    return redirect(url_for("authpage"))


# # Route to logout
# @app.route("/logout", methods=["GET"])
# @login_required
# def logout():
#     logout_user()
#     return redirect(url_for("index"))


# Run the app
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", 8080)),
        use_reloader=True,
        debug=False,
    )
