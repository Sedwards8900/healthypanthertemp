import os
from dotenv import load_dotenv
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

load_dotenv()
uri = os.getenv("DATABASE_URL")
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = uri
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# Initiate database for app
db = SQLAlchemy(app)
db.init_app(app)


# Temporary database table model containing User ids
class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    userid = db.Column(db.String(120), unique=True, nullable=False)


# # Comment out once created
# db.create_all()


# Index page
@app.route("/")
def index():
    return render_template("index.html")


# Redirect to user registration page
@app.route("/registration", methods=["GET"])
def signup():
    return render_template("registration.html")


# User Login redirect from main
@app.route("/login", methods=["GET"])
def login():
    return render_template("login.html")


# Registration
@app.route("/register", methods=["POST"])
def new_account():
    # If method is post and user plans to sign up
    if request.method == "POST":
        input_username = request.form.get("username")
        input_userid = request.form.get("userid")
        # If id is found on database, prompt user for new one
        if Users.query.filter_by(username=input_username).first():
            return render_template("registration.html")

        # If id available, create new user and hash the phone number
        new_user = Users(
            username=input_username,
            userid=generate_password_hash(input_userid, method="sha256"),
        )
        db.session.add(new_user)
        db.session.commit()
        return render_template("authpage.html")


# Login
@app.route("/account", methods=["POST"])
def account():
    if request.method == "POST":
        # The user data is stored for comparison
        input_username = request.form["username"]
        input_userid = request.form["userid"]

        user_account = Users.query.filter_by(username=input_username).first()
        # If the below passess, allow user into their profile
        if user_account and check_password_hash(user_account.userid, input_userid):
            print("It passed")
            # login_user(user_account)
            # Redirect user to profile page
            return redirect(url_for("profile"))

        # If user provides wrong information for login, redirect back to login page
        print("Why not working?")
        return redirect(url_for("login"))


# Profile and weekly health questionaire
@app.route("/profile", methods=["GET"])
def profile():
    return render_template("profile.html")


# @app.route("/authorize", method=["GET"])
# def authorize():
#     print("Still in process")
#     # INPUT CODE HERE
#     return redirect(url_for("authpage"))


# # Logout
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
        debug=True,
    )
