from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from . import db
from .models import User

auth = Blueprint("auth", __name__)


@auth.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash("Logged in successfully!", category="success")
                login_user(user, remember=True)
                return redirect(url_for("views.home"))
            else:
                flash("Incorrect password, try again.", category="error")
        else:
            flash("Email does not exist.", category="error")

    return render_template("login.html", user=current_user)


@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))


@auth.route("/sign-up", methods=["GET", "POST"])
def sign_up():
    if request.method == "POST":
        email = request.form.get("email")
        firstName = request.form.get("firstName")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")

        user = User.query.filter_by(email=email).first()

        if user:
            flash("Email already exists", category="error")
        elif len(email) < 4:
            flash("Email must be greater than 3 characters", category="error")
        elif len(firstName) < 2:
            flash("firstName must be greater than 1 characters", category="error")
        elif password1 != password2:
            flash("Password don't match", category="error")
        elif len(password1) < 7:
            flash("Password must be greater than 6 characters", category="error")
        else:
            new_user = User(
                email=email,
                first_name=firstName,
                password=generate_password_hash(password1, method="sha256"),
            )

            db.session.add(new_user)
            db.session.commit()

            login_user(user, remember=True)

            flash("Account Created", category="success")
            return redirect(url_for("views.home"))

    return render_template("sign_up.html")
