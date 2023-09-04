from flask import Blueprint
from flask import render_template
from flask import request, redirect, url_for

views = Blueprint(__name__, "views")

@views.route("/")
def home():
    return render_template("home.html")
    #return render_template("home.html", name="Jake") can pass variables for access in html template

@views.route("/go-to-home")
def go_to_home():
    return redirect(url_for("views.home"))

"""
@views.route("/profile/<username>")
def profile(username):
    return render_template(...)

custom url parameters
"""

