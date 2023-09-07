import json
from flask import Blueprint
from flask import render_template
from flask import request, redirect, url_for
import os
import base64
import hashlib
import re
import urllib.parse
import requests
from dotenv import load_dotenv

views = Blueprint(__name__, "views")

load_dotenv()
cid = os.getenv("CLIENT_ID")
cs = os.getenv("CLIENT_SECRET")
redirect_uri = "http://localhost:8000/callback"
access_token = ""

verifier = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8')
verifier = re.sub('[^a-zA-Z0-9]+', '', verifier)

challenge = hashlib.sha256(verifier.encode('utf-8')).digest()
challenge = base64.urlsafe_b64encode(challenge).decode('utf-8')
challenge = challenge.replace('=', '')

@views.route("/")
def home():
    return render_template("home.html")
    #return render_template("home.html", name="Jake") can pass variables for access in html template

@views.route("/login")
def login():
    scope = 'user-read-private user-read-email'
    state = "generaterandstring1"
    params={
        "response_type":"code",
        "client_id": cid,
        "scope" : scope,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge_method": 'S256',
        "code_challenge": challenge
    }
    url = 'https://accounts.spotify.com/authorize?' + urllib.parse.urlencode(params)
    return redirect(url, code=302)

@views.route("/callback")
def callback():
    code = request.args['code']
    head ={
        "Content-Type":"application/x-www-form-urlencoded"
    }
    body={
        "grant_type": "authorization_code",
        "code": str(code),
        "redirect_uri": redirect_uri,
        "client_id": cid,
        "code_verifier": verifier
    }
    req = requests.post('https://accounts.spotify.com/api/token', data=body, headers=head)
    resp = json.loads(req.text)
    global access_token
    access_token = resp["access_token"]
    return redirect(url_for("views.home"))

@views.route("/go-to-home")
def go_to_home():
    return redirect(url_for("views.home"))

"""
@views.route("/profile/<username>")
def profile(username):
    return render_template(...)

custom url parameters
"""

