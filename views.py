import os
import base64
import hashlib
import re
import urllib.parse
import requests
import webbrowser
import json
from time import time
from flask import Blueprint
from flask import render_template
from flask import request, redirect, url_for, session
from dotenv import load_dotenv
from bs4 import BeautifulSoup

views = Blueprint(__name__, "views")

load_dotenv()
cid = os.getenv("CLIENT_ID")
cs = os.getenv("CLIENT_SECRET")
redirect_uri = "http://localhost:8000/callback"
#access_token = ""

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
    scope = 'user-top-read playlist-modify-public playlist-modify-private user-read-private user-read-email'
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
    #global access_token
    session['access_token'] = resp["access_token"]
    return redirect(url_for("views.settings"))

@views.route("/go-to-home")
def go_to_home():
    return redirect(url_for("views.home"))

@views.route("/open-spotify")
def open_spotify():
    webbrowser.open_new_tab('https://open.spotify.com/')
    return redirect(url_for())

def token_check():
    return 

@views.route("/settings")
def settings():
    ac = session.get('access_token')
    auth_header = {
        "Authorization": "Bearer {}".format(ac)
    }
    endpoint = "https://api.spotify.com/v1/me"
    resp = requests.get(endpoint, headers=auth_header)
    profile = json.loads(resp.text)
    session['user_id'] = profile['id']
    return render_template("settings.html")

@views.route("/just-top-tracks",methods=['POST', 'GET'])
def just_top_tracks():
    if request.method == "POST":
        session['playlist_name'] = request.form["title"]
        session['limit'] = request.form["slider"]
        session['time_range'] = request.form["time"]

    playlist_name = session.get('playlist_name', None)
    time_range = session.get('time_range', None)
    limit = int(session.get('limit', None))
    user_id = session.get('user_id', None)
    ac = session.get('access_token')
    desc = ""

    if(limit > 50):
        limit = 50
    if(time_range == "All Time"):
        time_range = "long_term"
        desc = "Your top {} tracks of all time".format(limit)
    elif(time_range == "This Month"):
        time_range = "short_term"
        desc = "Your top {} tracks this past month".format(limit)
    else:
        time_range = "medium_term"
        desc = "Your top {} tracks in the last 6 months".format(limit)
    
    auth_header = {
        "Authorization": "Bearer {}".format(ac)
    }
    params={
        "time_range": time_range,
        "limit": limit
    }
    endpoint = "https://api.spotify.com/v1/me/top/tracks?"
    resp = requests.get(endpoint, headers=auth_header, params=params)
    tracks = json.loads(resp.text)
    songs = []
    for i in range (limit):
        result = tracks['items'][i]
        songs.append(result['uri'])
        
    head = {
        "Authorization": "Bearer {}".format(ac),
        "Content-Type": "application/json"
    }
    params2 = json.dumps({
        "name" : playlist_name,
        "description" : desc,
        "public" : False
    })

    create_endpoint = "https://api.spotify.com/v1/users/{}/playlists".format(user_id)
    resp2 = requests.post(url=create_endpoint, data=params2, headers=head)
    playlist = json.loads(resp2.text)
    pid = playlist['id']
    session['playlist_url'] = playlist['external_urls']['spotify']
    print(pid)

    params3 = json.dumps({
        "uris" : songs,
        "position" : 0
    })
    add_endpoint = "https://api.spotify.com/v1/playlists/{}/tracks".format(pid)
    resp3 = requests.post(url=add_endpoint, data=params3, headers=head)
    print(resp3.status_code)

    return redirect(url_for("views.preview"))

@views.route("/customize", methods=['GET', 'POST'])
def customize():


@views.route("/preview",methods=['GET', 'POST'])
def preview():
    playlist_url = session.get("playlist_url",None)
    ac = session.get('access_token')
    auth_header = {
        "Authorization": "Bearer {}".format(ac)
    }
    params = {
        "url": playlist_url
    }
    endpoint = "https://open.spotify.com/oembed"
    resp = requests.get(endpoint, params=params, headers=auth_header)
    oembed = json.loads(resp.text)
    htmlCode = oembed['html']
    print(htmlCode)

    soup = BeautifulSoup(open("templates/preview.html"), 'html.parser')
    soup.select_one("#prev").append(BeautifulSoup(htmlCode, 'html.parser'))

    #soup.find_all('iframe')[0]['height'] = "351"

    save = soup.prettify("utf-8")
    with open("templates/preview.html", "wb") as fp:
        fp.write(save)

    #somehow remove added embed upon exiting page

    return render_template("preview.html")

"""
@views.route("/profile/<username>")
def profile(username):
    return render_template(...)

custom url parameters
"""

