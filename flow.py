import requests
import math
import random
import os
import base64
import hashlib
import html
import json
import re
import urllib.parse
from dotenv import load_dotenv

load_dotenv()
cid = os.getenv("CLIENT_ID")
cs = os.getenv("CLIENT_SECRET")
redirect_uri = "http://localhost:3000"

verifier = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8')
verifier = re.sub('[^a-zA-Z0-9]+', '', verifier)

challenge = hashlib.sha256(verifier.encode('utf-8')).digest()
challenge = base64.urlsafe_b64encode(challenge).decode('utf-8')
challenge = challenge.replace('=', '')

scope = ''
state = "generaterandstring1"

resp = requests.get(
    url='https://accounts.spotify.com/authorize?',
    params={
        "response_type":"code",
        "client_id": cid,
        "scope" : scope,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge_method": 'S256',
        "code_challenge": challenge
    },
    allow_redirects=False
)
redirect = resp.headers['L']
query = urllib.parse()



