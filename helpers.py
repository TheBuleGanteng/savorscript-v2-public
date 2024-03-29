from flask import current_app
import csv
import datetime
from itsdangerous import TimedSerializer as Serializer
import os
import pytz
import re
import requests
import subprocess
import urllib
import uuid

from flask import redirect, render_template, session
from functools import wraps


def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def lookup(symbol):
    """Look up quote for symbol."""

    # Prepare API request
    symbol = symbol.upper()
    end = datetime.datetime.now(pytz.timezone("US/Eastern"))
    start = end - datetime.timedelta(days=7)

    # Yahoo Finance API
    url = (
        f"https://query1.finance.yahoo.com/v7/finance/download/{urllib.parse.quote_plus(symbol)}"
        f"?period1={int(start.timestamp())}"
        f"&period2={int(end.timestamp())}"
        f"&interval=1d&events=history&includeAdjustedClose=true"
    )

    # Query API
    try:
        response = requests.get(url, cookies={"session": str(uuid.uuid4())}, headers={"User-Agent": "python-requests", "Accept": "*/*"})
        response.raise_for_status()

        # CSV header: Date,Open,High,Low,Close,Adj Close,Volume
        quotes = list(csv.DictReader(response.content.decode("utf-8").splitlines()))
        quotes.reverse()
        price = round(float(quotes[0]["Adj Close"]), 2)
        return {
            "name": symbol,
            "price": price,
            "symbol": symbol
        }
    except (requests.RequestException, ValueError, KeyError, IndexError):
        return None


def usd(value):
    """Format value as USD."""
    return f"${value:,.2f}"


max_token_age_seconds = 900

# Token generation for password reset
def get_reset_token(user_id):
    s = Serializer(current_app.config['SECRET_KEY'], salt='reset-salt')
    return s.dumps({'user_id': user_id})

def verify_reset_token(token, max_age=max_token_age_seconds):
    print(f'running verify_reset_token(token, max_age=max_token_age_seconds)... starting')
    from models import User
    print(f'running verify_reset_token(token, max_age=max_token_age_seconds)... imported User from models')
    s = Serializer(current_app.config['SECRET_KEY'], salt='reset-salt')
    print(f'running verify_reset_token(token, max_age=max_token_age_seconds):... s from Serializer is: { s }')
    try:
        data = s.loads(token, max_age=max_age)
        print(f'running verify_reset_token(token, max_age=max_token_age_seconds):... data is: { data }')
        user_id = data['user_id']
        print(f'running verify_reset_token(token, max_age=max_token_age_seconds):... data[user_id] is: { data["user_id"] }')
    except Exception as e:
        print(f'running verify_reset_token(token, max_age=max_token_age_seconds):... error is: { e }')
        return None
    
    user_data = User.query.filter_by(user_id=user_id).first()
    if user_data:
        return user_data.as_dict()
    else:
        return None


# Generates a nonce to work with Talisman-managed CSP
def generate_nonce():
        return os.urandom(16).hex()