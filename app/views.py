#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
RENDERING HTML TEMPLATES
"""

from __future__ import annotations


HOME_URL                    = "http://localhost:5000"
# ---
GITLAB_URL                  = "https://gitlab.********.de"
GITLAB_CLIENT_ID            = "****************************************************************"
GITLAB_CLIENT_SECRET        = "****************************************************************"
GITLAB_SCOPE                = "openid"
# ---
GITLAB_REDIRECT_URI         = f"{HOME_URL}/auth/gitlab/callback"
GITLAB_OPENID_DISCOVERY_URL = f"{GITLAB_URL}/.well-known/openid-configuration"
GITLAB_AUTH_URL             = f"{GITLAB_URL}/oauth/authorize"
GITLAB_TOKEN_URL            = f"{GITLAB_URL}/oauth/token"
GITLAB_API_URL              = f"{GITLAB_URL}/api/v4"


import os
import datetime
import math
import hashlib
import uuid
import ast  # evaluating string to list

import requests

from app import app, login_manager, __encoding__

import flask
from flask import render_template, send_from_directory, url_for, request
from flask import Flask, redirect, request, session
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user


# dict containing (user id: str) as a key and the (user obj: User) as a val
LOGGED_IN_USERS: dict = {}


# ============================================================================================================
#
#   HELPER FUNCTIONS
#
def convert_time_unix2utc(t: float) -> str:
    """converting unix time stamp to utc time https://stackoverflow.com/a/59758661"""
    return str(datetime.datetime.fromtimestamp(t, tz=datetime.timezone.utc))


def get_user_session_info(key):
    return session["user"].get(key, f"Key `{key}` not found in user session info")


# ============================================================================================================
#
#   LOGIN USERS, REDIRECT UNAUTHORIZED USERS TO LOGIN PAGE
#

class User(UserMixin):
    _id: str        # GitLab ID
    name: str       # full name
    nickname: str   # gitlab user name

    def __init__(self, id: str, name: str, nickname: str):
        super(UserMixin, self).__init__()
        self._id = id
        self.name = name
        self.nickname = nickname

        # global LOGGED_IN_USERS
        LOGGED_IN_USERS[id] = self

    @property
    def id(self) -> str:
        return self._id

    @id.setter
    def id(self, a) -> None:
        raise NotImplementedError("IDs of Users can not be set/changed!")

    @staticmethod
    def get(user_id: str) -> User:
        # global LOGGED_IN_USERS
        return LOGGED_IN_USERS[user_id]


@app.route("/auth/gitlab")
def gitlab_auth():
    # Generate the GitLab authentication URL
    auth_url = f"{GITLAB_AUTH_URL}?client_id={GITLAB_CLIENT_ID}&redirect_uri={GITLAB_REDIRECT_URI}&response_type=code&scope={GITLAB_SCOPE}"

    # Redirect the user to the GitLab authentication URL
    return redirect(auth_url)


@app.route("/auth/gitlab/callback")
def gitlab_callback():

    def get_config():
        """
        get the config of the gitlab openid
        """
        response = requests.get(GITLAB_OPENID_DISCOVERY_URL)
        response.raise_for_status()
        
        return response.json()

    def get_access_token(code):
        """
        gets the access token form response code
        """
        config = get_config()
        token_url = config['token_endpoint']
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'client_id': GITLAB_CLIENT_ID,
            'client_secret': GITLAB_CLIENT_SECRET,
            'redirect_uri': GITLAB_REDIRECT_URI
        }
        response = requests.post(token_url, data=data)
        response.raise_for_status()

        return response.json()['access_token']

    def get_user_data(access_token):
        """
        get the users email via access token
        """
        config = get_config()
        userinfo_url = config['userinfo_endpoint']
        headers = {'Authorization': f'Bearer {access_token}'}
        response = requests.get(userinfo_url, headers=headers)
        response.raise_for_status()
        return response.json()

    # Exchange the authorization code for an access token
    code = request.args.get("code")

    # Retrieve the access token
    token_url = f"{GITLAB_TOKEN_URL}?client_id={GITLAB_CLIENT_ID}&client_secret={GITLAB_CLIENT_SECRET}&code={code}&grant_type=authorization_code&redirect_uri={GITLAB_REDIRECT_URI}"
    response = requests.post(token_url)
    access_token = response.json().get("access_token")

    # HTTP-Request to the OpenID Connect Discovery URL of GitLab
    discovery_response = requests.get(GITLAB_OPENID_DISCOVERY_URL)

    # Extract the introspection endpoint URL from the discovery request response
    introspection_endpoint = discovery_response.json()["introspection_endpoint"]

    # Parameter for the token introspection request
    data = {"token": access_token, "token_type_hint": "access_token"}

    # HTTP-Request to retrieve user data using the GitLab token
    introspection_response = requests.post(
        introspection_endpoint, data=data, auth=(GITLAB_CLIENT_ID, GITLAB_CLIENT_SECRET)
    )

    client_gitlab_id = introspection_response.json()["client_id"]

    user_data = get_user_data(access_token)

    user_gitlab_id = user_data['sub']
    user_name = user_data['name']
    user_nickname = user_data['nickname']
    user_groups = user_data['groups']


    # has authorized via GitLab (and is part of the 'abc' group)
    if True:  # 'abc' in user_groups:

        # create a new user
        user = User(id=user_gitlab_id, name=user_name, nickname=user_nickname)

        # login via flask session
        login_user(user)
        flask.flash("Logged in successfully.")

        next = flask.request.args.get("next")

        # TODO: check if the url is valid
        #  if not flask.is_safe_url(next):
        #     return flask.abort(400)

        return redirect(next or "/")  # (next or '/')  equiv to  (next if next else '/')

    # else:
    flask.flash("Login failed. Forbidden 403.")
    return redirect("/login")


#-------------------------------------------
#   LOGS USER IN IF CREDENTIALS ARE VALID
#
@app.route("/login", methods=["GET", "POST"])
def login_page():
    return render_template("login.html")


#-----------------------
#   LOAD USER FORM ID
#
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


#--------------------------------------------------
#   REDIRECT UNAUTHORIZED USER TO LOGIN PAGE
# (with the page he wanted to visit as a next arg)
#
@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect("/login?next=" + request.path)


#-----------------------
#   LOGS THE USER OUT
#
@app.route("/logout")
@login_required
def logout_page():
    # TODO remove user LOGGED_IN_USERS dict

    logout_user()

    return redirect("/login")


# ============================================================================================================
#
#   LANDING PAGE
#
@app.route("/", methods=("GET", "POST"))
@login_required
def landing_page():
    """
    Return a rendered html template
    """
    return render_template("landing.html")
