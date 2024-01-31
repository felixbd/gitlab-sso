#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PACKAGE FILE FOR THE WEB APP
"""

import os
from flask import Flask
from flask_login import LoginManager

__encoding__ = "utf-8"

app = Flask(__name__)  # !! APP IS DECLARED HERE !!
app.config["SECRET_KEY"] = os.urandom(24).hex()  # app.secret_key

login_manager = LoginManager()
login_manager.init_app(app)

# !!! IMPORT AFTER DECLARING APP !!!
from app import views

def create_app():
   return app
