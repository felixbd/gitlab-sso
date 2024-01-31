#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ENTRY POINT FOR FLASK
"""

from app import app


if __name__ == "__main__":
    app.run(debug=False)
