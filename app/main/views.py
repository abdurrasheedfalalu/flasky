from datetime import datetime

from flask import render_template, redirect, url_for, current_app
from flask_login import login_required

from app.models import User
from . import main


@main.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')


@main.route('/user/<username>')
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    print(user.last_seen)
    return render_template('user.html', user=user)