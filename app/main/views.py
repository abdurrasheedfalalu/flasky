from datetime import datetime

from flask import render_template, session, redirect, url_for, current_app
from flask_login import login_required

from app.models import Permission
from . import main

from .. decorators import permission_required, admin_required

@main.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')


@main.route("/admin")
@login_required
@admin_required
def for_admins_only():
    return "For Administrator"


@main.route("/moderator")
@login_required
@permission_required(Permission.MODERATE)
def for_moderators_only():
    return "For comment moderators!"