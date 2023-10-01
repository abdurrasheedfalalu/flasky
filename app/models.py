from datetime import datetime
import jwt
from time import time
from . import db, login_manager
from werkzeug.security import generate_password_hash, check_password_hash

from flask import current_app
from flask_login import AnonymousUserMixin, UserMixin

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Permission:
    FOLLOW = 1
    COMMENT = 2
    WRITE = 4
    MODERATE = 8
    ADMIN = 16


class Role(db.Model):
    __tablename__ = "roles"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship("User", backref="role", lazy="dynamic")

    def __init__(self, **kwargs):
        super(Role, self).__init__(**kwargs)
        if self.permissions is None:
            self.permissions = 0


    def add_permission(self, perm):
        if not self.has_permission(perm):
            self.permissions += perm

    def remove_permission(self, perm):
        if self.has_permission(perm):
            self.permissions -= perm
    
    def reset_permissions(self):
        self.permissions = 0

    def has_permission(self, perm):
        return self.permissions & perm == perm
    

    @staticmethod
    def insert_roles():
        roles = {
            "User": [
                Permission.FOLLOW,Permission.WRITE,Permission.COMMENT
            ],
            "Moderator": [
                Permission.MODERATE,Permission.WRITE,
                Permission.FOLLOW,Permission.COMMENT
            ],
            "Administrator": [
                Permission.ADMIN,Permission.MODERATE,Permission.WRITE,
                Permission.FOLLOW,Permission.COMMENT
            ]
        }

        default_role = "User"
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.reset_permissions()
            for perm in roles[r]:
                role.add_permission(perm)
            role.default = (role.name == default_role)
            db.session.add(role)
        db.session.commit()



    def __repr__(self):
        return f"<Role {self.name} >"
    

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"))
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(64))
    location = db.Column(db.String(64))
    about_me = db.Column(db.Text())
    member_since = db.Column(db.DateTime(), default=datetime.utcnow)
    last_since = db.Column(db.DateTime(), default=datetime.utcnow)

    @property
    def password(self):
        raise AttributeError("password is not a readable attribute")
    
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    


    def generate_confirmation_token(self, expiration=3600):
        payload = {'confirm': self.id, "exp": time() + expiration}
        token = jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')
        return token
    
    def confirm(self, token):
        try:
            payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return False  # Error occur
        if payload.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True




    def generate_reset_token(self, expiration=3600):
        payload = {'reset': self.id, "exp": time() + expiration}
        token = jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')
        return token

    @staticmethod
    def reset_password(token, new_password):
        try:
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return False
        user = User.query.get(data.get('reset'))
        if user is None:
            return False
        user.password = new_password
        db.session.add(user)
        return True

    def generate_email_change_token(self, new_email, expiration=3600):
        payload = {'change_email': self.id, "new_email": new_email, "exp": time() + expiration}
        token = jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')
        return token

    def change_email(self, token):
        try:
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return False
        if data.get('change_email') != self.id:
            return False
        new_email = data.get('new_email')
        if new_email is None:
            return False
        if self.query.filter_by(email=new_email).first() is not None:
            return False
        self.email = new_email
        self.avatar_hash = self.gravatar_hash()
        db.session.add(self)
        return True


    
    def can(self, perm):
        return self.role is not None and self.role.has_permission(perm)
    
    def is_administrator(self):
        return self.can(Permission.ADMIN)
    

    def ping(self):
        self.last_seen = datetime.utcnow()
        db.session.add(self)
        db.session.commit()


    def __repr__(self):
        return f"<User {self.username} >"
    


class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False
    
    def is_administrator(self):
        return False
    
login_manager.anonymous_user = AnonymousUser