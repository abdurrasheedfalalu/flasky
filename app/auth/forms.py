from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo, ValidationError

from .. models import User

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Length(1, 69),
                                             Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember_me = BooleanField("Keep me logged in")
    submit = SubmitField("Log In")


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
                DataRequired(), Length(1, 64),
                Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                'Usernames must have only letters, numbers, dots or '
                'underscores')])
    email = StringField("Email", validators=[DataRequired(), Length(1, 64),
                                             Email()])
    password = PasswordField("Password", validators=[
                DataRequired(), EqualTo("password2", message="Password must match.")])
    password2 = PasswordField("Confirm password", validators=[DataRequired()])
    submit = SubmitField("Register")


    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError("Email already registered.")
        
    def validate_email(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError("Username already in use.")