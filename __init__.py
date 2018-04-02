from flask import Flask, render_template, redirect
from flask_sqlalchemy import SQLAlchemy

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired

import argon2
import binascii
import os

app = Flask(__name__, template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY'] = binascii.b2a_hex(os.urandom(128)).decode('ascii')
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(256), nullable=False, unique=True)
    password_hash = db.Column(db.String(256), nullable=False)
    password_salt = db.Column(db.String(256), nullable=False)

    @classmethod
    def hash_password(cls, password, salt):
        return binascii.hexlify(argon2.argon2_hash(password, salt)).decode('ascii')

    @classmethod
    def create(cls, email, password):
        password_salt = binascii.b2a_hex(os.urandom(128)).decode('ascii')
        password_hash = cls.hash_password(password, password_salt)
        user = User(email=email, password_hash=password_hash, password_salt=password_salt)
        db.session.add(user)
        db.session.commit()

    @classmethod
    def check(cls, email, password):
        for user in User.query.filter(email==email):
            if user.password_hash == cls.hash_password(password, user.password_salt):
                return True
        return False

class UserCreateForm(FlaskForm):
    email = StringField('email', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    leaver_id = db.Column(db.Integer)
    receiver_id = db.Column(db.Integer)
    message = db.Column(db.String(1024))
    thumbs_up = db.Column(db.Boolean())
    date = db.Column(db.DateTime(6))
    viewed = db.Column(db.Boolean())

class UserLoginForm(FlaskForm):
    email = StringField('email', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])

db.create_all()

@app.route('/')
def index():
    #User.create('asdf', 'asdf', 'asdf')
    #print(User.check('asdf', 'fdsa'))
    return 'Hello World'

@app.route('/create', methods=['GET', 'POST'])
def create():
    form = UserCreateForm()
    if form.validate_on_submit():
        User.create(form.email.data, form.password.data)
        return redirect('/')
    return render_template('create.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = UserLoginForm()
    if form.validate_on_submit():
        return str(User.check(form.email.data, form.password.data))
    return render_template('login.html', form=form)

app.run(host='127.0.0.1', port=8080)

