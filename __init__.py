from flask import Flask, render_template, redirect, request, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user, login_required, login_user, logout_user

from sqlalchemy.sql import func

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectMultipleField, SubmitField
from wtforms.validators import DataRequired, Regexp

from flask_bootstrap import Bootstrap

import argon2
import binascii
import os
import time

app = Flask(__name__, template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY'] = binascii.b2a_hex(os.urandom(128)).decode('ascii')
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.login_view = 'user_login'
login_manager.init_app(app)

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
        return user

    @classmethod
    def check(cls, email, password):
        for user in User.query.filter(User.email==email):
            if user.password_hash == cls.hash_password(password, user.password_salt):
                return user
        return None

    def is_authenticated(self):
        return True
 
    def is_active(self):
        return True
 
    def is_anonymous(self):
        return False
 
    def get_id(self):
        return self.id

    @login_manager.user_loader
    def get_user(id):
        for user in User.query.filter(User.id==id):
            return user
        return None


class UserCreateForm(FlaskForm):
    email = StringField('email', validators=[DataRequired(), Regexp('^[A-z0-9]+\\@[A-z0-9]+\\.[A-z]+$')])
    password = PasswordField('password', validators=[DataRequired()])
    submit = SubmitField('submit')


class UserLoginForm(FlaskForm):
    email = StringField('email', validators=[DataRequired(), Regexp('^[A-z0-9]+\\@[A-z0-9]+\\.[A-z]+$')])
    password = PasswordField('password', validators=[DataRequired()])
    submit = SubmitField('submit')


class Plate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    state = db.Column(db.String(256))
    number = db.Column(db.String(256))

    @classmethod
    def create(cls, state, number):
        plate = Plate(state=state, number=number, user_id=-1)
        db.session.add(plate)
        db.session.commit()
        return plate

    @classmethod
    def get(cls, state, number):
        for plate in Plate.query.filter(Plate.state==state, Plate.number==number):
            return plate
        return None

    @property
    def score(self):
        for item in db.session.query(func.sum(Comment.thumbs_up).label('score')).filter(Comment.plate_id==self.id):
            return item.score
        return 0

    def assign(self, user_id):
        if self.user_id != -1:
            return
        self.user_id = user_id
        db.session.commit()


class PlateForm(FlaskForm):
    state = StringField('state', validators=[DataRequired()])
    number = StringField('number', validators=[DataRequired()])
    submit = SubmitField('submit')


class PlateSearchForm(FlaskForm):
    state = StringField('state', validators=[])
    number = StringField('number', validators=[])
    submit = SubmitField('submit')


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    leaver_id = db.Column(db.Integer)
    plate_id = db.Column(db.Integer)
    message = db.Column(db.String(1024))
    thumbs_up = db.Column(db.Integer)
    date = db.Column(db.DateTime(6))
    viewed = db.Column(db.Boolean())

    @classmethod
    def create(cls, leaver_id, plate_id, message, thumbs_up):
        comment = Comment(leaver_id=leaver_id, plate_id=plate_id, message=message, thumbs_up=thumbs_up)
        db.session.add(comment)
        db.session.commit()


class CommentForm(FlaskForm):
    message = StringField('comment', validators=[DataRequired()])
    thumbs_up = SelectMultipleField('thumbs up', choices=[('yes', 'yes'),('no', 'no')])
    submit = SubmitField('submit')


@app.before_request
def before_request():
    g.user = current_user

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/user/create', methods=['GET', 'POST'])
def user_create():
    form = UserCreateForm()
    if form.validate_on_submit():
        user = User.create(form.email.data, form.password.data)
        login_user(user)
        return redirect('/')
    return render_template('user_create.html', form=form)

@app.route('/user/login', methods=['GET', 'POST'])
def user_login():
    form = UserLoginForm()
    if form.validate_on_submit():
        user = User.check(form.email.data, form.password.data)
        if user:
            login_user(user)
            return redirect('/')
    return render_template('user_login.html', form=form)

@app.route('/user/logout')
def user_logout():
    logout_user()
    return redirect('/') 

@app.route('/user/plates/view')
@login_required
def user_plates_view():
    plates = Plate.query.filter(Plate.user_id==g.user.id)
    form = PlateForm()
    return render_template('user_plates_view.html', plates=plates, form=form)

@app.route('/user/plates/add', methods=['POST'])
@login_required
def user_plates_add():
    form = PlateForm()
    if form.validate_on_submit():
        plate = Plate.get(form.state.data, form.number.data)
        if plate is None:
            plate = Plate.create(form.state.data, form.number.data)
        if plate.user_id == -1:
            plate.assign(g.user.id)
        else:
            print('someone owns this already')
    return redirect('/user/plates/view')

@app.route('/plate/<state>/<number>', methods=['GET', 'POST'])
def plate(state, number):
    plate = Plate.get(state, number)
    if plate is None:
        return 'plate not found', 404
    form = CommentForm()
    if form.validate_on_submit():
        thumbs_up = -1
        if form.thumbs_up.data[0] == 'yes':
            thumbs_up = 1
        Comment.create(current_user.id, plate.id, form.message.data, thumbs_up)
    comments = Comment.query.filter(Comment.plate_id==plate.id)
    return render_template('plate.html', plate=plate, comments=comments, form=form)

@app.route('/plate/register', methods=['POST'])
def plate_register():
    form = PlateForm()
    if form.validate_on_submit():
        Plate.create(form.state.data, form.number.data)
        return redirect('/plate/{}/{}'.format(form.state.data, form.number.data))
    return redirect('/plate/search')

@app.route('/plate/search', methods=['GET', 'POST'])
def plate_search():
    form = PlateSearchForm()
    if form.validate_on_submit():
        plates = Plate.query.filter(Plate.state.contains(form.state.data))
    else:
        plates = Plate.query.filter()
    return render_template('plate_search.html', plates=plates, form=form)

db.create_all()
app.run(host='127.0.0.1', port=8080)

