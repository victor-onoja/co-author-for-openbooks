import os
from flask import Flask, render_template, redirect, url_for, redirect, request, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user, user_loaded_from_request
from flask_pymongo import PyMongo
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import InputRequired, Length, EqualTo, Email
from flask_bcrypt import Bcrypt
from bson import ObjectId

secret_key = os.urandom(24)
app = Flask(__name__)
csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)
uri = 'mongodb+srv://odohvictor47:FvnCRiooGaiDPlXh@cluster0.gqueebf.mongodb.net/?retryWrites=true&w=majority'
app.config['SECRET_KEY'] = secret_key
app.config['MONGO_URI'] = 'mongodb+srv://odohvictor47:FvnCRiooGaiDPlXh@cluster0.gqueebf.mongodb.net/?retryWrites=true&w=majority'
mongo = PyMongo(app)
login_manager = LoginManager(app)

client = MongoClient(uri)

db = client.main
users = db.users

try:
    client.admin.command('ping')
    print('Pinged your deployment. You successfully connected to MongoDB!')
except Exception as e:
    print(e)

@app.route('/')
def index():
    return render_template('index.html')

@login_manager.user_loader
def load_user(user_id):
    # Implement this function to load the user from your database.
    user_data = users.find_one({'_id': ObjectId(user_id)})
    if user_data:
        return User(user_data['_id'], user_data['penname'])
        return None
    # For simplicity, we'll create a temporary user here.
    # return User(user_id)

@user_loaded_from_request.connect
def on_user_loaded_from_request(sender, user):
    # Check if the user is active, banned, etc.
    if not user.is_active:
        logout_user()

class User(UserMixin):
    def __init__(self, user_id, penname):
        # For simplicity, we're using a temporary user with a user ID.
        self.id = user_id
        self.penname = penname

class LoginForm(FlaskForm):
    penname = StringField('Penname', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')

@app.route('/login', methods = ['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        penname = form.penname.data
        password = form.password.data

        user_data = users.find_one({'penname': penname})

        if user_data and bcrypt.check_password_hash(user_data['password'], password):
            user = User(user_data['_id'], user_data['penname'])
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid penname or password. Please try again.', 'failure')

    return render_template('login.html', form=form)
    # For simplicity, we'll log in a user with ID 1.
    # user = User(1)
    # login_user(user)
    # return redirect(url_for('home'))

@app.route('/home')
@login_required
def home():
    return render_template('home.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout successful!', 'success')
    return redirect(url_for('index'))

class RegistrationForm(FlaskForm):
    email = EmailField('Email', validators=[InputRequired(), Email()])
    penname = StringField('Penname', validators=[InputRequired(), Length(min=3, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=60)])
    submit = SubmitField('Register')

    def validate_penname(self, penname):
        user = users.find_one({'penname': penname.data})
        if user:
            raise ValidationError('Penname already taken. Please choose another one :(')

    def validate_email(self, email):
        user = users.find_one({'email': email.data})
        if user:
            raise ValidationError('Email already registered. Please use another email address.')

@app.route('/register', methods = ['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        user_data = {'email': form.email.data,'penname': form.penname.data, 'password': hashed_password}
        users.insert_one(user_data)
        flash('Registration successful!', 'success')

        return redirect(url_for('login'))

    return render_template('register.html', form = form)

if __name__ == '__main__':
    app.run(debug=True)