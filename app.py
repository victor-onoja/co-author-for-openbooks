import os
from flask import Flask, render_template, redirect, url_for, redirect
from flask_login import LoginManager, UserMixin, login_user
from flask_pymongo import PyMongo
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, EqualTo

secret_key = os.urandom(24)
app = Flask(__name__)
app.config['SECRET_KEY'] = secret_key
app.config['MONGO_URI'] = 'mongodb+srv://odohvictor47:xGMui2bKiAvw5mYs@cluster0.0mmubhj.mongodb.net/?retryWrites=true&w=majority'
mongo = PyMongo(app)
login_manager = LoginManager(app)

@app.route('/')
def home():
    return render_template('index.html')

@login_manager.user_loader
def load_user(user_id):
    # Implement this function to load the user from your database.
    # For simplicity, we'll create a temporary user here.
    return User(user_id)

class User(UserMixin):
    def __init__(self, user_id):
        # For simplicity, we're using a temporary user with a user ID.
        self.id = user_id

@app.route('/login')
def login():
    # For simplicity, we'll log in a user with ID 1.
    user = User(1)
    login_user(user)
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)