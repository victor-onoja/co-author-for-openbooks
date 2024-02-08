# imports

import os
from os.path import join
from flask import Flask, render_template, redirect, url_for, redirect, request, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user, user_loaded_from_request
from flask_pymongo import PyMongo
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField, FileRequired
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, EmailField, TextAreaField, BooleanField, FileField
from wtforms.validators import InputRequired, Length, EqualTo, Email, ValidationError
from flask_bcrypt import Bcrypt
from bson import ObjectId
from datetime import datetime
from flask_uploads import UploadSet, IMAGES, configure_uploads

# variables

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
openbooks = db.openbooks
text_editing_requests = db.text_editing_requests

photos = UploadSet('photos', IMAGES)
app.config['UPLOADED_PHOTOS_DEST'] = 'uploads'
configure_uploads(app, photos)

# test mongodb connection

try:
    client.admin.command('ping')
    print('Pinged your deployment. You successfully connected to MongoDB!')
except Exception as e:
    print(e)

# index app route

@app.route('/')
def index():
    return render_template('index.html')


# login, user functions

@login_manager.user_loader
def load_user(user_id):
    # Implement this function to load the user from your database.
    user_data = users.find_one({'_id': ObjectId(user_id)})
    if user_data:
        return User(user_data['_id'], user_data['penname'])
        return None

@user_loaded_from_request.connect
def on_user_loaded_from_request(sender, user):
    # Check if the user is active, banned, etc.
    if not user.is_active:
        logout_user()

class User(UserMixin):
    def __init__(self, user_id, penname):
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

# home route

@app.route('/home')
@login_required
def home():
    return render_template('home.html')

# new open book functions

def optional_file_allowed(form, field):
    if field.data:
        FileAllowed(['jpg', 'jpeg', 'png'], 'Images Only!')(form, field)


class NewOpenBookForm(FlaskForm):
    title = StringField('Title')
    description = TextAreaField('Description')
    content = TextAreaField('Content')
    is_private = BooleanField('Private')
    cover_image = FileField('Cover Image', validators=[optional_file_allowed])
    submit = SubmitField('Create Open Book')

@app.route('/new_openbook_form', methods = ['GET', 'POST'])
@login_required
def new_openbook_form():

    form = NewOpenBookForm()
  
    if form.validate_on_submit():
       
        cover_image = form.cover_image.data

        if cover_image:
            # Save the cover image
            filename = photos.save(cover_image)
            cover_image_path = join(app.config['UPLOADED_PHOTOS_DEST'], filename)
        else:
            cover_image_path = None
        openbook_data = {
            'title': form.title.data,
            'description': form.description.data,
            'is_private': form.is_private.data,
            'cover_image': cover_image_path,
            'creator': current_user.penname,
            'created_at': datetime.utcnow(),
            'content': ''
        }    

        openbooks.insert_one(openbook_data)    
        flash('Open Book created successfully!', 'success')
        return redirect(url_for('text_editing', openbook_id = openbook_data['_id']))

    return render_template('startnewopenbookform.html', form = form)

# textediting route

@app.route('/text_editing/<openbook_id>', methods=['GET', 'POST'])
@login_required
def text_editing(openbook_id):
    # Retrieve the existing openbook data
    openbook_data = openbooks.find_one({'_id': ObjectId(openbook_id)})

    if not openbook_data:
        flash('OpenBook not found!', 'danger')
        return redirect(url_for('home'))

    is_original_creator = current_user.penname == openbook_data['creator']

    # Pre-fill the form with the existing data or create an empty form
    form = NewOpenBookForm(obj=openbook_data) if openbook_data else NewOpenBookForm()

    if form.validate_on_submit():
        if is_original_creator:
            # Process form submission and update the content in the backend
            new_content = form.content.data
            openbooks.update_one({'_id': ObjectId(openbook_id)}, {'$set': {'content': new_content}})
            flash('Story saved successfully!', 'success')

            # Redirect to the same page to refresh the form with updated data
            return redirect(url_for('text_editing', openbook_id=openbook_id))
        else:
            new_content = form.content.data
            if openbook_data['content'] != new_content:
                new_creator = current_user.penname
                request_data = {
                    'original_document_id': openbook_id,
                    'original_creator': openbook_data['creator'],
                    'new_creator': new_creator,
                    'is_approved': None,
                    'edited_content': new_content
                }
                text_editing_requests.insert_one(request_data)

                flash(f'Text editing request sent to {openbook_data["creator"]} for approval.', 'info')
                return redirect(url_for('home'))
            else:
                flash('No changes detected. Request not submitted.', 'warning')

    # Render the template with the pre-filled form
    return render_template('textediting.html', form=form, openbook_data=openbook_data)

# read openbook
@app.route('/read_openbook/<openbook_id>')
@login_required
def read_openbook(openbook_id):
    openbook_data = openbooks.find_one({'_id': ObjectId(openbook_id)})
    if not openbook_data:
        flash('OpenBook not found!', 'danger')
        return redirect(url_for('home'))
    
    return render_template('read_openbook.html', openbook_data=openbook_data)

# review text editing route

@app.route('/review_text_editing_requests')
@login_required
def review_text_editing_requests():

    # Retrieve text editing requests for the current user
    requests = text_editing_requests.find({'original_creator': current_user.penname})

    return render_template('reviewrequests.html', requests=requests)

@app.route('/approve_request/<request_id>/<action>')
@login_required
def approve_request(request_id, action):
    # Get the text editing request
    request_data = text_editing_requests.find_one({'_id': ObjectId(request_id)})

    if not request_data or request_data['original_creator'] != current_user.penname:
        flash('Invalid request or you are not the original creator.', 'danger')
        return redirect(url_for('review_text_editing_requests'))

    # Update the request status based on the action
    if action == 'approve':
        text_editing_requests.update_one({'_id': ObjectId(request_id)}, {'$set': {'is_approved': True}})
        openbooks.update_one(
            {'_id': ObjectId(request_data['original_document_id'])},
            {'$set': {'content': request_data['edited_content']},  '$addToSet': {'collaborators': request_data['new_creator']}}
        )
        flash('Text editing request approved.', 'success')
    elif action == 'disapprove':
        text_editing_requests.delete_one({'_id': ObjectId(request_id)})
        flash('Text editing request disapproved.', 'success')

    return redirect(url_for('review_text_editing_requests'))

# myopenbooks route

@app.route('/my_openbooks')
@login_required
def my_openbooks():
    user_openbooks = openbooks.find({'creator': current_user.penname})
    return render_template('myopenbooks.html', openbooks=user_openbooks)

# explore_openbooks route

@app.route('/explore_openbooks')
@login_required
def explore_openbooks():
    # Fetch all non-private open books
    public_openbooks = openbooks.find({'is_private': False})

    openbooks_info = []
    for openbook in public_openbooks:
        # Extract relevant information
        openbook_info = {
            'title': openbook['title'],
            'description': openbook['description'],
            'creator': openbook['creator'],
            '_id': openbook['_id'],
            'collaborators': openbook.get('collaborators', []),
        }
        openbooks_info.append(openbook_info)

    return render_template('exploreopenbooks.html', openbooks=openbooks_info)


#  logout route

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout successful!', 'success')
    return redirect(url_for('index'))

# registration functions

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

# app main

if __name__ == '__main__':
    app.run(debug=False)