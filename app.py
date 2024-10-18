# imports

import atexit
import os
import cloudinary
import cloudinary.uploader
import cloudinary.api
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
from wtforms.validators import InputRequired, Length, EqualTo, Email, ValidationError, DataRequired
from flask_bcrypt import Bcrypt
from bson import ObjectId
from datetime import datetime
from flask_uploads import UploadSet, IMAGES, configure_uploads
from apscheduler.schedulers.background import BackgroundScheduler

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

# Create indexes for text_editing_requests collection
text_editing_requests.create_index("status")
text_editing_requests.create_index("creator_notified")
text_editing_requests.create_index("requester_notified")

# Configure Cloudinary credentials
cloudinary.config(
    cloud_name="dati00h7i",
    api_key="613737112654711",
    api_secret="VK0g88htvAGc4E9qX7_ZbHkA6ik"
)

# test mongodb connection

try:
    client.admin.command('ping')
    print('Pinged your deployment. You successfully connected to MongoDB!')
except Exception as e:
    print(e)

    # Add this function to clean up old requests
def cleanup_old_requests():
    old_requests = text_editing_requests.find({
        'creator_notified': True,
        'requester_notified': True
    })
    
    for request in old_requests:
        text_editing_requests.delete_one({'_id': request['_id']})
    
    print(f"Cleanup complete. Deleted {old_requests.count()} old requests.")

    # Set up the scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(func=cleanup_old_requests, trigger="interval", hours=730)
scheduler.start()

# index app route

@app.route('/')
def index():
    current_year = datetime.now().year
    return render_template('index.html', current_year=current_year)


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
    current_year = datetime.now().year

    # Check for pending requests for the original creator
    pending_requests = text_editing_requests.find({
        'original_creator': current_user.penname,
        'status': 'pending',
        'creator_notified': False
    })
    
    for request in pending_requests:
        flash(f"You have a pending request from {request['new_creator']}.", 'info')
    
    # Check for status updates for the requester
    user_requests = text_editing_requests.find({
        'new_creator': current_user.penname,
    })

    for request in user_requests:
        if request['status'] == 'pending':
            flash(f"Your request for '{request['original_document_title']}' is still pending from {request['original_creator']}.", 'info')
        elif request['status'] in ['approved', 'disapproved'] and not request.get('requester_notified', False):
            if request['status'] == 'approved':
                flash(f"Your request for '{request['original_document_title']}' has been approved.", 'success')
            else:
                flash(f"Your request for '{request['original_document_title']}' has been disapproved.", 'info')
            
            text_editing_requests.update_one(
                {'_id': request['_id']},
                {'$set': {'requester_notified': True}}
            )
    return render_template('home.html', current_year=current_year)

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
    current_year = datetime.now().year
  
    if form.validate_on_submit():
       
        cover_image = form.cover_image.data

        if cover_image:
            # Upload image to Cloudinary
            uploaded_image = cloudinary.uploader.upload(cover_image)
            cover_image_url = uploaded_image['url']
        else:
            cover_image_url = None
        openbook_data = {
            'title': form.title.data,
            'description': form.description.data,
            'is_private': form.is_private.data,
            'cover_image': cover_image_url,
            'creator': current_user.penname,
            'created_at': datetime.now(),
            'content': ''
        }    

        openbooks.insert_one(openbook_data)    
        flash('Open Book created successfully!', 'success')
        return redirect(url_for('text_editing', openbook_id = openbook_data['_id']))

    return render_template('startnewopenbookform.html', form = form, current_year=current_year)

# textediting route

@app.route('/text_editing/<openbook_id>', methods=['GET', 'POST'])
@login_required
def text_editing(openbook_id):
    current_year = datetime.now().year
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
                    'original_document_title': openbook_data['title'],
                    'original_creator': openbook_data['creator'],
                    'new_creator': new_creator,
                    'status': 'pending',
                    'edited_content': new_content,
                    'creator_notified': False,
                    'requester_notified': False
                }
                text_editing_requests.insert_one(request_data)

                flash(f'Text editing request sent to {openbook_data["creator"]} for approval.', 'info')
                return redirect(url_for('home'))
            else:
                flash('No changes detected. Request not submitted.', 'warning')

    # Render the template with the pre-filled form
    return render_template('textediting.html', form=form, openbook_data=openbook_data, current_year=current_year)

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

    current_year = datetime.now().year

    # Retrieve text editing requests for the current user
    requests = text_editing_requests.find({'original_creator': current_user.penname})

    return render_template('reviewrequests.html', requests=requests, current_year=current_year)

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
        text_editing_requests.update_one({'_id': ObjectId(request_id)}, {'$set': {'status': 'approved',
                'creator_notified': True,
                'requester_notified': False}})
        openbooks.update_one(
            {'_id': ObjectId(request_data['original_document_id'])},
            {'$set': {'content': request_data['edited_content']},  '$addToSet': {'collaborators': request_data['new_creator']}}
        )
        flash('Text editing request approved.', 'success')
    elif action == 'disapprove':
        text_editing_requests.update_one(
            {'_id': ObjectId(request_id)},
            {'$set': {
                'status': 'disapproved',
                'creator_notified': True,
                'requester_notified': False
            }}
        )
        flash('Text editing request disapproved.', 'success')

    return redirect(url_for('review_text_editing_requests'))

# myopenbooks route

@app.route('/my_openbooks')
@login_required
def my_openbooks():
    current_year = datetime.now().year
    user_openbooks = openbooks.find({'creator': current_user.penname})
    return render_template('myopenbooks.html', openbooks=user_openbooks, current_year=current_year)

# explore_openbooks route

@app.route('/explore_openbooks')
@login_required
def explore_openbooks():
    current_year = datetime.now().year
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

    return render_template('exploreopenbooks.html', openbooks=openbooks_info, current_year=current_year)


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
    agree = BooleanField('I agree to the Terms of Service and User Agreement', validators=[DataRequired()])
    submit = SubmitField('Register')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        if not form.agree.data:
            flash('You must agree to the Terms of Service and User Agreement.', 'error')
            return redirect(url_for('register'))

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        # Check if the email is already registered
        existing_user = users.find_one({'email': form.email.data})
        if existing_user:
            flash('Email already registered. Please use another email address.', 'error')
            return redirect(url_for('register'))

        # Check if the penname is already taken
        existing_penname = users.find_one({'penname': form.penname.data})
        if existing_penname:
            flash('Penname already taken. Please choose another one.', 'error')
            return redirect(url_for('register'))

        # Insert the new user data into the database
        user_data = {'email': form.email.data, 'penname': form.penname.data, 'password': hashed_password}
        try:
            users.insert_one(user_data)
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash('An error occurred while registering. Please try again later.', 'error')
            app.logger.error(f"Error during user registration: {str(e)}")
            return redirect(url_for('register'))

    return render_template('register.html', form=form)

#  terms of service 

@app.route('/terms_of_service')
def terms_of_service():
    return render_template('terms_of_service.html')


# app main

if __name__ == '__main__':
    app.run(debug=False)

atexit.register(lambda: scheduler.shutdown())