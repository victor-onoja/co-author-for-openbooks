# Coauthor for openbooks

## Video Demo

[Video Demo Link](https://youtu.be/U2bsxTrdxTM)

## Description

This project is an app that let's users create text documents collaboratively with others in real time. It aims to provide a platform for writers to write leisurely and foster collaboration. The following sections provide an overview of the project structure, key files, and design choices.

## Project Structure

### `app.py`

The main application file that contains the Flask application setup, routes, and business logic. Key functionalities include user authentication, open book creation, text editing, and review request handling.

### `templates/`

This directory contains HTML templates used for rendering different pages of the web application. Notable templates include:

- `index.html`: Landing page
- `home.html`: User home page
- `textediting.html`: Page for editing open book content
- `review_requests.html`: Page for reviewing text editing requests
- `explore_openbooks.html`: Page displaying public open books
- `login.html`: Page for login
- `myopenbooks.html`: Page displaying user's openbooks
- `register.html`: Page for registration
- `startnewopenbookform.html`: Page to provide details for new openboook

### `README.md`

The document you are currently reading. It provides comprehensive information about the project, its structure, and key components.

## Design Choices

### User Authentication

I chose Flask-Login for user authentication due to its simplicity and seamless integration with Flask. It allows users to log in, log out, and access certain routes based on their authentication status.

### MongoDB Integration

MongoDB, a NoSQL database, was selected for its flexibility in handling unstructured data, which suits the dynamic nature of open book content and user information.

### Text Editing Workflow

The text editing workflow involves creating a review request when a user attempts to edit someone else's open book. The original creator can approve or disapprove the request. If approved, the content is updated, and the new creator is added as a collaborator.

Feel free to reach out if you have any questions or issues!
