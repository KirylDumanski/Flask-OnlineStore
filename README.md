# Flask Online Store

## Introduction
"Flask Online Store" is an application based on Python using the Flask microframework.

## Technology stack
- Python 3.8
- Flask
- SQLAlchemy ORM
- Flask-login
- Flask-WTF

## Functionality
- Registration and authorization of users
- Session based shopping cart
- Ability to add categories and products
- User dashboard

## Installation Guide
1. Clone git repository
```
https://github.com/KirylDumanski/Flask-OnlineStore.git
```
2. Install a Virtual Environment.
3. Install the dependencies.
```
pip install -r requirements.txt  
```
4. Open the Flask shell to create DB:
```
flask shell
```
```
from app.models import Post, User, Profile
```
```
db.create_all()
```
5. Exit the flask shell `Ctrl+Z`,`Enter`
6. Run the application.