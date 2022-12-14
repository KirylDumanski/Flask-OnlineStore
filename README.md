# Flask Online Store

## Introduction
This application based on one of my previous project but only used Flask microframework 
architecture. The goal was to get acquainted with this microframework and its plugins.


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
