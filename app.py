import os
from datetime import datetime

from flask import Flask, render_template
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from slugify import slugify

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'store.db')
db = SQLAlchemy(app)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False, unique=True)
    slug = db.Column(db.String(150), index=True, unique=True)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Integer, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    is_active = db.Column(db.Boolean, default=True)

    def __init__(self, *args, **kwargs):
        if 'slug' not in kwargs:
            kwargs['slug'] = slugify(kwargs.get('title', ''))
        super().__init__(*args, **kwargs)

    def __repr__(self):
        return f"<Product {self.title}"


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    product_id = db.relationship('Product', backref='product_category')


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(500), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    date = db.Column(db.Integer, default=datetime.utcnow)

    def __repr__(self):
        return f"<User {self.id} - {self.first_name} {self.last_name}>"


@app.route('/')
def index():
    return render_template('store/index.html')


@app.route('/about')
def about():
    return render_template('store/about.html')


if __name__ == '__main__':
    app.run(debug=True)
