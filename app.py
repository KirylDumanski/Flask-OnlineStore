import os
import uuid
from datetime import datetime

from flask import Flask, render_template, flash, request
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from slugify import slugify
from werkzeug.utils import secure_filename
from wtforms import SubmitField, StringField, IntegerField, BooleanField, TextAreaField, FileField
from wtforms.validators import DataRequired
from wtforms_alchemy import QuerySelectField

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'DEVELOPMENT'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'store.db')
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'static\\images\\')
db = SQLAlchemy(app)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False, unique=True)
    slug = db.Column(db.String(150), index=True, unique=True)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Integer, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    quantity = db.Column(db.Integer, nullable=False)
    active = db.Column(db.Boolean, default=True)
    picture = db.Column(db.String(), nullable=True)

    def __init__(self, *args, **kwargs):
        if 'slug' not in kwargs:
            kwargs['slug'] = slugify(kwargs.get('title', ''))
        super().__init__(*args, **kwargs)

    def __repr__(self):
        return f"<Product {self.id} - {self.title}"


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    slug = db.Column(db.String(200), index=True, unique=True)
    product_id = db.relationship('Product', backref='category')

    def __init__(self, *args, **kwargs):
        if 'slug' not in kwargs:
            kwargs['slug'] = slugify(kwargs.get('name', ''))
        super().__init__(*args, **kwargs)

    def __repr__(self):
        return f"{self.name}"


@app.context_processor
def inject_sidebar():
    return dict(sidebar_categories=Category.query.order_by(Category.name))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(500), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    date = db.Column(db.Integer, default=datetime.utcnow)

    def __repr__(self):
        return f"<User {self.id} - {self.first_name} {self.last_name}>"


class ProductForm(FlaskForm):
    title = StringField("Title: ", validators=[DataRequired()])
    description = TextAreaField("Description: ")
    price = IntegerField("Price (in cents): ", validators=[DataRequired()])
    category_id = QuerySelectField("Category: ",
                                   query_factory=lambda: Category.query.all(),
                                   validators=[DataRequired()])
    quantity = IntegerField("Quantity: ", validators=[DataRequired()])
    active = BooleanField("Active", default=True)
    picture = FileField("Product picture: ")
    submit = SubmitField("Add product")


class CategoryForm(FlaskForm):
    name = StringField("Name: ", validators=[DataRequired()])
    submit = SubmitField("Add category")


@app.route('/category/<string:category_slug>')
@app.route('/')
def index(category_slug=None):
    products = Product.query.filter(Product.active == 1)
    if category_slug:
        try:
            products = Product.query.filter(Product.active == 1).join(Category).filter(Category.slug == category_slug)
            if products.first():
                return render_template('store/index.html', products=products, category=products.first().category.name)
            return render_template('store/index.html', empty_query=True)
        except Exception as e:
            print(e)
    return render_template('store/index.html', products=products)


@app.route('/product/add', methods=["GET", "POST"])
def add_product():
    form = ProductForm()
    if form.validate_on_submit():
        try:
            if request.files['picture'].filename:
                loaded_picture_name = secure_filename(request.files['picture'].filename)
                picture_name_to_save = str(uuid.uuid1()) + "_" + loaded_picture_name
                form.picture.data.save(os.path.join(app.config['UPLOAD_FOLDER'], picture_name_to_save))
            else:
                picture_name_to_save = None
            product = Product(title=form.title.data,
                              description=form.description.data,
                              price=form.price.data,
                              category_id=int(form.category_id.raw_data[0]),
                              quantity=form.quantity.data,
                              active=form.active.data,
                              picture=picture_name_to_save)
            db.session.add(product)
            db.session.commit()
            flash('Product added successfully!')
            return render_template('store/product/add_product.html')
        except Exception as e:
            db.session.rollback()
            print(e)

    return render_template('store/add_product.html', form=form)


@app.route('/category/add', methods=["GET", "POST"])
def add_category():
    form = CategoryForm()
    if form.validate_on_submit():
        try:
            category = Category(name=form.name.data)
            db.session.add(category)
            db.session.commit()
            flash('Category added successfully!')
            return render_template('store/add_category.html')
        except Exception as e:
            db.session.rollback()
            print(e)

    return render_template('store/add_category.html', form=form)


@app.route('/about')
def about():
    return render_template('store/about.html')


if __name__ == '__main__':
    app.run(debug=True)
