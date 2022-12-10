import os
import uuid
from datetime import datetime

from flask import Flask, render_template, flash, request, redirect, url_for, session
from flask_login import UserMixin, LoginManager, current_user, login_user, login_required, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from slugify import slugify
from sqlalchemy.exc import NoResultFound
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from wtforms import SubmitField, StringField, IntegerField, BooleanField, TextAreaField, FileField, PasswordField, \
    SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo, InputRequired, NumberRange
from wtforms_alchemy import QuerySelectField

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'DEVELOPMENT'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'store.db')
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'static\\images\\')
login_manager = LoginManager(app)
db = SQLAlchemy(app)
CART_SESSION_ID = 'cart'


# Models
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


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(500), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    date = db.Column(db.Integer, default=datetime.utcnow)

    def __repr__(self):
        return f"<User {self.id} - {self.first_name} {self.last_name}>"


@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(user_id)


# Context processors
@app.context_processor
def inject_sidebar():
    return dict(sidebar_categories=Category.query.order_by(Category.name))


@app.context_processor
def inject_cart_total_quantity():
    try:
        total_quantity = sum(item['quantity'] for item in session['cart'].values())
        return dict(total_quantity=total_quantity)
    except:
        return dict(total_quantity=0)


# Forms
class RegisterForm(FlaskForm):
    first_name = StringField("First name: ", validators=[DataRequired()])
    last_name = StringField("Last name: ", validators=[DataRequired()])
    email = StringField("Email: ", validators=[Email(), DataRequired()])
    password1 = PasswordField("Password: ", validators=[DataRequired(), Length(min=4, max=100)])
    password2 = PasswordField("Confirm password: ",
                              validators=[DataRequired(), EqualTo('password1', message='Passwords do not match.')])
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = StringField("Email: ", validators=[Email()])
    password = PasswordField("Password: ", validators=[DataRequired(), Length(min=4, max=100)])
    remember = BooleanField("Remember me", default=False)
    submit = SubmitField("Login")


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


class CartAddProductForm(FlaskForm):
    quantity = SelectField(coerce=int, validators=[InputRequired(), NumberRange(min=1)],
                           choices=[('1', 1), ('2', 2), ('3', 3), ('4', 4), ('5', 5)])
    submit = SubmitField('Add to cart')


# Views
@app.route('/category/<string:category_slug>')
@app.route('/')
def index(category_slug=None):
    products = Product.query.filter(Product.active == 1)
    cart_add_form = CartAddProductForm()
    if category_slug:
        try:
            products = Product.query.filter(Product.active == 1).join(Category).filter(Category.slug == category_slug)
            if products.first():
                return render_template('store/index.html', products=products, category=products.first().category.name)
            return render_template('store/index.html', empty_query=True)
        except Exception as e:
            print(e)
    return render_template('store/index.html',
                           products=products,
                           form=cart_add_form)


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


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        try:
            password_hash = generate_password_hash(form.password1.data)
            user = User(email=form.email.data,  # type: ignore
                        password=password_hash,  # type: ignore
                        first_name=form.first_name.data,  # type: ignore
                        last_name=form.last_name.data)  # type: ignore
            db.session.add(user)
            db.session.commit()
            flash("You have successfully registered!", category='success')
            return redirect(url_for('login'))

        except Exception as e:
            db.session.rollback()
            print(e)
            flash("Registration error", category='error')

    return render_template('auth/register.html', title='Register', form=form)


@app.route("/login", methods=["POST", "GET"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(email=form.email.data).one()
            if user and check_password_hash(user.password, form.password.data):
                rm = form.remember.data
                login_user(user, remember=rm)
                flash("Logged in successfully")
                return redirect(request.args.get('next') or url_for('dashboard'))
            else:
                flash('Incorrect username and/or password entered', category='error')
        except NoResultFound:
            flash('Incorrect username and/or password entered', category='error')

    return render_template('auth/login.html', title='Authorization', form=form)


@app.route('/logout')
@login_required
def logout():
    """Logout the current user."""
    logout_user()
    flash('Logged out successfully', category='success')
    return redirect(url_for('login'))


@app.route('/dashboard', methods=["GET", "POST"])
@login_required
def dashboard():
    form = RegisterForm()
    user_id = current_user.id
    user_to_update = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user_to_update.first_name = form.first_name.data
        user_to_update.last_name = form.last_name.data
        user_to_update.email = form.email.data
        try:
            db.session.commit()
            flash('User updated successfully')
            return render_template('auth/dashboard.html',
                                   form=form,
                                   user_to_update=user_to_update)
        except Exception as e:
            print(e)
            flash('Error! Looks like there was a problem... try again!')
            return render_template('auth/dashboard.html',
                                   form=form,
                                   user_to_update=user_to_update)

    return render_template('auth/dashboard.html',
                           form=form,
                           user_to_update=user_to_update,
                           user_id=user_id)


class Cart:
    def __init__(self, session):
        self.session = session
        cart = session.get(CART_SESSION_ID)
        if not cart:
            self.session[CART_SESSION_ID] = {}
            cart = self.session[CART_SESSION_ID]
        self.cart = cart

    def add(self, product: Product, quantity=1, update_quantity=False):
        product_id = str(product.id)

        if product_id not in self.cart:
            self.cart[product_id] = {'quantity': 0,
                                     'price': product.price}

        if update_quantity:
            self.cart[product_id]['quantity'] = quantity
        else:
            self.cart[product_id]['quantity'] += quantity

        self.save()

    def save(self):
        self.session.modified = True

    def remove(self, product: Product):
        product_id = str(product.id)
        if product_id in self.cart:
            del self.cart[product_id]
            self.save()

    def __iter__(self):
        product_ids = list(map(int, self.cart.keys()))

        products = Product.query.filter(Product.id.in_(product_ids))

        for product in products:
            self.cart[str(product.id)]['product'] = product

        for item in self.cart.values():
            item['total_price'] = round(int(item['price']) / 100 * int(item['quantity']), 2)  # in cents
            yield item

    def __len__(self):
        """Counting all items in the cart."""
        try:
            return sum(item['quantity'] for item in self.cart.values())
        except AttributeError:
            return 0

    def get_total_price(self):
        """Calculate the cost of items in the shopping cart."""
        return round(sum(int(item['price']) / 100 * int(item['quantity']) for item in self.cart.values()), 2)

    def clear(self):
        """ Delete cart from session"""
        del self.session[CART_SESSION_ID]
        self.session.modified = True


@app.route('/cart/add/', methods=['POST'])
def cart_add():
    if request.method == 'POST':
        cart = Cart(session)
        product_id = request.form['product_id']
        product = Product.query.get_or_404(int(product_id))
        cart.add(product=product,
                 quantity=int(request.form['quantity']),
                 update_quantity=bool(request.form['update_quantity']))

        return redirect(url_for('cart_detail'))


@app.route('/cart/remove/', methods=['POST'])
def cart_remove():
    cart = Cart(session)
    product_id = request.form['product_id']
    product = Product.query.get_or_404(int(product_id))
    cart.remove(product)
    return redirect(url_for('cart_detail'))


@app.route('/cart/detail/', methods=['GET', 'POST'])
def cart_detail():
    cart = Cart(session)
    form = ProductForm()
    return render_template('store/cart_detail.html', cart=cart, form=form)


if __name__ == '__main__':
    app.run(debug=True)
