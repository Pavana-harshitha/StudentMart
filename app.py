from flask import Flask, render_template, redirect, session, url_for, jsonify, request, flash
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError, Email
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import String, Column, Integer
import os
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from random import randint
from flask_marshmallow import Marshmallow
from marshmallow import fields
from werkzeug.utils import secure_filename
from flask_migrate import Migrate



app = Flask(__name__)
app.config['SECRET_KEY'] = 'privatekey'
  

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
ma=Marshmallow(app)
migrate = Migrate(app, db)


app.config["MAIL_SERVER"] = 'smtp.gmail.com'
app.config["MAIL_PORT"] = 465
app.config["MAIL_USERNAME"] = 'studentmart32@gmail.com'
app.config['MAIL_PASSWORD'] = 'zdze nziw jeex jlvf'  
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_DEFAULT_SENDER'] = 'studentmart32@gmail.com'
mail = Mail(app)

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)


class Listing(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(255))
    purchased_date = db.Column(db.String(50))
    price = db.Column(db.Float, nullable=False)
    ad_description = db.Column(db.Text)
    name = db.Column(db.String(255), nullable=False)
    mobile = db.Column(db.String(10), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    images = db.Column(db.String(500))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sold = db.Column(db.Boolean, default=False, nullable=False)
    pending = db.Column(db.Boolean, default=False)
    buyer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  

    # Specify foreign_keys explicitly
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('listings', lazy=True))
    buyer = db.relationship('User', foreign_keys=[buyer_id], backref='purchased_items')


class Wishlist(db.Model):
    __tablename__ = 'wishlist'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('listing.id'), nullable=False)

    # Relationships
    user = db.relationship('User', backref=db.backref('wishlist', lazy=True))
    product = db.relationship('Listing', backref=db.backref('wishlisted_by', lazy=True))


class Cart(db.Model):
    __tablename__ = 'cart'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('listing.id'), nullable=False)

    # Relationships
    user = db.relationship('User', backref=db.backref('cart', lazy=True))
    product = db.relationship('Listing', backref=db.backref('cart_items', lazy=True))


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=20)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Get OTP')

    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError("Username already exists. Choose another.")

    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError("Email already registered. Choose another.")

class OTPForm(FlaskForm):
    otp = StringField('Enter OTP', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify OTP')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=20)])
    submit = SubmitField('Login')


class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Reset')

class ResetPasswordForm(FlaskForm):
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Reset Password')


class Donation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    mobile = db.Column(db.String(20), nullable=False)
    state=db.Column(db.String(20), nullable=True)
    pincode = db.Column(db.String(10), nullable=False)
    address = db.Column(db.Text, nullable=False)
    landmark = db.Column(db.String(255), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    approx_books = db.Column(db.Integer, nullable=False)
    carton_boxes = db.Column(db.Integer, default=0)
    categories = db.Column(db.Text, default=None)
    terms_accepted = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    user = db.relationship('User', backref=db.backref('donations', lazy=True))
    orphanage_id = db.Column(db.Integer, db.ForeignKey('orphanage.id'))  # Foreign key
    orphanage = db.relationship('Orphanage', backref='donations')  # Relationship to the Orphanage model

class Orphanage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    orphanage_name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    mobile = db.Column(db.String(20), nullable=False)
    state = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    pincode = db.Column(db.String(10), nullable=False)
    address = db.Column(db.Text)
    orphanage_type = db.Column(db.String(100), nullable=False)



class UserSchema(ma.Schema):
    class Meta:
        fields=('id','username','email')

users_schema=UserSchema(many=True)


class ProductSchema(ma.Schema):
    is_owner = fields.Method("get_is_owner")  # Add a custom field

    class Meta:
        fields = (
            'id', 'title', 'category', 'author', 
            'purchased_date', 'price', 'ad_description',
            'name', 'city', 'images', 'is_owner'  # Include is_owner
        )

    def get_is_owner(self, obj):
        """Returns True if the logged-in user is the owner of the product"""
        user_id = self.context.get("user_id")  # Get user_id from context
        return obj.user_id == user_id  # Compare with product owner

# Initialize schema
products_schema = ProductSchema(many=True)

def send_otp(email):
    otp = str(randint(100000, 999999))  
    session['otp'] = otp  
    session['reset_email'] = email  
    session['otp_verified'] = False 

    msg = Message('Password Reset OTP', sender='studentmart32@gmail.com', recipients=[email])
    msg.body = f'Your OTP for resetting your password is: {otp}. Do not share it with anyone.'
    mail.send(msg)


def get_current_user():
    user_id = session.get("user_id")  # Get user ID from session
    if user_id:
        return db.session.get(User, user_id)  # Use db.session.get() instead of query.get()
    return None  # No user logged in


def create_admin():
    with app.app_context():
        db.create_all()  
        admin = Admin.query.filter_by(username="studentmart").first()
        if not admin:
             
            hashed_password = bcrypt.generate_password_hash("22bq1a05").decode('utf-8')
            new_admin = Admin(username="studentmart", password=hashed_password)
            db.session.add(new_admin)
            db.session.commit()
           

create_admin() 

@app.route('/')
@app.route('/home')
def home():
    user_loggedin = "user_id" in session 
    username = None
    if user_loggedin:
        user = User.query.get(session["user_id"])
        if user:
            username = user.username 
    return render_template('HomePage1.html', user_loggedin=user_loggedin, username=username)

@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        otp = str(randint(100000, 999999))  
        session['otp'] = otp  
        session['registration_data'] = {'username': form.username.data, 'email': form.email.data, 'password': form.password.data}

        msg = Message('Your OTP Code', sender='studentmart32@gmail.com', recipients=[form.email.data])
        msg.body = f'Your OTP is: {otp}. Do not share it with anyone.'
        mail.send(msg)

        flash('An OTP has been sent to your email. Please enter it to complete registration.', 'info')
        return redirect(url_for('verify_otp'))

    return render_template('user_signup.html', form=form)

@app.route('/verify_otp', methods=['POST', 'GET'])
def verify_otp():
    form = OTPForm()
    if form.validate_on_submit():
        if 'otp' in session and session['otp'] == form.otp.data:
            data = session.pop('registration_data', None)  
            hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

            new_user = User(username=data['username'], email=data['email'], password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            session.pop('otp', None) 
            flash('Account created successfully. You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')

    return render_template('verify_otp.html', form=form)


@app.route("/check_email", methods=["POST"])
def check_email():
    email = request.form.get("email")

    if not email:
        return jsonify({"success": False, "error": "Email is required"}), 400

    user = User.query.filter_by(email=email).first()

    if user:
        return jsonify({"success": False, "error": "Email already registered"}), 200
    else:
        return jsonify({"success": True, "message": "Email available"}), 200
    
    
@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        admin = Admin.query.filter_by(username=form.username.data).first()
        if admin and bcrypt.check_password_hash(admin.password, form.password.data):
            session["admin_id"] = admin.id  
            flash("Admin login successful!", "success")
            return redirect(url_for('admin_dashboard')) 
        
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            session["user_id"] = user.id  
            flash("User login successful!", "success")
            return redirect(url_for('home')) 
        
        flash("Invalid username or password", "danger")

    return render_template('login.html', form=form)

@app.route('/admin')
def admin_dashboard():
    if "admin_id" not in session:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('login'))
    return render_template('admin_dashboard.html')  # Create an admin dashboard template

@app.route('/manage_users')
def manage_users():
    if "admin_id" not in session:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('login'))

    users = User.query.all()
    return render_template('manage_users.html', users=users)


@app.route('/manage_products')
def manage_products():
    if "admin_id" not in session:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('login'))

    # Fetch all products along with the user who uploaded them
    products = db.session.query(Listing, User.username).join(User, Listing.user_id == User.id).all()
    return render_template('manageproducts.html', products=products)

@app.route('/delete_product/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    if "admin_id" not in session:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('login'))

    # Fetch the product by ID
    product = Listing.query.get_or_404(product_id)

    # Delete the product from the database
    db.session.delete(product)
    db.session.commit()

    flash('Product deleted successfully!', 'success')
    return redirect(url_for('manage_products'))

@app.route('/add_an_orphanage', methods=['POST', 'GET'])
def add_an_orphanage():
    if "admin_id" not in session:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        print("Form Data:", request.form)  # Debugging

        # Fetch data safely
        orphanage_name = request.form.get('orphanage_name')
        email = request.form.get('email')
        mobile = request.form.get('mobile')
        state = request.form.get('state')
        city = request.form.get('city')
        pincode = request.form.get('pincode')
        address = request.form.get('address')
        orphanage_type = request.form.get('orphanage_type')

        # Validate inputs
        if not orphanage_name:
            flash("Orphanage Name is required!", "danger")
            return redirect(url_for('add_an_orphanage'))
        if not email:
            flash("Email is required!", "danger")
            return redirect(url_for('add_an_orphanage'))
        if not mobile or not mobile.isdigit() or len(mobile) != 10:
            flash("Invalid mobile number. Must be 10 digits.", "warning")
            return redirect(url_for('add_an_orphanage'))
        if not pincode or not pincode.isdigit() or len(pincode) != 6:
            flash("Invalid pincode. Must be 6 digits.", "warning")
            return redirect(url_for('add_an_orphanage'))
        if orphanage_type == "":
            flash("Please select a valid orphanage type.", "warning")
            return redirect(url_for('add_an_orphanage'))

        # Check if email already exists
        existing_orphanage = Orphanage.query.filter_by(email=email).first()
        if existing_orphanage:
            flash("This orphanage is already registered!", "warning")
            return redirect(url_for('add_an_orphanage'))

        # Create a new orphanage record
        new_orphanage = Orphanage(
            orphanage_name=orphanage_name,
            email=email,
            mobile=mobile,
            state=state,
            city=city,
            pincode=pincode,
            address=address,
            orphanage_type=orphanage_type
        )

        db.session.add(new_orphanage)
        db.session.commit()
        return render_template("successfully_Added.html")

    return render_template("orphanage_form.html")


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()

        if user:
            send_otp(email)  
            return redirect(url_for('reset_password')) 
        else:
            flash('Email not found in our records. Please register first.', 'danger')

    return render_template('forgot_password.html', form=form)



@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_email' not in session:
        flash('Unauthorized access. Please request password reset again.', 'warning')
        return redirect(url_for('forgot_password'))

    form = ResetPasswordForm()
    if request.method == 'POST':
        if 'otp' in request.form:  
            user_otp = request.form.get('otp')
            if 'otp' in session and session['otp'] == user_otp:
                session['otp_verified'] = True  
                flash('OTP verified successfully!', 'success')
            else:
                flash('Invalid OTP! Please try again.', 'danger')
        elif form.validate_on_submit():  
            if session.get('otp_verified'):
                new_password_hash = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
                
                email = session['reset_email']

                user = User.query.filter_by(email=email).first()
                if user:
                    user.password = new_password_hash
                    db.session.commit()

                    session.pop('reset_email', None)
                    session.pop('otp_verified', None)
                    session.pop('otp', None)

                    flash('Your password has been updated successfully!', 'success')
                    return redirect(url_for('login'))
                else:
                    flash('Something went wrong! Try again.', 'danger')
            else:
                flash('OTP verification is required to reset the password.', 'danger')

    return render_template('reset_password.html', form=form, otp_verified=session.get('otp_verified', False))






@app.route('/profile')
def profile():
    user = get_current_user()
    if not user:  
        return redirect(url_for('login'))  # Redirect if not logged in

    return render_template('profile.html', user_loggedin=True, username=user.username, email=user.email)


@app.route('/update_profile', methods=['POST'])
def update_profile():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')

    # Update the database (example logic)
    user = User.query.filter_by(email=email).first()
    if user:
        user.username = username
        db.session.commit()
        return jsonify({"success": True, "message": "Profile updated successfully!"})
    else:
        return jsonify({"success": False, "message": "User not found."}), 404


@app.route('/add_to_wishlist/<int:product_id>')
def add_to_wishlist(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    user_id = session.get('user_id')

    # Check if product is already in wishlist
    existing_item = Wishlist.query.filter_by(user_id=user_id, product_id=product_id).first()
    if existing_item:
        return redirect(url_for('wishlist', message="Product is already in your wishlist", message_type="warning"))

    # Add new product to wishlist
    new_wishlist_item = Wishlist(user_id=user_id, product_id=product_id)
    db.session.add(new_wishlist_item)
    db.session.commit()

    return redirect(url_for('wishlist', message="Product added to your wishlist", message_type="success"))




@app.route('/wishlist')
def wishlist():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    user_id = session.get('user_id')

    # Fetch wishlist items along with related products
    wishlist_items = db.session.query(Listing).join(Wishlist, Listing.id == Wishlist.product_id).filter(Wishlist.user_id == user_id).all()

    # Get message from URL parameters
    message = request.args.get('message')
    message_type = request.args.get('message_type')

    return render_template('wishlist.html', products=wishlist_items, message=message, message_type=message_type)


@app.route('/remove_from_wishlist/<int:product_id>')
def remove_from_wishlist(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    user_id = session.get('user_id')

    # Check if product is in wishlist
    wishlist_item = Wishlist.query.filter_by(user_id=user_id, product_id=product_id).first()
    
    if wishlist_item:
        db.session.delete(wishlist_item)
        db.session.commit()
        return redirect(url_for('wishlist', message="Product removed from your wishlist", message_type="danger"))

    return redirect(url_for('wishlist', message="Product not found in your wishlist", message_type="warning"))




@app.route('/buypage', methods=['GET', 'POST'])
def buypage():
    user_id = session.get("user_id")  # Get logged-in user ID
    products = Listing.query.filter_by(sold=False).all()  # Fetch all listings

    # Set context before calling dump()
    products_schema.context = {"user_id": user_id}  
    result = products_schema.dump(products)  # Dump without passing context explicitly

    return render_template('BuyPage.html', data=result, user_id=user_id)







@app.route('/productdetails/<int:product_id>')
def productdetails(product_id):
    product = db.session.get(Listing, product_id)  # ✅ Fixed
    if not product:
        return jsonify(message="Product not found"), 404
    return render_template("detailedpage.html", product=product)

@app.route('/add_to_cart/<int:product_id>')
def add_to_cart(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    user_id = session.get('user_id')

    # Check if the product is already in the cart
    existing_item = Cart.query.filter_by(user_id=user_id, product_id=product_id).first()
    if existing_item:
        return redirect(url_for('cart', message="Product is already in your cart", message_type="warning"))

    # Add new product to cart
    new_cart_item = Cart(user_id=user_id, product_id=product_id)
    db.session.add(new_cart_item)
    db.session.commit()

    return redirect(url_for('cart', message="Product added to your cart", message_type="success"))


@app.route('/cart')
def cart():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    user_id = session.get('user_id')

    # Fetch cart items along with related product details
    cart_items = db.session.query(Listing).join(Cart, Listing.id == Cart.product_id).filter(Cart.user_id == user_id).all()

    # Calculate total price
    total_price = sum(item.price for item in cart_items)

    # Get message from URL parameters
    message = request.args.get('message')
    message_type = request.args.get('message_type')

    return render_template('cart.html', products=cart_items, total_price=total_price, message=message, message_type=message_type)



@app.route('/remove_from_cart/<int:product_id>')
def remove_from_cart(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    user_id = session.get('user_id')

    # Check if product is in cart
    cart_item = Cart.query.filter_by(user_id=user_id, product_id=product_id).first()
    
    if cart_item:
        db.session.delete(cart_item)
        db.session.commit()
        return redirect(url_for('cart', message="Product removed from your cart", message_type="danger"))

    return redirect(url_for('cart', message="Product not found in your cart", message_type="warning"))




@app.route('/checkout')
def checkout():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    cart_items = db.session.query(Listing).join(Cart, Listing.id == Cart.product_id).filter(Cart.user_id == user_id).all()

    listing_ids = ",".join([str(item.id) for item in cart_items])
    
    return render_template('checkoutform.html', listing_ids=listing_ids, user=User.query.get(user_id))



def send_email_to_seller(seller_email, name, listing, city):
    subject = "New Order Request for Your Product"
    body = f"""
    Hello,

    A buyer is interested in purchasing your product: {listing.title}.
    
    Buyer Details:
    - Name: {name}
    - City: {city}

    Please visit the website to confirm the order and receive the buyer's contact details.

    Regards,  
    StudentMart Team
    """

    msg = Message(subject, sender="studentmart32@gmail.com", recipients=[seller_email])
    msg.body = body
    mail.send(msg)


def send_email_to_seller_acceptance(seller_email, buyer, name, listing, mobile, city):
    subject = "Buyer Details for Your Product"
    body = f"""
    Hello,

    You have accepted a buyer for your product: {listing.title}.
    
    Buyer Details:
    - Name: {name}
    - Email: {buyer.email}
    - Phone: {mobile}
    - City: {city}

    Please contact the buyer to proceed with the sale.

    Regards,  
    StudentMart Team
    """

    msg = Message(subject, sender="studentmart32@gmail.com", recipients=[seller_email])
    msg.body = body
    mail.send(msg)


def send_email_to_buyer_rejection(buyer_email, listing):
    subject = "Your Order Request Has Been Rejected"
    body = f"""
    Hello,

    Unfortunately, your order request for the product "{listing.title}" has been rejected by the seller.

    You can explore other available products on our website.

    Regards,  
    StudentMart Team
    """

    msg = Message(subject, sender="studentmart32@gmail.com", recipients=[buyer_email])
    msg.body = body
    mail.send(msg)


def send_email_to_buyer_acceptance(buyer_email, listing):
    subject = "Your Order Request Has Been Accepted"
    body = f"""
    Hello,

    Great news! Your order request for the product "{listing.title}" has been accepted by the seller.

    Seller Details:
    - Name: {listing.name}
    - Email: {listing.user.email}
    - Phone: {listing.mobile}  
    - City: {listing.city}

    The seller will contact you soon to arrange the next steps.

    Regards,  
    StudentMart Team
    """

    msg = Message(subject, sender="studentmart32@gmail.com", recipients=[buyer_email])
    msg.body = body
    mail.send(msg)


@app.route('/process_checkout', methods=['POST'])
def process_checkout():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    buyer = User.query.get(user_id)
    if not buyer:
        return "Buyer not found!", 400

    listing_ids = request.form.get('listing_ids')
    name = request.form.get('name')
    mobile = request.form.get('phone')
    city = request.form.get('city')

    if not listing_ids:
        return "No products selected!", 400

    listing_ids = listing_ids.split(',')
    listings = Listing.query.filter(Listing.id.in_(listing_ids)).all()

    for listing in listings:
        seller = User.query.get(listing.user_id)
        if seller:
            send_email_to_seller(seller.email, name, listing, city)  # Only seller gets email

    # Remove products from Cart and Wishlist
    Cart.query.filter(Cart.user_id == user_id, Cart.product_id.in_(listing_ids)).delete(synchronize_session=False)
    Wishlist.query.filter(Wishlist.user_id == user_id, Wishlist.product_id.in_(listing_ids)).delete(synchronize_session=False)

    # Mark products as "pending" and assign buyer_id
    for listing in listings:
        listing.pending = True  # Order is pending seller approval
        listing.buyer_id = user_id  

    db.session.commit()

    return redirect(url_for('cart', message="Checkout successful! Waiting for seller approval.", message_type="info"))




@app.route('/search')
def search():
    query = request.args.get('query', '').strip().lower()
    categories = request.args.getlist('category')  
    min_price = request.args.get('min_price', 0, type=int)
    max_price = request.args.get('max_price', 2000, type=int)

    results_query = Listing.query.filter(Listing.sold == False)

    if query:
        results_query = results_query.filter(Listing.title.ilike(f"%{query}%"))

    if categories:
        results_query = results_query.filter(Listing.category.in_(categories))

    results_query = results_query.filter(Listing.price.between(min_price, max_price))
    results = results_query.all()

    user_id = session.get("user_id")
    product_schema = ProductSchema(many=True, context={"user_id": user_id})
    results2 = product_schema.dump(results)

    # If no results found, send an extra flag to template
    return render_template(
        'BuyPage.html',
        data=results2,
        filters_applied=True,
        no_results=(len(results2) == 0),
        query=query
    )



def get_products_bought_by_user(user_id):
    bought_products =Listing.query.filter(Listing.sold == 1, Listing.buyer_id == user_id).all()

    return bought_products


@app.route('/my_orders',methods=['GET'])
def my_orders():
    user = get_current_user()  
   
    products = get_products_bought_by_user(user.id)
    print(products)
    return render_template('my_orders.html', products=products)




@app.route('/sell', methods=['GET', 'POST'])
def sell():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    if request.method == 'POST':
        return redirect(url_for('buypage'))  # Redirect after form submission

    return render_template('sell.html')


def send_email_on_submission(user,title):
    try:
        subject = "Your Product Listing has been Submitted"
        body = f"""
        Hello {user.username},

        Your product named {title} has been successfully submitted to StudentMart.

        It is now available for buyers to view and purchase.

        Listing Details:
        - Seller Username: {user.username}
        - Seller Email: {user.email}
        - Seller Phone: {user.listings[-1].mobile if user.listings else 'N/A'}
        - Seller City: {user.listings[-1].city if user.listings else 'N/A'}

        If you need to make any changes, you can edit or delete your listing from your 'My Products' section.

        Regards,
        StudentMart Team
        """

        msg = Message(subject, sender="studentmart32@gmail.com", recipients=[user.email])
        msg.body = body
        mail.send(msg)
        print(f"✅ Email sent successfully to {user.email}")  # Debugging log

    except Exception as e:
        print(f"❌ Error sending email: {e}")


@app.route('/myproducts',methods=['GET'])
def my_products():
    user = get_current_user()  
    products = Listing.query.filter_by(user_id=user.id).all()
    
    return render_template('myproducts.html', products=products)



@app.route('/seller_orders')
def seller_orders():
    user = get_current_user()  # Function to get logged-in user
    if not user:
        return redirect(url_for('login'))
    
    """ Show pending orders for the seller """
    
    orders = Listing.query.filter(
    Listing.user_id == user.id, 
    Listing.pending == True  # ✅ Show only pending orders
).all()

    if not orders:
        print("No pending orders found.")
    else:
        for order in orders:
            print(order.id, order.title, order.buyer_id)


    return render_template('Seller Orders.html', orders=orders)


@app.route('/approve_order/<int:order_id>', methods=['POST'])
def approve_order(order_id):
    listing = Listing.query.get(order_id)
    
    if not listing or not listing.pending:
        return jsonify({'message': 'Invalid order or already processed!'}), 400

    # Mark the listing as sold and no longer pending
    listing.sold = True  
    listing.pending = False  

    # Fetch buyer and seller details
    buyer = User.query.get(listing.buyer_id)
    seller = User.query.get(listing.user_id)  # Get seller details

    if buyer and seller:
        send_email_to_seller_acceptance(seller.email, buyer, listing.name, listing, listing.mobile, listing.city)
        send_email_to_buyer_acceptance(buyer.email, listing)  

    db.session.commit()
    return render_template('order_approved.html', listing=listing)


    


@app.route('/reject_order/<int:order_id>', methods=['POST'])
def reject_order(order_id):
    listing = Listing.query.get(order_id)
    if not listing or not listing.pending:
        return jsonify({'message': 'Invalid order or already processed!'}), 400

    listing.pending = False  # Reset pending
    listing.buyer_id = None  # Remove assigned buyer

    # Notify Buyer (Optional)
    buyer = User.query.get(listing.buyer_id)
    if buyer:
        send_email_to_buyer_rejection(buyer.email, listing)  # Notify buyer about rejection

    db.session.commit()
    return render_template('order_rejected.html', listing=listing)





@app.route('/submit-form', methods=['POST'])
def submit_form():
    """Handles product submission"""
    title = request.form['title']
    category = request.form['category']
    author = request.form.get('author', None)
    purchased_date = request.form['purchased_date']
    price = request.form['price']
    ad_description = request.form['ad_description']
    name = request.form['name']
    mobile = request.form['mobile']
    city = request.form['city']
    images = request.files.getlist('images')

    # Save images to the uploads folder
    image_filenames = []
    upload_folder = "static/uploads"
    os.makedirs(upload_folder, exist_ok=True)

    for image in images:
        if image.filename:
            filename = secure_filename(image.filename)  # Ensure safe filenames
            image_path = os.path.join(upload_folder, filename)
            image.save(image_path)
            image_filenames.append(filename)

    # Get the currently logged-in user
    user = get_current_user()
    if not user:
        return """
        <script>
            alert("You must be logged in to submit a listing.");
            window.location.href = "/login";
        </script>
        """

    # Save listing to database
    new_listing = Listing(
        title=title, category=category, author=author, 
        purchased_date=purchased_date, price=price, ad_description=ad_description,
        name=name, mobile=mobile, city=city, images=",".join(image_filenames),
        user_id=user.id  # Correctly assigning user_id
    )
    db.session.add(new_listing)
    db.session.commit()

    # Send email notification to seller with error handling
    try:
        send_email_on_submission(user,title)

    except Exception as e:
        print("Error sending email:", e)  # Debugging purpose

    # Return alert message and redirect to My Products page
    return """
    <script>
        alert("Product submitted successfully!");
        window.location.href = "/myproducts";
    </script>
    """

@app.route('/edit-listing/<int:product_id>', methods=['POST'])
def edit_listing(product_id):
    user = get_current_user()
    if not user:
        return jsonify({"message": "Unauthorized access"}), 403

    product = Listing.query.filter_by(id=product_id, user_id=user.id).first()
    if not product:
        return jsonify({"message": "Product not found"}), 404

    data = request.json
    product.title = data.get('title', product.title)
    product.price = data.get('price', product.price)

    db.session.commit()  # ✅ Saves changes to the database
    return jsonify({"message": "Product updated successfully!"})


@app.route('/delete-listing/<int:product_id>', methods=['POST'])
def delete_listing(product_id):
    user = get_current_user()
    if not user:
        return jsonify({"message": "Unauthorized access"}), 403

    product = Listing.query.filter_by(id=product_id, user_id=user.id).first()
    if not product:
        return jsonify({"message": "Product not found"}), 404

    db.session.delete(product)
    db.session.commit()  # ✅ Deletes from the database
    return jsonify({"message": "Product deleted successfully!"})


@app.route('/donate')
def donate():
    return render_template('bookdonationpage.html')


@app.route('/donate_form', methods=['POST', 'GET'])
def donate_form():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))

    # Fetch orphanages from the database
    orphanages = Orphanage.query.all()  # Assuming you have an Orphanage model

    return render_template('donation_form.html', orphanages=orphanages)


def send_email_orphanage(to, subject, body):
    try:
        msg = Message(subject, recipients=[to])
        msg.body = body
        mail.send(msg)
        print("✅ Email sent successfully!")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")

@app.route('/submit_donation', methods=['GET', 'POST'])
def submit_donation():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))

    # Collect form data
    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')
    mobile = request.form.get('mobile')
    email = request.form.get('email')
    state = request.form.get('state')
    city = request.form.get('city')
    pincode = request.form.get('pincode')
    address = request.form.get('address')
    landmark = request.form.get('landmark')
    approx_books = request.form.get('approxBooks')
    carton_boxes = request.form.get('cartonBoxes')
    terms_accepted = bool(request.form.get('terms'))
    orphanage_id = request.form.get('orphanage_id')
    categories = ','.join(request.form.getlist('category'))

    # Validate required fields
    if not (first_name and last_name and email and orphanage_id and state):
        flash("Please fill all required fields", "error")
        return redirect(url_for('donate_form'))

    orphanage = Orphanage.query.get(orphanage_id)
    if not orphanage:
        flash("Invalid orphanage selection.", "error")
        return redirect(url_for('donate_form'))

    # Create a new donation entry
    new_donation = Donation(
        user_id=user.id,
        first_name=first_name,
        last_name=last_name,
        state=state,
        email=email,
        mobile=mobile,
        city=city,
        pincode=pincode,
        address=address,
        landmark=landmark,
        approx_books=approx_books,
        carton_boxes=carton_boxes,
        terms_accepted=terms_accepted,
        orphanage_id=orphanage_id,
        categories=categories
    )

    try:
        db.session.add(new_donation)
        db.session.commit()
        flash("Donation submitted successfully!", "success")

        print(f"✅ Donation stored successfully! Assigned to: {orphanage.orphanage_name}")

        # Send Email to Assigned Orphanage
        subject = "New Book Donation Available"
        body = f"""Dear {orphanage.orphanage_name} Team,

A new book donation has been received and assigned to you.

📌 **Donor Details:**
- Name: {first_name} {last_name}
- Email: {email}
- Mobile: {mobile}
- Address: {address}, {city}, {pincode}
- Landmark: {landmark}
- Approximate Books: {approx_books}
- Carton Boxes: {carton_boxes}
- Categories: {categories if categories else 'Not specified'}

Please reach out if you are interested in collecting these books.

Best Regards,  
**StudentMart Team**
"""
        send_email_orphanage(orphanage.email, subject, body)

        return redirect(url_for('donation_success'))

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Database error: {e}")
        flash("An error occurred. Please try again later.", "error")
        return redirect(url_for('donate_form'))




@app.route('/donation_success')
def donation_success():
    return render_template('successfully_Added.html')  # Render a success page


@app.route('/my_donations',methods=['GET'])
def my_donations():
    user = get_current_user()  
    donation = Donation.query.filter_by(user_id=user.id).all()
    
    return render_template('my_donations.html', donation=donation)



@app.route('/product_request',methods=['GET','POST'])
def product_request():
    return render_template('product_form.html')


@app.route('/submit_request', methods=['POST'])
def submit_request():
    # Collect data from the form
    first_name = request.form['first-name']
    last_name = request.form['last-name']
    email = request.form['email']
    product_type = request.form['product-type']
    product_name = request.form['product-name']
    description = request.form['description']

    # Create a message to be sent
    subject = f"New Product Request: {product_name}"
    body = f"""
    A new product request has been made by {first_name} {last_name}.

    Details:
    - Product Type: {product_type}
    - Product Name: {product_name}
    - Description: {description}

    Contact Information:
    - Email: {email}
    """

    # Query all user emails from the User table
    users = User.query.all()
    user_emails = [user.email for user in users]

    # Send the email to all users
    with mail.connect() as conn:
        for user_email in user_emails:
            message = Message(
                subject,
                recipients=[user_email],
                sender="studentmart32@gmail.com",
                body=body
            )
            conn.send(message)

    return render_template("request_submitted.html")

 


#@app.route('/db_create')
#def db_create():
#   db.create_all()
 #   return jsonify(msg='Database created')
 
@app.route('/logout')
def logout():
    session.pop("user_id", None)  
    session.pop("admin_id", None)  
    flash("Logged out successfully", "info")
    return redirect(url_for('home'))


@app.route('/db_destroy')
def db_destroy():
    db.drop_all()
    return jsonify(msg='Database dropped')

if __name__ == '__main__':
    with app.app_context():  
        db.create_all()
        create_admin()  
    app.run(debug=True)


