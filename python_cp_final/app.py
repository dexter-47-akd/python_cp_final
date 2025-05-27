from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, Regexp
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import google.generativeai as genai
from flask_mail import Mail, Message
from twilio.rest import Client
from dotenv import load_dotenv
from flask_migrate import Migrate

# Load environment variables
load_dotenv()

# Configure Google Generative AI
genai.configure(api_key=os.getenv('GOOGLE_AI_API_KEY'))
model = genai.GenerativeModel(
    model_name="gemini-pro",
    generation_config={
        "temperature": 0.9,
        "top_p": 1,
        "top_k": 1,
        "max_output_tokens": 2048,
    },
    safety_settings=[
        {
            "category": "HARM_CATEGORY_HARASSMENT",
            "threshold": "BLOCK_MEDIUM_AND_ABOVE"
        },
        {
            "category": "HARM_CATEGORY_HATE_SPEECH",
            "threshold": "BLOCK_MEDIUM_AND_ABOVE"
        },
        {
            "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
            "threshold": "BLOCK_MEDIUM_AND_ABOVE"
        },
        {
            "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
            "threshold": "BLOCK_MEDIUM_AND_ABOVE"
        }
    ]
)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')  # Fallback for development
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///railway.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = ('Indian Railways', os.getenv('MAIL_USERNAME'))
app.config['MAIL_DEBUG'] = True  # Enable debug mode for email

# Initialize Flask-Mail
mail = Mail(app)

# Initialize Twilio client
twilio_account_sid = 'AC453afb3c5ac916aaa84c698dbe71a90d'
twilio_auth_token = 'a59c7cf0155091f83d467d4a84180f45'
twilio_whatsapp_number = '+14155238886'

try:
    twilio_client = Client(twilio_account_sid, twilio_auth_token)
    print("Twilio client initialized successfully")
except Exception as e:
    print(f"Error initializing Twilio client: {str(e)}")
    twilio_client = None

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Form Classes
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone_number = StringField('Phone Number', validators=[
        DataRequired(),
        Length(min=10, max=15),
        Regexp(r'^\+?1?\d{9,15}$', message='Please enter a valid phone number')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')

    def validate_phone_number(self, phone_number):
        user = User.query.filter_by(phone_number=phone_number.data).first()
        if user:
            raise ValidationError('That phone number is already registered.')

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    phone_number = db.Column(db.String(20), nullable=True)
    bookings = db.relationship('Booking', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Station(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(10), unique=True, nullable=False)
    city = db.Column(db.String(50), nullable=False)
    
class Train(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    train_number = db.Column(db.String(20), unique=True, nullable=False)
    source_id = db.Column(db.Integer, db.ForeignKey('station.id'), nullable=False)
    destination_id = db.Column(db.Integer, db.ForeignKey('station.id'), nullable=False)
    departure_time = db.Column(db.DateTime, nullable=False)
    arrival_time = db.Column(db.DateTime, nullable=False)
    total_seats = db.Column(db.Integer, nullable=False)
    
    source = db.relationship('Station', foreign_keys=[source_id])
    destination = db.relationship('Station', foreign_keys=[destination_id])
    seats = db.relationship('Seat', backref='train', lazy=True)

class Seat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    train_id = db.Column(db.Integer, db.ForeignKey('train.id'), nullable=False)
    seat_number = db.Column(db.String(10), nullable=False)
    seat_type = db.Column(db.String(20), nullable=False)  # e.g., "Window", "Aisle", "Middle"
    coach = db.Column(db.String(5), nullable=False)
    is_available = db.Column(db.Boolean, default=True)
    price = db.Column(db.Float, nullable=False)
    
class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    train_id = db.Column(db.Integer, db.ForeignKey('train.id'), nullable=False)
    seat_id = db.Column(db.Integer, db.ForeignKey('seat.id'), nullable=False)
    booking_date = db.Column(db.DateTime, default=datetime.utcnow)
    journey_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(20), default='Confirmed')
    passenger_name = db.Column(db.String(100), nullable=False)
    
    # Define relationships
    train = db.relationship('Train', backref='bookings')
    seat = db.relationship('Seat', backref='bookings')

# Create database tables
with app.app_context():
    # Drop all tables and recreate them
    db.drop_all()
    db.create_all()
    
    # Add sample data if database is empty
    if not Station.query.first():
        # Add stations
        stations = [
            # Northern Region
            Station(name='New Delhi Railway Station', code='NDLS', city='Delhi'),
            Station(name='Mumbai Central', code='MMCT', city='Mumbai'),
            Station(name='Chennai Central', code='MAS', city='Chennai'),
            Station(name='Howrah Junction', code='HWH', city='Kolkata'),
            Station(name='Bengaluru City Junction', code='SBC', city='Bengaluru'),
            Station(name='Jaipur Junction', code='JP', city='Jaipur'),
            Station(name='Lucknow Junction', code='LKO', city='Lucknow'),
            Station(name='Raipur Junction', code='R', city='Raipur'),
            Station(name='Nagpur Junction', code='NGP', city='Nagpur'),
            
            # North-Eastern Region
            Station(name='Guwahati Junction', code='GHY', city='Guwahati'),
            Station(name='Imphal Railway Station', code='IMPL', city='Imphal'),
            Station(name='Shillong Railway Station', code='SHL', city='Shillong'),
            Station(name='Aizawl Railway Station', code='AZL', city='Aizawl'),
            Station(name='Agartala Railway Station', code='AGTL', city='Agartala'),
            Station(name='Kohima Railway Station', code='KOH', city='Kohima'),
            Station(name='Itanagar Railway Station', code='ITNR', city='Itanagar'),
            
            # Other Major Cities
            Station(name='Ahmedabad Junction', code='ADI', city='Ahmedabad'),
            Station(name='Surat Junction', code='ST', city='Surat'),
            Station(name='Bhopal Junction', code='BPL', city='Bhopal'), 
            Station(name='Hyderabad Junction', code='HYB', city='Hyderabad'),
            Station(name='Pune Junction', code='PUNE', city='Pune'),
            Station(name='Kota Junction', code='KOTA', city='Kota'),
            Station(name='Indore Junction', code='INDB', city='Indore'),
            Station(name='Bhubaneswar Junction', code='BBS', city='Bhubaneswar'),
            Station(name='Visakhapatnam Junction', code='VSKP', city='Visakhapatnam'),
            Station(name='Kanpur Central', code='CNB', city='Kanpur'),
            Station(name='Varanasi Junction', code='BSB', city='Varanasi'),
            Station(name='Patna Junction', code='PNBE', city='Patna'),
            Station(name='Amritsar Junction', code='ASR', city='Amritsar'),
            Station(name='Jammu Tawi', code='JAT', city='Jammu'),
            Station(name='Thiruvananthapuram Central', code='TVC', city='Thiruvananthapuram'),
            Station(name='Kochi Junction', code='ERS', city='Kochi')
        ]
        db.session.add_all(stations)
        db.session.commit()
        
        # Add trains
        trains = [
            Train(
                name='Rajdhani Express', 
                train_number='12301',
                source_id=1,  # Delhi
                destination_id=2,  # Mumbai
                departure_time=datetime.strptime('2023-06-01 16:00:00', '%Y-%m-%d %H:%M:%S'),
                arrival_time=datetime.strptime('2023-06-02 08:00:00', '%Y-%m-%d %H:%M:%S'),
                total_seats=72
            ),
            Train(
                name='Shatabdi Express', 
                train_number='12002',
                source_id=1,  # Delhi
                destination_id=5,  # Bengaluru
                departure_time=datetime.strptime('2023-06-01 06:00:00', '%Y-%m-%d %H:%M:%S'),
                arrival_time=datetime.strptime('2023-06-02 22:00:00', '%Y-%m-%d %H:%M:%S'),
                total_seats=60
            ),
            Train(
                name='Duronto Express', 
                train_number='12259',
                source_id=4,  # Howrah/Kolkata
                destination_id=3,  # Chennai
                departure_time=datetime.strptime('2023-06-01 20:00:00', '%Y-%m-%d %H:%M:%S'),
                arrival_time=datetime.strptime('2023-06-02 18:00:00', '%Y-%m-%d %H:%M:%S'),
                total_seats=72
            ),
            Train(
                name='Humsafar Express',
                train_number='12275', 
                source_id=2,  # Mumbai
                destination_id=20,  # Hyderabad
                departure_time=datetime.strptime('2023-06-01 23:00:00', '%Y-%m-%d %H:%M:%S'),
                arrival_time=datetime.strptime('2023-06-02 15:00:00', '%Y-%m-%d %H:%M:%S'),
                total_seats=60
            ),
            Train(
                name='Garib Rath Express',
                train_number='12203',
                source_id=1,  # Delhi 
                destination_id=28,  # Patna
                departure_time=datetime.strptime('2023-06-01 07:00:00', '%Y-%m-%d %H:%M:%S'),
                arrival_time=datetime.strptime('2023-06-02 04:00:00', '%Y-%m-%d %H:%M:%S'),
                total_seats=72
            ),
            Train(
                name='Vande Bharat Express',
                train_number='12280',
                source_id=17,  # Ahmedabad
                destination_id=20,  # Pune
                departure_time=datetime.strptime('2023-06-01 06:00:00', '%Y-%m-%d %H:%M:%S'),
                arrival_time=datetime.strptime('2023-06-01 14:00:00', '%Y-%m-%d %H:%M:%S'),
                total_seats=60
            ),
            Train(
                name='Northeast Express',
                train_number='12505',
                source_id=10,  # Guwahati
                destination_id=1,  # Delhi
                departure_time=datetime.strptime('2023-06-01 16:30:00', '%Y-%m-%d %H:%M:%S'),
                arrival_time=datetime.strptime('2023-06-03 06:00:00', '%Y-%m-%d %H:%M:%S'),
                total_seats=72
            ),
            Train(
                name='Kerala Express',
                train_number='12625',
                source_id=31,  # Thiruvananthapuram
                destination_id=32,  # Kochi
                departure_time=datetime.strptime('2023-06-01 08:00:00', '%Y-%m-%d %H:%M:%S'),
                arrival_time=datetime.strptime('2023-06-01 12:00:00', '%Y-%m-%d %H:%M:%S'),
                total_seats=60
            ),
            Train(
                name='Deccan Queen',
                train_number='12124',
                source_id=20,  # Pune
                destination_id=2,  # Mumbai
                departure_time=datetime.strptime('2023-06-01 07:15:00', '%Y-%m-%d %H:%M:%S'),
                arrival_time=datetime.strptime('2023-06-01 10:25:00', '%Y-%m-%d %H:%M:%S'),
                total_seats=60
            ),
            Train(
                name='Konkan Kanya Express',
                train_number='10111',
                source_id=2,  # Mumbai
                destination_id=31,  # Thiruvananthapuram
                departure_time=datetime.strptime('2023-06-01 15:00:00', '%Y-%m-%d %H:%M:%S'),
                arrival_time=datetime.strptime('2023-06-02 18:30:00', '%Y-%m-%d %H:%M:%S'),
                total_seats=72
            ),
            Train(
                name='Golden Temple Mail',
                train_number='12903',
                source_id=1,  # Delhi
                destination_id=29,  # Amritsar
                departure_time=datetime.strptime('2023-06-01 16:30:00', '%Y-%m-%d %H:%M:%S'),
                arrival_time=datetime.strptime('2023-06-02 03:30:00', '%Y-%m-%d %H:%M:%S'),
                total_seats=60
            ),
            Train(
                name='Chennai Express',
                train_number='12163',
                source_id=2,  # Mumbai
                destination_id=3,  # Chennai
                departure_time=datetime.strptime('2023-06-01 16:00:00', '%Y-%m-%d %H:%M:%S'),
                arrival_time=datetime.strptime('2023-06-02 08:30:00', '%Y-%m-%d %H:%M:%S'),
                total_seats=72
            ),
            Train(
                name='Howrah Rajdhani',
                train_number='12302',
                source_id=1,  # Delhi
                destination_id=4,  # Kolkata/Howrah
                departure_time=datetime.strptime('2023-06-01 16:50:00', '%Y-%m-%d %H:%M:%S'),
                arrival_time=datetime.strptime('2023-06-02 10:00:00', '%Y-%m-%d %H:%M:%S'),
                total_seats=72
            ),
            Train(
                name='Tejas Express',
                train_number='22120',
                source_id=2,  # Mumbai
                destination_id=17,  # Ahmedabad
                departure_time=datetime.strptime('2023-06-01 06:40:00', '%Y-%m-%d %H:%M:%S'),
                arrival_time=datetime.strptime('2023-06-01 13:10:00', '%Y-%m-%d %H:%M:%S'),
                total_seats=60
            )
        ]
        db.session.add_all(trains)
        db.session.commit()
        
        # Create seats for each train
        coaches = ['A1', 'A2', 'A3']
        for train in Train.query.all():
            for coach in coaches:
                for i in range(1, 71):  # Changed from 21 to 71 for 70 seats
                    seat_type = 'Window' if i % 3 == 1 else ('Aisle' if i % 3 == 2 else 'Middle')
                    price = 1200 if seat_type == 'Window' else (1000 if seat_type == 'Aisle' else 800)
                    seat = Seat(
                        train=train,
                        seat_number=i,
                        coach=coach,
                        seat_type=seat_type,
                        price=price
                    )
                    db.session.add(seat)
            db.session.commit()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(
            username=form.username.data,
            email=form.email.data,
            phone_number=form.phone_number.data,
            password_hash=hashed_password
        )
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('Login successful!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user
    bookings = Booking.query.filter_by(user_id=user.id).all()
    
    # Add today's date to the context
    today = datetime.now().date()
    
    return render_template('dashboard.html', user=user, bookings=bookings, today=today)


@app.route('/search', methods=['GET'])
def search():
    if request.method == 'GET':
        from_id = request.args.get('from_id')
        to_id = request.args.get('to_id')
        from_name = request.args.get('from')
        to_name = request.args.get('to')
        date = request.args.get('date')
        
        # Debug logging
        print(f"Search parameters - From: {from_name} ({from_id}), To: {to_name} ({to_id}), Date: {date}")
        
        # If we have station IDs, use them directly
        if from_id and to_id:
            trains = Train.query.filter_by(
                source_id=from_id,
                destination_id=to_id
            ).all()
        # Otherwise try to find stations by name
        elif from_name and to_name:
            source_station = Station.query.filter(
                (Station.name.ilike(f'%{from_name}%')) | 
                (Station.city.ilike(f'%{from_name}%'))
            ).first()
            
            destination_station = Station.query.filter(
                (Station.name.ilike(f'%{to_name}%')) | 
                (Station.city.ilike(f'%{to_name}%'))
            ).first()
            
            print(f"Found stations - Source: {source_station}, Destination: {destination_station}")
            
            if source_station and destination_station:
                trains = Train.query.filter_by(
                    source_id=source_station.id,
                    destination_id=destination_station.id
                ).all()
                print(f"Found {len(trains)} trains for this route")
            else:
                trains = []
                print("No matching stations found")
        else:
            trains = []
        
        return render_template('search.html', trains=trains, date=date, searched=True)
    
    return render_template('search.html', searched=False)

@app.route('/api/stations/search')
def search_stations():
    query = request.args.get('q', '').lower()
    if not query:
        return jsonify([])
    
    stations = Station.query.filter(
        (Station.name.ilike(f'%{query}%')) | 
        (Station.city.ilike(f'%{query}%')) |
        (Station.code.ilike(f'%{query}%'))
    ).limit(10).all()
    
    results = [{
        'id': station.id,
        'name': station.name,
        'city': station.city,
        'code': station.code
    } for station in stations]
    
    return jsonify(results)

@app.route('/train/<int:train_id>/seats/<journey_date>')
def select_seat(train_id, journey_date):
    if not current_user.is_authenticated:
        flash('Please login first.')
        return redirect(url_for('login'))
    
    train = Train.query.get_or_404(train_id)
    seats = Seat.query.filter_by(train_id=train_id).all()
    
    # Check which seats are already booked for this date
    booked_seats = Booking.query.filter_by(
        train_id=train_id, 
        journey_date=datetime.strptime(journey_date, '%Y-%m-%d').date()
    ).all()
    
    booked_seat_ids = [booking.seat_id for booking in booked_seats]
    
    return render_template('select_seat.html', train=train, seats=seats, journey_date=journey_date, booked_seat_ids=booked_seat_ids)

@app.route('/book', methods=['POST'])
def book_ticket():
    if not current_user.is_authenticated:
        flash('Please login first.')
        return redirect(url_for('login'))
    
    train_id = request.form.get('train_id')
    journey_date = request.form.get('journey_date')
    seat_ids = request.form.getlist('seat_ids[]')
    passenger_names = request.form.getlist('passenger_names[]')
    
    if not all([train_id, journey_date, seat_ids, passenger_names]):
        flash('Missing required information.')
        return redirect(url_for('select_seat', train_id=train_id, journey_date=journey_date))
    
    if len(seat_ids) != len(passenger_names):
        flash('Number of seats and passenger names do not match.')
        return redirect(url_for('select_seat', train_id=train_id, journey_date=journey_date))
    
    # Check if any of the seats are already booked
    for seat_id in seat_ids:
        existing_booking = Booking.query.filter_by(
            train_id=train_id,
            seat_id=seat_id,
            journey_date=datetime.strptime(journey_date, '%Y-%m-%d').date()
        ).first()
        
        if existing_booking:
            flash(f'Seat {seat_id} is already booked for the selected date.')
            return redirect(url_for('select_seat', train_id=train_id, journey_date=journey_date))
    
    # Create bookings for each seat
    bookings = []
    for seat_id, passenger_name in zip(seat_ids, passenger_names):
        booking = Booking(
            user_id=current_user.id,
            train_id=train_id,
            seat_id=seat_id,
            journey_date=datetime.strptime(journey_date, '%Y-%m-%d').date(),
            passenger_name=passenger_name
        )
        bookings.append(booking)
    
    try:
        db.session.add_all(bookings)
        db.session.commit()
        flash('Tickets booked successfully!')
        return redirect(url_for('booking_confirmation', booking_ids=','.join(str(b.id) for b in bookings)))
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while booking the tickets. Please try again.')
        return redirect(url_for('select_seat', train_id=train_id, journey_date=journey_date))

def send_booking_confirmation_email(booking_data):
    try:
        msg = Message(
            'Railway Booking Confirmation',
            recipients=[current_user.email]
        )
        
        # Create the HTML version of the message
        html = f"""
        <html>
            <body>
                <h2>Railway Booking Confirmation</h2>
                <p>Dear {current_user.username},</p>
                <p>Your booking has been confirmed. Here are the details:</p>
                <table style="border-collapse: collapse; width: 100%;">
                    <tr>
                        <td style="border: 1px solid #ddd; padding: 8px;"><strong>Booking ID:</strong></td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{booking_data['id']}</td>
                    </tr>
                    <tr>
                        <td style="border: 1px solid #ddd; padding: 8px;"><strong>Train:</strong></td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{booking_data['train_name']} ({booking_data['train_number']})</td>
                    </tr>
                    <tr>
                        <td style="border: 1px solid #ddd; padding: 8px;"><strong>From:</strong></td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{booking_data['source']}</td>
                    </tr>
                    <tr>
                        <td style="border: 1px solid #ddd; padding: 8px;"><strong>To:</strong></td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{booking_data['destination']}</td>
                    </tr>
                    <tr>
                        <td style="border: 1px solid #ddd; padding: 8px;"><strong>Date:</strong></td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{booking_data['journey_date']}</td>
                    </tr>
                    <tr>
                        <td style="border: 1px solid #ddd; padding: 8px;"><strong>Departure Time:</strong></td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{booking_data['departure_time']}</td>
                    </tr>
                    <tr>
                        <td style="border: 1px solid #ddd; padding: 8px;"><strong>Arrival Time:</strong></td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{booking_data['arrival_time']}</td>
                    </tr>
                    <tr>
                        <td style="border: 1px solid #ddd; padding: 8px;"><strong>Seat Number:</strong></td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{booking_data['seat_number']}</td>
                    </tr>
                    <tr>
                        <td style="border: 1px solid #ddd; padding: 8px;"><strong>Coach:</strong></td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{booking_data['coach']}</td>
                    </tr>
                    <tr>
                        <td style="border: 1px solid #ddd; padding: 8px;"><strong>Price:</strong></td>
                        <td style="border: 1px solid #ddd; padding: 8px;">₹{booking_data['price']}</td>
                    </tr>
                </table>
                <p>Thank you for choosing our service!</p>
            </body>
        </html>
        """
        
        msg.html = html
        mail.send(msg)
        
        print(f"Email sent successfully to {current_user.email}")
        return True
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        flash(f"Error sending email: {str(e)}", 'error')
        return False

def send_booking_confirmation_whatsapp(booking_data):
    try:
        if not twilio_client:
            print("Twilio client not initialized")
            return False
            
        # Format phone number to E.164 format if not already
        phone_number = current_user.phone_number
        if not phone_number.startswith('+'):
            phone_number = '+' + phone_number
            
        message = f"""
*Railway Booking Confirmation*

Dear {current_user.username},

Your booking has been confirmed. Here are the details:

Booking ID: {booking_data['id']}
Train: {booking_data['train_name']} ({booking_data['train_number']})
From: {booking_data['source']}
To: {booking_data['destination']}
Date: {booking_data['journey_date']}
Departure Time: {booking_data['departure_time']}
Arrival Time: {booking_data['arrival_time']}
Seat Number: {booking_data['seat_number']}
Coach: {booking_data['coach']}
Price: ₹{booking_data['price']}

Thank you for choosing our service!
"""
        
        # Send WhatsApp message
        message = twilio_client.messages.create(
            from_=f"whatsapp:{twilio_whatsapp_number}",
            body=message,
            to=f"whatsapp:{phone_number}"
        )
        
        print(f"WhatsApp message sent successfully to {phone_number}")
        print(f"Message SID: {message.sid}")
        return True
    except Exception as e:
        print(f"Error sending WhatsApp message: {str(e)}")
        return False

@app.route('/booking/<booking_ids>')
def booking_confirmation(booking_ids):
    if not current_user.is_authenticated:
        flash('Please login first.')
        return redirect(url_for('login'))
    
    try:
        # Convert booking IDs from string to list of integers
        booking_ids = [int(id) for id in booking_ids.split(',')]
        
        # Get all bookings for these IDs
        bookings = Booking.query.filter(Booking.id.in_(booking_ids)).all()
        
        if not bookings:
            flash('No bookings found.')
            return redirect(url_for('dashboard'))
        
        # Ensure all bookings belong to the logged-in user
        if not all(booking.user_id == current_user.id for booking in bookings):
            flash('Unauthorized access.')
            return redirect(url_for('dashboard'))
        
        # Prepare booking data for the template
        booking_data = []
        for booking in bookings:
            train = Train.query.get(booking.train_id)
            seat = Seat.query.get(booking.seat_id)
            source_station = Station.query.get(train.source_id)
            dest_station = Station.query.get(train.destination_id)
            
            if not all([train, seat, source_station, dest_station]):
                flash('Error retrieving booking details.')
                return redirect(url_for('dashboard'))
            
            booking_info = {
                'id': booking.id,
                'passenger_name': booking.passenger_name,
                'train_name': train.name,
                'train_number': train.train_number,
                'source': source_station.name,
                'destination': dest_station.name,
                'departure_time': train.departure_time.strftime('%H:%M'),
                'arrival_time': train.arrival_time.strftime('%H:%M'),
                'journey_date': booking.journey_date.strftime('%Y-%m-%d'),
                'seat_number': seat.seat_number,
                'coach': seat.coach,
                'seat_type': seat.seat_type,
                'price': seat.price
            }
            booking_data.append(booking_info)
            
            # Send WhatsApp notification if configured
            send_booking_confirmation_whatsapp(booking_info)
        
        return render_template('booking_confirmation.html', bookings=booking_data)
    except Exception as e:
        print(f"Error in booking_confirmation: {str(e)}")
        flash('Error retrieving booking details.')
        return redirect(url_for('dashboard'))

@app.route('/chatbot', methods=['POST'])
def chatbot():
    data = request.get_json()
    query = data.get('query', '')

    if not query:
        return jsonify({'response': 'Please provide a query.'}), 400

    try:
        response = model.generate_content(query).text
        return jsonify({'response': response})
    except Exception as e:
        print(f"Error generating chatbot response: {e}")
        return jsonify({'response': 'Sorry, I am unable to process your query at the moment.'}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5001)

print("Flask application initialized with database models and routes")