import os
import random
from urllib.parse import urlencode
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, session, request, jsonify, make_response, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
import bcrypt

from AuditServer import AuditServer

# GLOBAL CONFIG
TIMEOUT = timedelta(seconds=300)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = '8da27f76c24c13b7f11690da'  # os.urandom(12).hex()
app.config['PERMANENT_SESSION_LIFETIME'] = TIMEOUT
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'patient.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

#test
locl_host = "127.0.0.1"
locl_port = 9890
name = "Server A"
notifier_config = {
    'name': "Audit Server",
    'rate': 5,
    'identity': {
        'name': "Audit Server",
        'ip': "127.0.0.1",
        'node_port': 0,
        'server_port': 9890
    }
}
aserver = AuditServer(locl_host, locl_port, name, notifier_config)

# Actions
ACT_CREATE = 0xC0FFEE01
ACT_DELETE = 0xC0FFEE02
ACT_CHANGE = 0xF00D4DAD
ACT_QUERY = 0xFACE0FFF
ACT_PRINT = 0xBEEF4DAD
ACT_COPY = 0xCAFECAFE


class Patients(db.Model):
    """
    Patients Objects will include the following:
    id:             Unique, and generated randomly upon signup
    firstname:      User's first name
    lastname:       User's last name
    email:          Unique, email address of user
    password_salt:  Random salt used for password hashing
    password_hash:  User's password hash with salt applied
    created_at:     Time of Instantiation of a user profile
    """
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password_salt = db.Column(db.String(64), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())

    def __init__(self, firstname: str, lastname: str, email: str, password: str):
        """
        Patients object initialization function. Password will be salted.
        :param firstname: User's first name
        :param lastname:  User's last name
        :param email:     User's email address (must be unique)
        :param password:  User's password
        """
        self.id = random.randint(1, 1000000)
        self.firstname = firstname
        self.lastname = lastname
        self.email = email
        self.password_salt = bcrypt.gensalt().decode('utf-8')
        self.set_password(self, password=password)

    @staticmethod
    def create(first, last, email, password):
        """
        Add user to SQLITE database. This function will query the DB to ensure that the email address
        passed into the signup form is UNIQUE.
        :param first:    First Name
        :param last:     Last Name
        :param email:    Email Address
        :param password: User's Password
        :return:         T: User has been added / F: DB addition has failed
        """
        existing_user = Patients.query.filter_by(email=email).first()

        # Check for existing user
        if existing_user:
            return False
        else:
            new_user = Patients(firstname=first, lastname=last, email=email, password=password)
            db.session.add(new_user)
            db.session.commit()
            return True

    @staticmethod
    def get_id(self):
        return self.id

    @staticmethod
    def get_firstname(self):
        return self.firstname

    @staticmethod
    def get_lastname(self):
        return self.lastname

    @staticmethod
    def get_email(self):
        return self.email

    @staticmethod
    def set_password(self, password: str):
        """
        Private method that will concatenate salt with password and update the User's password hash
        :param self:      Current Patients object
        :param password:  User's Password (RED)
        :return:          None
        """
        salted_password = (password + self.password_salt).encode('utf-8')
        self.password_hash = bcrypt.hashpw(salted_password, bcrypt.gensalt()).decode('utf-8')

    @staticmethod
    def check_password(self, password: str) -> bool:
        """
        Simple method to verify a password
        :param self:     Current Patients object
        :param password: User's password
        :return:         True: H(Password + Salt) matches DB // F: H(Password + Salt) does not match
        """
        salted_password = (password + self.password_salt).encode('utf-8')
        return bcrypt.checkpw(salted_password, self.password_hash.encode('utf-8'))

    def __repr__(self):
        return f'<Patient {self.firstname}>'


def token_required(function):
    """
    Wrapper function used for ensuring JWT tokens have been established before calling subsequent functions
    :param function: Function requiring token_required wrapping
    :return: JSON error code or valid JWT token
    """

    @wraps(function)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'Alert': 'Token is missing'})

        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except jwt.InvalidTokenError as e:
            return jsonify({'ALERT': f'Invalid Token: {str(e)}'})

        return function(*args, **kwargs)

    return decorated

def token_handle():
    token = request.args.get('token')
    payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    expiration_time = datetime.strptime(payload['expiration'], '%Y-%m-%d %H:%M:%S.%f')

    # Check if the session has timed out
    if datetime.utcnow() >= expiration_time:
        return render_template('session_timeout.html')

    # Update the expiration time to extend the session
    new_expiration_time = datetime.utcnow() + TIMEOUT
    payload['expiration'] = str(new_expiration_time)
    new_token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

    return new_token


@app.route('/public')
def public():
    return 'For Public'


@app.route('/create-ehr-data', methods=['POST'])
@token_required
def create_ehr_data():
    token = token_handle()
    payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    email = payload['email']
    session['create-ehr-data'] = request.form['create-ehr-textbox']

    user: Patients = Patients.query.filter_by(email=email).first()

    if not user:
        return jsonify({'ERROR': f'User with {email} not in database'})

    id = user.get_id(user)

    aserver.append_user_record(user_id=id, action="placeholder")

    return render_template('00_Create_EHR.html')



# @app.route('/create-ehr-data')
# @token_required
# def create_ehr():
#     token = token_handle()
#     payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
#     email = payload['email']
#
#     user: Patients = Patients.query.filter_by(email=email).first()
#
#     if not user:
#         return jsonify({'ERROR': f'User with {email} not in database'})
#
#     id = user.get_id(user)
#
#     return render_template('00_Create_EHR.html')

@app.route('/delete-ehr-data')
@token_required
def delete_ehr():
    token = token_handle()
    payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    email = payload['email']

    user: Patients = Patients.query.filter_by(email=email).first()

    if not user:
        return jsonify({'ERROR': f'User with {email} not in database'})

    id = user.get_id(user)

    return render_template('01_Delete_EHR.html')

@app.route('/change-ehr-data')
@token_required
def change_ehr():
    token = token_handle()
    payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    email = payload['email']

    user: Patients = Patients.query.filter_by(email=email).first()

    if not user:
        return jsonify({'ERROR': f'User with {email} not in database'})

    id = user.get_id(user)

    return render_template('02_Change_EHR.html')

@app.route('/query-ehr-data')
@token_required
def query_ehr():
    token = token_handle()
    payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    email = payload['email']

    user: Patients = Patients.query.filter_by(email=email).first()

    if not user:
        return jsonify({'ERROR': f'User with {email} not in database'})

    id = user.get_id(user)

    return render_template('03_Query_EHR.html')

@app.route('/print-ehr-data')
@token_required
def print_ehr():
    token = token_handle()
    payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    email = payload['email']

    user: Patients = Patients.query.filter_by(email=email).first()

    if not user:
        return jsonify({'ERROR': f'User with {email} not in database'})

    id = user.get_id(user)

    return render_template('04_Print_EHR.html')

@app.route('/copy-ehr-data')
@token_required
def copy_ehr():
    token = token_handle()
    payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    email = payload['email']

    user: Patients = Patients.query.filter_by(email=email).first()

    if not user:
        return jsonify({'ERROR': f'User with {email} not in database'})

    id = user.get_id(user)

    return render_template('05_Copy_EHR.html')



@app.route('/auth')
@token_required
def auth():
    """
    Flask successful login with JWT
    :return: None
    """
    token = request.args.get('token')
    payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    email = payload['email']
    expiration_time = datetime.strptime(payload['expiration'], '%Y-%m-%d %H:%M:%S.%f')

    # Check if the session has timed out
    if datetime.utcnow() >= expiration_time:
        return render_template('session_timeout.html')

    # Update the expiration time to extend the session
    new_expiration_time = datetime.utcnow() + TIMEOUT
    payload['expiration'] = str(new_expiration_time)
    new_token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

    user: Patients = Patients.query.filter_by(email=email).first()
    if not user:
        return jsonify({'ERROR': f'User with {email} not in database'})

    id = user.get_id(user)
    session['jwt_token'] = new_token
    session['uid'] = id

    # admin dashboard set during /login route
    if session['admin']:
        return render_template('admin_dash.html')
    else:
        return render_template('user_dash.html')

@app.route('/')
def home():
    """
    Flask Homepage
    :return: render of EHR homepage
    """
    return render_template('index.html')


@app.route('/login.html', methods=['GET'])
def login():
    """
    Flask login page
    :return: render of EHR login page
    """
    return render_template('login.html')


@app.route('/signup.html', methods=['GET'])
def signup():
    """
    Flask signup page
    :return: render of EHR signup page
    """
    return render_template('signup.html')


@app.route('/signup', methods=['POST'])
def post_signup():
    """
    User form parsing for creation of new entry in Patients DB
    :return: Error code / Successful login
    """
    FN = request.form['FN']
    LN = request.form['LN']
    email = request.form['Email']
    pw = request.form['new-password']
    confirm_pw = request.form['confirm-password']

    admin_prevent = check_admin(email)

    if admin_prevent:
        return render_template('signup_failure_admin_prevent.html')

    if pw != confirm_pw:
        return render_template('err_pw_mismatch.html')
    else:
        status = Patients.create(first=FN, last=LN, email=email, password=pw)

        if status:
            return render_template('signup_success.html')
        else:
            return render_template('signup_failure.html')


def check_admin(email: str):
    return email.lower().endswith('@audit.usc.edu')

@app.route('/login', methods=['POST'])
def post_login():
    """
    Flask EHR login page
    Check if user is within our database and generate them a JWT token for their session
    :return: JWT token valid for TIMEOUT seconds
    """
    email = request.form['Email']
    password = request.form['password']

    user = Patients.query.filter_by(email=email).first()

    if user is not None and user.check_password(self=user, password=password):
        session['logged_in'] = True
        session.permanent = True

        # global admin check
        session['admin'] = check_admin(email)

        token = jwt.encode(
            payload={
                'email': request.form['Email'],
                'expiration': str(datetime.utcnow() + TIMEOUT)
            },
            key=app.config['SECRET_KEY'],
            algorithm='HS256'
        )
        params = {'token': token}
        query_string = urlencode(params)
        redirect_url = url_for('auth') + '?' + query_string
        return redirect(redirect_url)
    else:
        return make_response('Unable to verify', 403, {'WWW-Authenticate': 'Basic Realm:"Authentication Failed"'})


def db_check():
    """
    Check if DB is instantiated
    :return: None
    """

    if db.session.query(Patients).count() == 0:
        for t in range(1, 11, 1):
            FN = 'Patient' + str(t) + 'FN'
            LN = 'Patient' + str(t) + 'LN'
            email = 'Patient' + str(t) + '@usc.edu'
            Patients.create(FN, LN, email, '1234')

        for a in range(1, 4, 1):
            FN = 'Audit' + str(a) + 'FN'
            LN = 'Audit' + str(a) + 'LN'
            email = 'Auditor' + str(a) + '@audit.usc.edu'
            Patients.create(FN, LN, email, '1234')
    else:
        print('SQL Table already populated')
        patients: db.Model = Patients.query.order_by(Patients.email).all()
        for patient in patients:
            dt: str = patient.created_at.strftime('%Y-%m-%d %H:%M:%S')
            print(
                f'{patient.firstname.ljust(15)} {patient.lastname.ljust(15)} {patient.email.ljust(30)} '
                f'{str(patient.id).ljust(10)} {dt.ljust(20)}')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        db_check()
        app.run(debug=True)
