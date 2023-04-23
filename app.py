import random
from urllib.parse import urlencode
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, session, request, jsonify, make_response, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func

# GLOBAL
TIMEOUT = timedelta(seconds=100)

app = Flask(__name__)
app.config['SECRET_KEY'] = '8da27f76c24c13b7f11690da'  # os.urandom(12).hex()
app.config['PERMANENT_SESSION_LIFETIME'] = TIMEOUT
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///patient.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


class Patients(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())

    def __init__(self, firstname: str, lastname: str, email: str):
        self.id = random.randint(1, 1000000)
        self.firstname = firstname
        self.lastname = lastname
        self.email = email

    @staticmethod
    def create(first, last, email):  # create new user
        new_user = Patients(firstname=first, lastname=last, email=email)
        db.session.add(new_user)
        db.session.commit()

    @staticmethod
    def get_id(self): return self.id

    @staticmethod
    def get_firstname(self): return self.firstname

    @staticmethod
    def get_lastname(self): return self.lastname

    @staticmethod
    def get_email(self): return self.email

    def __repr__(self):
        return f'<Patient {self.firstname}>'


def token_required(function):
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


@app.route('/public')
def public():
    return 'For Public'


@app.route('/auth')
@token_required
def auth():
    token = request.args.get('token')
    payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    username = payload['user']
    expiration_time = datetime.strptime(payload['expiration'], '%Y-%m-%d %H:%M:%S.%f')

    # Check if the session has timed out
    if datetime.utcnow() >= expiration_time:
        return jsonify({'Message': 'Session has timed out'})

    # Update the expiration time to extend the session
    new_expiration_time = datetime.utcnow() + TIMEOUT
    payload['expiration'] = str(new_expiration_time)
    new_token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({
        'Message1': f'JWT Verified, welcome to dashboard {username}!',
        'Message2': f'Your session ends at: {expiration_time}',
        'Message3': f'Current time: {datetime.utcnow()}',
        'NewToken': new_token
    })


@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login.html', methods=['GET'])
def login():
    return render_template('login.html')

@app.route('/signup.html', methods=['GET'])
def signup():
    return render_template('signup.html')

@app.route('/login', methods=['POST'])
def post_login():
    if request.form['username'] and request.form['password'] == '123456':
        session['logged_in'] = True
        session.permanent = True
        token = jwt.encode(
            payload={
                'user': request.form['username'],
                'expiration': str(datetime.utcnow() + timedelta(seconds=30))
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
    <WARN> I found my database located here (might be different depending on setup):                     <WARN>
    <WARN> %APPDATA%\\Local\\JetBrains\\Toolbox\\apps\\PyCharm-P\\ch-0\\231.8109.197\\jbr\\bin\\instance <WARN>

    :return: None
    """

    if db.session.query(Patients).count() == 0:
        for t in range(1, 11, 1):
            FN = 'Test' + str(t) + 'FN'
            LN = 'Test' + str(t) + 'LN'
            email = 'T' + str(t) + '@usc.edu'
            Patients.create(FN, LN, email)

        for a in range(1, 4, 1):
            FN = 'Audit' + str(a) + 'FN'
            LN = 'Audit' + str(a) + 'LN'
            email = 'Auditor' + str(a) + '@usc.edu'
            Patients.create(FN, LN, email)
    else:
        print('SQL Table already populated')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        db_check()
    app.run(debug=True)
    # patients: db.Model = Patients.query.order_by(Patients.email).all()
    # for patient in patients:
    #     dt: str = patient.created_at.strftime('%Y-%m-%d %H:%M:%S')
    #     print(
    #         f'{patient.firstname.ljust(10)} {patient.lastname.ljust(10)} {patient.email.ljust(20)} '
    #         f'{str(patient.id).ljust(10)} {dt.ljust(20)}')
