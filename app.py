from urllib.parse import urlencode

import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, session, request, jsonify, make_response, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func

app = Flask(__name__)
app.config['SECRET_KEY'] = '8da27f76c24c13b7f11690da'  # os.urandom(12).hex()
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=30)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///patients.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


class Patients(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())

    def __init__(self, username: str, name: str, email: str):
        self.username = username
        self.name = name
        self.email = email

    @staticmethod
    def create(username, name, email):  # create new user
        new_user = Patients(username, name, email)
        db.session.add(new_user)
        db.session.commit()

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
    new_expiration_time = datetime.utcnow() + timedelta(seconds=30)
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
    if not session.get('logged in'):
        return render_template('login.html')
    else:
        return 'Logged in Currently'


@app.route('/login', methods=['POST'])
def login():
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


if __name__ == '__main__':
    Patients.create("test", "chris", "chris")
    app.run(debug=True)
