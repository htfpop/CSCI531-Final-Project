from urllib.parse import urlencode

import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, session, request, jsonify, make_response, redirect, url_for

app = Flask(__name__)
app.config['SECRET_KEY'] = '8da27f76c24c13b7f11690da'  # os.urandom(12).hex()
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=30)


def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'Alert': 'Token is missing'})

        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except jwt.InvalidTokenError as e:
            return jsonify({'ALERT': f'Invalid Token: {str(e)}'})

        return func(*args, **kwargs)

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
    app.run(debug=True)
