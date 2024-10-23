from flask import Flask, request, jsonify, make_response, redirect, url_for, render_template
from flask_sqlalchemy import SQLAlchemy
import uuid 
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask_migrate import Migrate
from flask_session import Session
import sys

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///clothes.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'

app.config["PERMANENT_SESSION_LIFETIME"] = 60
app.config['SESSION_TYPE'] = 'sqlalchemy' 

app.config['SESSION_SQLALCHEMY_TABLE'] = "sessions"

db = SQLAlchemy(app)
app.config['SESSION_SQLALCHEMY'] = db
sess = Session(app)
migrate = Migrate(app, db)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(70), unique=True)
    password = db.Column(db.String(80))

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        elif 'x-access-token' in request.cookies:
            token = request.cookies.get('x-access-token')
        if not token:
            return jsonify({'message': 'Token is missing !!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid !!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/home', methods=['GET'])
def adduser():
    user = User(public_id=str(uuid.uuid4()), name='admin', email='hhhf@gmail.com', password=generate_password_hash('admin'))
    db.session.add(user)
    db.session.commit()
    return 'User Created'


@app.route('/protected', methods=['GET'])
@token_required
def protected(current_user):
    return jsonify({'message': f'This is a protected route, {current_user.name}.'})


@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    users = User.query.all()
    output = []
    for user in users:
        output.append({
            'public_id': user.public_id,
            'name': user.name,
            'email': user.email
        })

    return jsonify({'users': output})








@app.route('/login', methods=['GET', 'POST'])
def login():
    # Initialize next_param to None
    next_param = None

    if request.method == 'GET':
        print(f"Request URL: {request.url}")  # Debugging statement
        
        # Extract the 'next' parameter value
        next_param = request.args.get('next')  # Get the next parameter

        if next_param:
            print(f"Extracted next parameter: {next_param}")
        else:
            print("No next parameter found.")

        return render_template('login.html', next=next_param)

    if request.method == 'POST':
        auth = request.form
        print(auth)

        if not auth or not auth.get('email') or not auth.get('password'):
            return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm ="Login required !!"'})

        user = User.query.filter_by(email=auth.get('email')).first()

        if not user:
            return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm ="User does not exist !!"'})

        if check_password_hash(user.password, auth.get('password')):
            token = jwt.encode({
                'public_id': user.public_id,
                'name': user.name,
                'email': user.email,
                'exp': datetime.utcnow() + timedelta(minutes=30)
            }, app.config['SECRET_KEY'], algorithm="HS256")
            
            next_param = str(auth.get('next'))  
            print(f"Next parameter from form: {next_param}")

            # Redirect to the next parameter or dashboard
            if next_param != None: 
                print(f"Redirecting to next page: {next_param}") 
                response = redirect(next_param)  
            else:
                print("No next parameter found. Redirecting to dashboard.")  
                response = make_response(redirect(url_for('dashboard')))

            response.set_cookie('x-access-token', token)
            return response

    return make_response('Could not verify', 403, {'WWW-Authenticate': 'Basic realm ="Wrong Password !!"'})


    





@app.route('/logout', methods=['GET'])
def logout():
    response = make_response(redirect(url_for('login')))
    response.set_cookie('x-access-token', expires=0)
    return response

@app.route('/signup', methods=['POST'])
def signup():
    data = request.form
    name, email = data.get('name'), data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(
            public_id=str(uuid.uuid4()),
            name=name,
            email=email,
            password=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        return make_response('Successfully registered.', 201)
    else:
        return make_response('User already exists. Please Log in.', 202)

@app.route('/dashboard', methods=['GET'])
@token_required
def dashboard(current_user):
    return jsonify({'message': f'Welcome to the dashboard, {current_user.name}!'})


if __name__ == "__main__":
    
    
    app.run(debug=True, port=5500)
