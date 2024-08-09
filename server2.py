from flask import Flask, request, jsonify, redirect, url_for, session, make_response
import jwt
import requests

app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisisasecretkey'  # Use the same SECRET_KEY as Server A

AUTH_SERVER = 'http://localhost:5500'  # Server A URL

# def token_required(f):
#     def decorated(*args, **kwargs):
#         token = None
#         if 'x-access-token' in request.cookies:
#             token = request.cookies.get('x-access-token')
#         if not token:
#             redirect(url_for('login'))

#         try:
#             data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
#             current_user = data['public_id']
#         except jwt.ExpiredSignatureError:
#             return redirect(url_for('login'))
#         except jwt.InvalidTokenError:
#             return redirect(url_for('login'))

#         return f(current_user, *args, **kwargs)

#     return decorated


def token_required(f):
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.cookies:
            token = request.cookies.get('x-access-token')
        if not token:
            return redirect(url_for('login')), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            print(data)
            current_user = {
                'public_id': data['public_id'],
                'name': data['name'],
                'email': data['email']
            }
        except jwt.ExpiredSignatureError:
            return redirect(url_for('login')), 401
        except jwt.InvalidTokenError:
            return redirect(url_for('login')), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/', endpoint='index')
@token_required
def index(current_user):
    if not current_user:
        return redirect(url_for('login')), 401


    return jsonify({
        'message': f"Hello, {current_user['name']} ({current_user['email']})! You are authenticated.",
        'user_id': current_user['public_id']
    })


@app.route('/logout')
def logout():

    return redirect(AUTH_SERVER + '/logout?next=' + url_for('login', _external=True))

@app.route('/login')
def login():
    # Construct the next parameter to point back to the callback route on Server B
    callback_url = url_for('callback', _external=True)
    return make_response(redirect(f"{AUTH_SERVER}/login?next={callback_url}"))

    #return redirect(f"{AUTH_SERVER}/login?next={callback_url}")


@app.route('/callback')
def callback():
    token = request.cookies.get('x-access-token')
    if not token:
        return 'Authentication failed', 401
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        current_user = {
            'public_id': data['public_id'],
            'name': data['name'],
            'email': data['email']
        }
        # Optionally store user info in session if needed
    except jwt.ExpiredSignatureError:
        return 'Token expired', 401
    except jwt.InvalidTokenError:
        return 'Invalid token', 401

    # Redirect to the index page after successful authentication
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True, port=4331)