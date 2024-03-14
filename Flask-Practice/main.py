from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import sqlite3

# # generate key:
# import secrets
# secret_key = secrets.token_hex(16)

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'd467466db359b7b0111e1673e4384d09'
jwt = JWTManager(app)


def get_db():
    db = sqlite3.connect('sqlite.db')
    db.row_factory = sqlite3.Row
    return db


###
#     db = sqlite3.connect("sqlite.db")
#     db.cursor().execute("INSERT INTO station (station_id, station_name, longitude, latitude) VALUES (?, ?, ?, ?)",
#                         (data["station_id"], data["station_name"], data["longitude"], data["latitude"]))
#     db.commit()
#     db.close()
###

@app.route('/api/new/user', methods=['POST'])
def create_user():
    data = request.get_json()
    username = data['username']
    password = data['password']
    email = data['email']

    db = get_db()
    db.cursor().execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', (username, password, email))
    db.commit()
    db.close()

    return {'message': 'Registration successful', 'user': {'username': username, 'email': email}}, 200


@app.route('/api/login', methods=['POST'])
def login_user():
    data = request.get_json()
    username = data['username']
    password = data['password']
    email = data['email']
    if len(email) == 0 or not email:
        # match with username
        db = get_db()
        user = db.cursor().execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()
        # user = db.cursor().fetchone()
        if not user:
            return {'error': 'wrong username or password'}, 451
        access_token = create_access_token(identity=user[0])
        return {'access_token': access_token}, 200
    elif len(username) == 0 or not username:
        # match with email
        db = get_db()
        user = db.cursor().execute('SELECT * FROM users WHERE email = ? AND password = ?', (email, password)).fetchone()
        # user = db.cursor().fetchone()
        if not user:
            return {'error': 'wrong username or password'}, 401
        access_token = create_access_token(identity=user[0])
        return {'access_token': access_token}, 200
    else:
        return {'error': 'wrong username or password', 'username': username, 'email': email, 'password': password}, 401


@app.route('/api/get-user', methods=['GET'])
@jwt_required()
def get_user():
    return {'user': get_jwt_identity()}, 200


if __name__ == "__main__":
    app.run(debug=True)
