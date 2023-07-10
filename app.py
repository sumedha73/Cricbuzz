import datetime
import os
from flask import Flask, render_template, request, redirect, url_for, flash, app, jsonify
import pymysql
import jwt
from functools import wraps


app = Flask(__name__)

connection = pymysql.Connection(host='localhost',
                             user='root',
                             password='Sumedha123',
                             db='cricbuzz',
                             charset='utf8mb4',
                             cursorclass=pymysql.cursors.DictCursor)


SECRET_KEY = os.environ.get('SECRET_KEY') or 'this is a secret'
print(SECRET_KEY)
jwt_secret_key = '071889bc-03c4-4f12-9d3b-c55493dd5d89'


from flask import Flask, jsonify, request
import hashlib
import mysql.connector

app = Flask(__name__)

# Endpoint: POST /api/admin/signup
@app.route('/api/admin/signup', methods=['POST'])
def admin_signup():
    # Get signup details from the request body
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    # Hash the password
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    # Check if the user already exists
    with connection.cursor(pymysql.cursors.DictCursor) as cursor:
        # todo
        #     select_query = "SELECT COUNT(*) FROM User WHERE name = %s OR email = %s"
        #     cursor.execute(select_query, (username, email))
        #     user_exists = cursor.fetchone()
        # if user_exists:
        #     cursor.close()
        #     response_data = {
        #         'status': 'User already exists',
        #         'status_code': 409
        #     }
        #     return jsonify(response_data), 409

        # Insert user details into the database
        insert_query = "INSERT INTO `user` (name, email, password) VALUES (%s, %s, %s)"
        cursor.execute(insert_query, (username, email, hashed_password))
        connection.commit()
        user_id = cursor.lastrowid
        cursor.close()

        # Prepare the response with inserted user details
        response_data = {
            'status': 'Admin Account successfully created',
            'status_code': 200,
            'user_id': user_id
        }

    return jsonify(response_data), 200


@app.route('/api/admin/login', methods=['POST'])
def login():
    # Authenticate the user (perform your authentication logic here)
    data = request.json
    username = data.get('username')
    password = data.get('password')

    # Verify the user's credentials
    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            sql = "SELECT password, user_id FROM `user` WHERE name = %s"
            cursor.execute(sql, username)
            result = cursor.fetchone()

            if result is None:
                cursor.close()
                return jsonify(message='Invalid credentials'), 401

            db_password = result['password']
            user_id = result['user_id']
            hashed_user_password = hashlib.sha256(password.encode()).hexdigest()

            if hashed_user_password == db_password:
                # Generate the JWT token
                token_payload = {'username': username,
                                 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
                                 # Set expiration time to 30 minutes from now
                                 }
                token = jwt.encode(token_payload, jwt_secret_key, algorithm='HS256')
                # Return the JWT token as the response
                return jsonify({
                    "status": "Login successful",
                    "status_code": 200,
                    "user_id": user_id,
                    "access_token": token,
                }), 200

    except Exception as e:
        return jsonify({
            "status": "Incorrect username/password provided. Please retry",
            "status_code": 401
        }), 401


    return jsonify(message='Invalid credentials'), 401

def authenticate(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Get the JWT token from the request header
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            try:
                # Verify and decode the JWT token
                decoded_token = jwt.decode(token, jwt_secret_key, algorithms=['HS256'])
                # Add the decoded token to the request context for further processing
                request.current_user = decoded_token
                return f(*args, **kwargs)
            except jwt.ExpiredSignatureError:
                return jsonify(message='Token has expired'), 401
            except jwt.InvalidTokenError:
                return jsonify(message='Invalid token'), 401
        return jsonify(message='Missing or invalid Authorization header'), 401

    return decorated


@app.route('/api/matches', methods=['POST'])
@authenticate
def create_matches():
    try:
        data = request.json
        team1_name = data.get('team_1')
        team2_name = data.get('team_2')
        match_date = data.get('date')
        venue = data.get('venue')

        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            insert_query = "INSERT INTO `matches` (team1_name, team2_name, match_date, venue) VALUES (%s, %s, %s, %s)"
            cursor.execute(insert_query, (team1_name, team2_name, match_date, venue))
            connection.commit()
            match_id = cursor.lastrowid
            cursor.close()

            # Prepare the response with inserted match details
            response_data = {
                'match_id': match_id,
                'message': "Match created successfully",
            }

            return jsonify(response_data), 200

    except Exception as e:
        return jsonify({
            "message": "failed to create match",
            "error": str(e),
            "data": None
        }), 500


@app.route('/api/matches', methods=['GET'])
# @authenticate
def fetch_matches():
    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            sql = "SELECT match_id, team1_name, team2_name, match_date, venue FROM matches"
            cursor.execute(sql)
            result = cursor.fetchall()
            return jsonify(result), 200

    except Exception as e:
        return jsonify({
            "message": "failed to retrieve match schedules",
            "error": str(e),
            "data": None
        }), 500



@app.route('/api/players/<int:player_id>/stats', methods=['GET'])
def get_player_stats(player_id):
    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            sql = "SELECT player_id, name, matches_played, runs, average, strike_rate FROM `player_stats` where player_id = %s"
            cursor.execute(sql, (player_id,))
            result = cursor.fetchall()
            return jsonify(result), 200

    except Exception as e:
        return jsonify({
            "message": "failed to retrieve player statistics",
            "error": str(e),
            "data": None
        }), 500


@app.errorhandler(403)
def forbidden(e):
    return jsonify({
        "message": "Forbidden",
        "error": str(e),
        "data": None
    }), 403

@app.errorhandler(404)
def forbidden(e):
    return jsonify({
        "message": "Endpoint Not Found",
        "error": str(e),
        "data": None
    }), 404




if __name__ == '__main__':
    app.run(debug=True)