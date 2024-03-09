import sqlite3
from flask import Flask, flash, session, render_template, redirect
import sys
import cgi, os

# from werkzeug import secure_filename
from werkzeug.utils import secure_filename
import time
import collections
import os.path as op
from datetime import datetime as dt
from flask import Flask, render_template, url_for, redirect, request
from flask_admin.contrib.sqla import ModelView
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin, form
from flask import session as login_session
from flask_login import LoginManager, login_user, logout_user, login_required
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required
from flask_bcrypt import Bcrypt
import sqlite3

from flask_admin import Admin, form

from flask import Flask, flash, request, redirect, url_for
from sqlalchemy.exc import IntegrityError
import requests
import json

from typing import Union, Type

admin = Admin()
app = Flask(__name__, static_folder='static')
app.secret_key = 'any random string'
# see http://bootswatch.com/3/ for available swatches
app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'

bcrypt = Bcrypt(app)


connect = sqlite3.connect(r'C:\Users\Bongeka.Mpofu\DB Browser for SQLite\\weathersql.db', check_same_thread=False)


connect.execute(
    'CREATE TABLE IF NOT EXISTS role (id INTEGER NOT NULL PRIMARY KEY autoincrement, name TEXT)')

connect.execute(
    'CREATE TABLE IF NOT EXISTS user (id INTEGER NOT NULL PRIMARY KEY autoincrement, username VARCHAR NOT NULL UNIQUE, \
firstname TEXT, lastname TEXT, email NOT NULL UNIQUE, password TEXT, agreed_terms TEXT, regDateTime TIMESTAMP DEFAULT CURRENT_TIMESTAMP, path TEXT, role_code INTEGER)')


connect.execute(
    'CREATE TABLE IF NOT EXISTS health (hid INTEGER NOT NULL PRIMARY KEY autoincrement, weight REAL, height REAL, bmi REAL, calories REAL, assess_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')


connect.execute(
    'CREATE TABLE IF NOT EXISTS weather (wid INTEGER NOT NULL PRIMARY KEY autoincrement, current_temp REAL, \
current_pressure  REAL, current_humidity REAL, current_airindex REAL, weather_description REAL, date_taken TIMESTAMP)')


connect.execute(
    'CREATE TABLE IF NOT EXISTS city (city_id INTEGER NOT NULL PRIMARY KEY autoincrement, city_name TEXT, \
 longitude REAL, latitude REAL)')


@app.route('/')
@app.route('/home')
def option():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        user_entered = request.form['password']
        cur = connect.cursor()
        cur.execute(f"SELECT username, password from user WHERE username='{username}'")
        if cur is not None:
            # Get Stored hashed and salted password - Need to change fetch one to only return the one username
            data = cur.fetchone()
            #print(data)
            #print(type(data))
            password = data[1]

            print(password)
            print(type(password))
            # Compare Password with hashed password- Bcrypt
            if bcrypt.check_password_hash(password, user_entered):
                session['logged_in'] = True
                session['username'] = username
                flash('You are now logged in', 'success')
                return redirect(url_for('welcome'))
                # Close Connection
                cursor.close()

            else:
                error = 'Invalid Username or Password'
                return render_template('login.html', error=error)
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']
        password_hash = request.form['password']
        agreed_terms = request.form.get('terms')
        path = "avator.jpg"
        role_code = 2
        role_code = int(role_code)

        hashed_password = bcrypt.generate_password_hash(
            password_hash).decode('utf-8')
        try:
            cur = connect.cursor()
            cur.execute(
                "INSERT INTO user(username,firstname, lastname, email, password, agreed_terms, path, role_code) VALUES (?,?, ?, ?, ?, ?, ?, ?)", (username, firstname, lastname, email, hashed_password, agreed_terms, path, role_code))


        except IntegrityError:
            session.rollback()

        else:
            connect.commit()
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/welcome')
def welcome():
    if session:

        return render_template('welcome.html')
    else:
        return redirect(url_for('login'))


@app.route('/forecast', methods=['GET', 'POST'])
def forecast():
    city_name = ""
    region = ""
    country = ""
    localtime = ""
    current_temperature = ""
    current_wind = ""
    current_humidity = ""
    air_quality = ""
    weather_description = ""
    risk = ""
    general = ""

    if request.method == 'POST':
        city_name = request.form.get('city_name')

        url = f"http://api.weatherapi.com/v1/current.json?key={API}&q={city_name}&aqi={aqi}"
        result = requests.get(url)  # Will call the website and fetch information
        # successful response code is 200
        print(result)
        # data is more readable with json module
        wdata = json.loads(result.text)
        print(wdata)

        city_name = wdata["location"]["name"]

        region = wdata["location"]["region"]
        country = wdata["location"]["country"]
        tz_id = wdata["location"]["tz_id"]
        localtime = wdata["location"]["localtime"]

        # Current vars
        current_temperature = wdata["current"]["temp_c"]
        wind_kph = wdata["current"]["wind_kph"]
        current_wind = wdata["current"]["wind_degree"]
        wind_dir = wdata["current"]["wind_dir"]
        precip_mm = wdata["current"]["precip_mm"]
        current_humidity = wdata["current"]["humidity"]
        cloud = wdata["current"]["cloud"]
        uv = wdata["current"]["uv"]
        gust_kph = wdata["current"]["gust_kph"]
        weather_description = wdata["current"]["condition"]["text"]
        air_quality = wdata["current"]["air_quality"]["gb-defra-index"]

        if int(air_quality) >= 10:
            risk = "Index is Very High, At-risk individuals*, Adults and children with lung problems, adults with heart problems, and older people, should avoid strenuous physical activity. People with asthma may find they need to use their reliever inhaler more often"
            general = "Index is Very High, General population, Reduce physical exertion, particularly outdoors, especially if you experience symptoms such as cough or sore throat"
        elif int(air_quality) >= 7:
            risk = "Index is High, At-risk individuals*, Adults and children with lung problems, and adults with heart problems, should reduce strenuous physical exertion, particularly outdoors, and particularly if they experience symptoms. People with asthma may find they need to use their reliever inhaler more often. Older people should also reduce physical exertion"
            general = "Index is High, General population, Anyone experiencing discomfort such as sore eyes, cough or sore throat should consider reducing activity, particularly outdoors"
        elif air_quality >= 4:
            risk = "Index is Moderate, At-risk individuals*, Adults and children with lung problems, and adults with heart problems, who experience symptoms, should consider reducing strenuous physical activity, particularly outdoors"
            general = "Index is Moderate, General population, Enjoy your usual outdoor activities"
        elif air_quality <= 3:
            risk = "Index is Low, At-risk individuals*, Enjoy your usual outdoor activities"
            general = "Index is Low, General population, Enjoy your usual outdoor activities"

    return render_template("forecast.html", city_name=city_name, region=region, country=country, localtime=localtime,
                           current_temperature=current_temperature, current_wind=current_wind,
                           current_humidity=current_humidity, air_quality=air_quality,
                           weather_description=weather_description, risk=risk, general=general)


@app.route('/bmi', methods=['get', 'post'])
#@app.route('/bmi')
def bmi():
    if request.method == 'POST':
        height = float(request.form['height'])
        weight = float(request.form['weight'])
        if "username" in session:
            username = session['username']
            print(username)
            cur = connect.cursor()
            cur.execute(f"SELECT id, username, password, email from user WHERE username='{username}'")
            if cur is not None:
                # Get Stored hashed and salted password - Need to change fetch one to only return the one username
                data = cur.fetchone()
                id = data[0]
                username = data[1]
                password = data[2]
                email = data[3]
                print(username)
                print(type(username))

                bmi = float(weight/(height*height))
                calories = float(request.form['calories'])
                print("user is is", username)
                try:
                    cur = connect.cursor()
                    cur.execute(
                        "INSERT INTO health(weight,height, bmi, calories) VALUES (?,?, ?, ?)",
                          (weight, height, bmi, calories))
                except IntegrityError:
                    session.rollback()

                else:
                    connect.commit()

    return render_template("bmi.html")


@app.route('/update', methods=['GET', 'POST'])
def update():
    if request.method == 'POST':
        try:
            username = request.form['username']
            user = User.query.filter_by(username=username).first()
            user.lastname = request.form['lastname']
            user.email = request.form['email']
            password = request.form['password']
            hashed_password = bcrypt.generate_password_hash(
                password).decode('utf-8')
            user.password = hashed_password
        except IntegrityError:
            db.session.rollback()
            raise ValidationError('That email is taken. Please choose a different one.')
        else:
            db.session.commit()
    return render_template("update.html")


@app.route('/terms/')
def terms():
    return render_template('terms.html')

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if "username" in login_session:
        print(login_session['username'])
        name = login_session['username']
        user = User.query.filter_by(username=name).first()
        email = user.email
        if request.method == 'POST':
            if 'file1' not in request.files:
                return 'there is no file1 in form!'
            file1 = request.files['file1']
            path1 = os.path.join(app.config['UPLOAD_FOLDER'], file1.filename)
            file1.save(path1)
            user.path = path1
            db.session.commit()
    return render_template('profile.html', name = name, email=email)


@app.route('/gdpr/')
def gdpr():
    return render_template('gdpr.html')


@app.route('/cookies/')
def cookies():
    return render_template('cookies.html')


@app.route('/js/')
def js():
    return render_template('js.html')


@app.route('/rating/')
def rating():
    return render_template('rating.html')


@app.route('/privacy/')
def privacy():
    return render_template('privacy.html')


@app.route('/logout')
def logout():
    #del login_session['username']
    session.pop('username', None) 
    return redirect(url_for('login'))

if __name__ == "__main__":
    #app_dir = op.realpath(os.path.dirname(__file__))
    #with app.app_context():
        #db.create_all()
    app.run(debug=True)