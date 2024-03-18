from flask import Flask, flash, session, render_template, redirect
import cgi, os
from flask import Flask, render_template, url_for, redirect, request
from flask import session as login_session
from flask_bcrypt import Bcrypt
import sqlite3
from flask_admin import Admin, form
from flask import Flask, flash, request, redirect, url_for
import requests
import json
from typing import Union, Type
import os

#from cs50 import SQL
from flask import Flask, flash, json, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from datetime import datetime
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
#from helpers import apology, passwordValid
#from flask_login import login_required, passwordValid
from flask_login import login_required
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required
#import requests
import urllib.parse

from flask import redirect, render_template, request, session
from functools import wraps



app = Flask(__name__, static_folder='static')
app.secret_key = 'any random string'


login_manager = LoginManager(app)
bcrypt = Bcrypt(app)
login_manager.init_app(app)


UPLOAD_FOLDER = 'static'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

connect = sqlite3.connect(r'C:\Users\Bongeka.Mpofu\DB Browser for SQLite\\healthAdvice.db', check_same_thread=False)

#connect = SQL('sqlite:///C:\\Users\\Bongeka.Mpofu\\DB Browser for SQLite\\healthAdvice.db')
connect.execute(
    'CREATE TABLE IF NOT EXISTS role (id INTEGER NOT NULL PRIMARY KEY autoincrement, name TEXT)')

connect.execute(
    'CREATE TABLE IF NOT EXISTS messages(username TEXT, subject TEXT, message TEXT)')

connect.execute('CREATE TABLE IF NOT EXISTS transactions (transactID INTEGER NOT NULL PRIMARY KEY autoincrement, userID INTEGER NOT NULL, eventID INTEGER NOT NULL, tickets INTEGER NOT NULL, transTime TIMESTAMP DEFAULT CURRENT_TIMESTAMP, dateBooked TIMESTAMP)')


#connect.execute('CREATE TABLE IF NOT EXISTS events (eventID INTEGER NOT NULL, eventName VARCHAR NOT NULL, ticketsLeft INTEGER NOT NULL, type VARCHAR NOT NULL, startDate date NOT NULL, endDate date NOT NULL, description VARCHAR NOT NULL, venueID INTEGER NOT NULL, adminID	INTEGER NOT NULL, endTime time NOT NULL, startTime time NOT NULL )')
connect.execute('CREATE TABLE IF NOT EXISTS events (eventID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, eventName VARCHAR NOT NULL,ticketsLeft INTEGER NOT NULL, type VARCHAR NOT NULL, startDate date NOT NULL, endDate date NOT NULL, description VARCHAR NOT NULL, venueID INTEGER NOT NULL,adminID INTEGER NOT NULL, endTime TEXT , startTime TEXT )')

connect.execute(
    'CREATE TABLE IF NOT EXISTS user (id INTEGER NOT NULL PRIMARY KEY autoincrement, username VARCHAR NOT NULL UNIQUE, \
firstname TEXT, lastname TEXT, email NOT NULL UNIQUE, password TEXT, agreed_terms TEXT, regDateTime TIMESTAMP DEFAULT CURRENT_TIMESTAMP, path TEXT, role_code INTEGER)')


connect.execute(
    'CREATE TABLE IF NOT EXISTS health (hid INTEGER NOT NULL PRIMARY KEY autoincrement, weight REAL, height REAL, bmi REAL, calories REAL, assess_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP, user_id INTEGER NOT NULL, FOREIGN KEY (user_id) REFERENCES user (id)\
                                   )')
connect.execute(
    'CREATE TABLE IF NOT EXISTS weather (wid INTEGER NOT NULL PRIMARY KEY autoincrement, current_temp REAL, \
current_pressure  REAL, current_humidity REAL, current_airindex REAL, weather_description REAL, date_taken TIMESTAMP)')


connect.execute(
    'CREATE TABLE IF NOT EXISTS venues (venueID INTEGER NOT NULL PRIMARY KEY autoincrement, venueName VARCHAR NOT NULL,capacity INTEGER NOT NULL,address1 ARCHAR NOT NULL,address2 VARCHAR NOT NULL, city VARCHAR NOT NULL,county VARCHAR NOT NULL,postcode VARCHAR NOT NULL, adminID INTEGER NOT NULL  )')


# Both
venueQry = "SELECT * FROM venues WHERE venueID = :venueID"
eventQry = "SELECT * FROM events WHERE eventID = :eventID"
allEventQry = "SELECT * FROM events"
allVenueQry = "SELECT * FROM venues"

@app.route('/')
@app.route('/home')
def home():
    cur = connect.cursor()
    cur.execute("SELECT * FROM events")
    events = cur.fetchall()
    print(events)

    cur.close()
    #connect.commit()

    #select venues
    cur = connect.cursor()
    cur.execute("SELECT * FROM venues")
    venues = cur.fetchall()
    print(venues)
    cur.close()
    output = []
    for item in events:
        dic = {}
        dic["eventID"] = item[0]
        dic["eventName"] = item[1]
        dic["ticketsLeft"] = item[2]
        dic["type"] = item[3]
        dic["startDate"] = item[4]
        dic["endDate"] = item[5]
        dic["description"] = item[6]
        output.append(dic)
    print(output)
    print(type(output))

    return render_template("home.html", output=output)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        user_entered = request.form['password']
        cur = connect.cursor()
        cur.execute(f"SELECT id, username, password from user WHERE username='{username}'")
        if cur is not None:
            # Get Stored hashed and salted password - Need to change fetch one to only return the one username
            data = cur.fetchone()
            print(data)
            id = data[0]
            password = data[2]

            print("user id is ",id)
            print(password)
            print(type(password))
            # Compare Password with hashed password- Bcrypt
            if bcrypt.check_password_hash(password, user_entered):
                session['logged_in'] = True
                session['username'] = username
                session['id'] = id

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
        cur = connect.cursor()
        cur.execute("SELECT * FROM events")
        events = cur.fetchall()
        print(events)

        cur.close()
        #connect.commit()

        #select venues
        cur = connect.cursor()
        cur.execute("SELECT * FROM venues")
        venues = cur.fetchall()
        print(venues)
        cur.close()
        output = []
        for item in events:
            dic = {}
            dic["eventID"] = item[0]
            dic["eventName"] = item[1]
            dic["ticketsLeft"] = item[2]
            dic["type"] = item[3]
            dic["startDate"] = item[4]
            dic["endDate"] = item[5]
            dic["description"] = item[6]
            output.append(dic)
        print(output)
        print(type(output))

        return render_template('welcome.html', output=output)
    else:
        return redirect(url_for('login'))



@app.route("/book/<eventID>", methods=["POST", "GET"])
#@login_required
def book(eventID):

    if request.method == "POST":

        id = session.get("id")

        if not request.form.get("tickets"):
            msg = "no tic"
            return render_template("error.html", msg=msg)
        if not eventID:
            msg = "no id"
            return render_template("error.html", msg=msg)
        else:
            cur = connect.cursor()
            event = cur.execute(f"SELECT * FROM events WHERE eventID ='{eventID}'")
            data = cur.fetchone()
            tLef = data[2]
            print("original ticket numbers are ", tLef)
            tic = int(request.form.get("tickets"))
            print("tickets bought number is ", tic)
            #tleft = int(tLef - tic)
            #print("Tickets left ", tLeft)
            dateBooked = request.form.get("bookdate")
            print(dateBooked)
            #print("Tickets left are ", tLeft)
            cur.execute("INSERT INTO transactions (userID, eventID, tickets, dateBooked) VALUES (?, ?, ?, ?)",(id, eventID, tic, dateBooked))
            #cur.execute("INSERT INTO health(weight,height, bmi, calories, user_id) VALUES (?,?, ?, ?, ?)",(weight, height, bmi, calories,id))

            cur.execute("UPDATE events SET ticketsLeft = ? WHERE eventID =?", (int(tLef - tic), eventID))
            connect.commit()
            msg = "Success!"
            return render_template("confirmation.html", msg=msg)
    else:
        if not eventID:
            msg = "no id"
            return render_template("error.html", msg=msg)

        #event = cur.execute(eventQry, eventID=eventID)
        cur = connect.cursor()
        event = cur.execute(f"SELECT * FROM events WHERE eventID ='{eventID}'")
        data = cur.fetchone()
        print(data)
        eventID = data[0]
        eventName = data[1]
        ticketsLeft = data[2]
        type = data[3]
        description = data[6]
        startDate = data[4]
        endDate = data[5]

        #id = session['id']

        id=session.get("id")

        usr = cur.execute(f"SELECT * FROM user WHERE id ='{id}'")
        data = cur.fetchone()
        print(data)
        id = data[0]
        username = data[1]
        firstname = data[2]
        lastname = data[3]
        email = data[4]

        #return render_template("booking.html", event=event, username=username, firstname=firstname, lastname=lastname, email=email)
        return render_template("booking.html", eventID=eventID, eventName=eventName, ticketsLeft=ticketsLeft, type=type, description=description, startDate=startDate, endDate=endDate, username=username, firstname=firstname, lastname=lastname, email=email)


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
def bmi():
    print("testing bmi")
    username = session['username']
    print(username)
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

                bmi = float(weight/(height*height))
                calories = float(request.form['calories'])
                print("user is is", username)
                try:
                    print("im here")
                    cur = connect.cursor()
                    cur.execute(
                        "INSERT INTO health(weight,height, bmi, calories, user_id) VALUES (?,?, ?, ?, ?)",
                          (weight, height, bmi, calories,id))
                except IntegrityError:
                    session.rollback()

                else:
                    connect.commit()

    return render_template("bmi.html")


@app.route('/update', methods=['GET', 'POST'])
def update():
    if request.method == 'POST':
        if "username" in session:
            username = session['username']
            lastname = request.form['lastname']
            email = request.form['email']
            hpassword = request.form['password']
            hashed_password = bcrypt.generate_password_hash(
                hpassword).decode('utf-8')
            password = hashed_password

            print(username)
            try:
                cur = connect.cursor()
                cur.execute(
                    "UPDATE user SET lastname=?,email=?,password=? WHERE username=?".format(
                        username),
                    (lastname, email, password, username,))
                connect.commit()
            except IntegrityError:
                session.rollback()
                raise ValidationError('That email is taken. Please choose a different one.')
            else:
                connect.commit()
    return render_template("update.html")


@app.route('/terms/')
def terms():
    return render_template('terms.html')

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if "username" in session:
        username = session['username']
        print(username)
        cur = connect.cursor()
        cur.execute(f"SELECT id, username, email, path from user WHERE username='{username}'")

        data = cur.fetchone()
        print("hellos first", data)
        #cur.execute(f"SELECT id, username, email, height, weight, bmi from user INNER JOIN health ON health.hid = user.id WHERE username='{username}'")

        if cur is not None:
            # Get Stored hashed and salted password - Need to change fetch one to only return the one username

            id = data[0]
            username = data[1]
            email = data[2]
            path = data[3]

            if request.method == 'POST':
                if 'file1' not in request.files:
                    return 'there is no file1 in form!'
                file1 = request.files['file1']
                path = os.path.join(app.config['UPLOAD_FOLDER'], file1.filename)
                file1.save(path)
                print(path)
                try:
                    cur = connect.cursor()
                    print(path)
                    cur.execute("UPDATE user SET path=? WHERE username=?".format(username), (path, username,))
                except:
                    #session.rollback()
                    print('User details already exist. Try again ')
                else:
                    connect.commit()
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('profile.html', name = username, email=email, path=path)


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

@app.route('/graph/')
def graph():
    return render_template('graph.html')


@app.route('/privacy/')
def privacy():
    return render_template('privacy.html')

@app.route('/contact/')
def contact():
    return render_template('contact.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == "__main__":

    app.run(debug=True)
