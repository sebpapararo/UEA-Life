from flask import Flask, redirect, render_template, request, flash, make_response, g
import functions
import sqlite3
import re
import uuid
import datetime
import os
from base64 import b64encode, b64decode
import validSessions
from flask_mail import Mail, Message

# Configuration Statements
app = Flask(__name__, template_folder="templates")
DATABASE = 'database.db'
sslContext = ('server.crt', 'server.key')
# TODO: 25/02/2020 research what these do
app.secret_key = os.urandom(64)
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT = 465,
    MAIL_USE_SSL = True,
    MAIL_USERNAME = 'uealifedss@gmail.com',
    MAIL_PASSWORD = '8pw9X$a%bHZkHz8&@ZeU',
)
mail = Mail(app)


# Database Methods - Courtesy of Oli
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)

    def make_dicts(cursor, row):
        return dict((cursor.description[idx][0], value)
                    for idx, value in enumerate(row))

    db.row_factory = make_dicts
    return db


def query_db(query, args=(), one=False):
    cur = None
    rv = None
    try:
        cur = get_db().execute(query, args)
        rv = cur.fetchall()
    except sqlite3.Error as e:
        app.logger.info('Database error: %s' % e)
    except Exception as e:
        app.logger.info('Exception in query_db: %s' % e)
    finally:
        if cur:
            cur.close()
    return (rv[0] if rv else None) if one else rv


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


# Routes
@app.route('/', methods=['GET'])
def index():
    return render_template('/index.html', title="UEA Life | Home")


@app.route('/login', methods=['POST'])
def login():
    # If the fields are not emtpy
    if request.form['email'] != '' and request.form['password'] != '':
        email = functions.sanitiseInputs(request.form['email'])
        # If the user exists in the database
        if query_db('SELECT COUNT(email) FROM users WHERE email = "%s"' % email) and \
                query_db('SELECT COUNT(email) FROM users WHERE email = "%s"' % email)[0].get('COUNT(email)') == 1:
            # Check if the password is correct
            retrievedSalt = query_db('SELECT salt FROM users where email = "%s"' % email)[0].get('salt')
            retrievedSalt = b64decode(retrievedSalt.encode('utf-8'))
            if query_db('SELECT password FROM users WHERE email = "%s"' % email)[0].get('password') == functions.generateHashedPass(retrievedSalt, request.form['password']):
                # Check if the reCaptcha is valid
                if functions.verifyCaptcha():

                    cookieId = os.urandom(64)
                    cookieId = b64encode(cookieId)
                    expiryDate = datetime.datetime.today() + datetime.timedelta(days=2)
                    userId = query_db('SELECT id FROM users where email = "%s"' % email)[0].get('id')
                    ipAddr = request.remote_addr
                    cookieValue = [userId, expiryDate, ipAddr]
                    validSessions.addSession(cookieId, cookieValue)

                    response = make_response(redirect('/dashboard'))
                    # TODO: 03/03/2020 change secure to True
                    response.set_cookie('userSession', cookieId, samesite='strict', secure=False, httponly=True, expires=expiryDate)

                    flash('Successfully logged in as %s' % email)
                    return response
                else:
                    flash('Invalid Captcha!')
            else:
                flash('The username or password is incorrect!')
        else:
            flash('The username or password is incorrect!')
    else:
        flash('The username and password fields cannot be left blank!')
    return redirect('/')


@app.route('/logout')
def logout():
    userCookie = functions.getCookie()
    validSessions.removeSession(userCookie)

    cookieId = os.urandom(64)
    cookieId = b64encode(cookieId)
    response = make_response(redirect('/'))
    # TODO: 03/03/2020 change secure to True
    response.set_cookie('userSession', cookieId, samesite='strict', secure=False, httponly=True, expires=0)

    flash('Successfully logged out!')
    return response


@app.route('/dashboard', methods=['GET'])
def dashboard():
    userCookie = functions.getCookie()

    if validSessions.checkSession(userCookie) is False:
        flash('Mate, you dont have a session hackerman! Go and login')
        return redirect('/')

    uid = validSessions.checkSession(userCookie)
    username = query_db('SELECT username FROM profiles where id = "%s"' % uid)[0].get('username')

    flash('Nice one bro! You are logged in as: ' + username)
    return render_template('/dashboard.html', title="UEA Life | Dashboard")


#######################################################################################################################
@app.route('/newPost', methods=['GET'])
def newPost():
    return render_template('/newPost.html', title="UEA Life | New Post")


@app.route('/createPost', methods=['POST'])
def createPost():
    print(request.form)
    # username = request.form.get('username', None)
    cats = ['General', 'Finance', 'Accommodation', 'Student Union', 'Local Area', 'Travel']
    category = request.form.get('category', None)
    title = request.form.get('title', None)
    content = request.form.get('content', None)

    userCookie = functions.getCookie()
    posted_by = validSessions.checkSession(userCookie)
    print(posted_by)

    tod = datetime.datetime.today().strftime('%d/%m/%Y %H:%M')
    # uid = "0037d9b5-681d-4b23-a6c8-c7d061a78521"

    if category not in cats:
        flash('Incorrect Category Selected Dick!!')
        return redirect('/newPost')
    category = functions.sanitiseInputs(category)
    if category == '':
        flash('Really?? Category')
        return redirect('/newPost')

    if title is None:
        flash('Title not sent')
        return redirect('/newPost')
    title = functions.sanitiseInputs(title)
    if title == '':
        flash('Really??? Title??')
        return redirect('/newPost')

    if content is None:
        flash('Content Not Sent')
        return redirect('/newPost')
    content = functions.sanitiseInputs(content)
    if content == '':
        flash('Really?!?! Content')
        return redirect('/newPost')

    # if query_db('SELECT verified FROM users WHERE username = "%s"' % session['username'])[0].get('verified') == 1:
    query = 'INSERT INTO posts (posted_by, category, title, content, posted_on) VALUES("%s","%s","%s","%s","%s");' % \
            (posted_by, category, title, content, tod)
    query_db(query)
    get_db().commit()
    print(query)
    return redirect('/dashboard')
    # else:
    #     flash('You must verify account before posting')
    #     return redirect('/dashboard')

########################################################################################################################


@app.route('/accountSettings', methods=['GET', 'POST'])
def accountSettings():
    return render_template('/settings.html', title="UEA Life | Create Post")


@app.route('/accountSettings/updateUsername', methods=['POST'])
def updateUsername():
    # TODO: add more checks here (see createAccount as example)

    # TODO: Get these from the request
    username = request.form.get('username', None)
    uid = "0037d9b5-681d-4b23-a6c8-c7d061a78521" # TODO: get from request

    # Check they have sent a field called username
    if username is None:
        flash('Username field not sent mate')
        return redirect('/accountSettings')

    # Sanitising inputs
    username = functions.sanitiseInputs(username)

    #  Check username is not empty
    if username == '':
        flash('Username cannot be empty you cheeky cunt')
        return redirect('/accountSettings')

    # Check if username has already been taken
    if query_db('SELECT COUNT(username) FROM profiles WHERE username = "%s"' % username) and \
    query_db('SELECT COUNT(username) FROM profiles WHERE username = "%s"' % username)[0].get('COUNT(username)') != 0:
        flash("Username already in use. Please pick another one.")
        return redirect('/accountSettings')

    # Update requesting users username to the supplied
    query_db('UPDATE profiles SET username=? WHERE id=?', [username, uid])
    get_db().commit()

    flash('Username updated successfully!')
    return redirect('/accountSettings')

# Render the register html
@app.route('/register', methods=['GET'])
def register():
    return render_template('/register.html', title="UEA Life | Register")


# Creates a new user account
@app.route('/register/createAccount', methods=['POST'])
def createAccount():
    # If none of the fields are emtpy
    # TODO: 25/02/2020 check if XSS works in password field as it is not being sanitised
    if request.form['username'] != '' and request.form['email'] != '' and request.form['password'] != '' and \
            request.form['verifyPassword'] != '':
        username = functions.sanitiseInputs(request.form['username'])
        email = functions.sanitiseInputs(request.form['email'])
        level = functions.sanitiseInputs(request.form['level'])
        school = functions.sanitiseInputs(request.form['school'])
        # Verify the email is in the correct format using a regular expression
        if re.match('^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email):
            # Check the username matches the allowed format
            if re.match("^[A-Za-z0-9_-]*$", username):
                # Check the email does not exist in the database
                if query_db('SELECT COUNT(email) FROM users WHERE email = "%s"' % email) and \
                        query_db('SELECT COUNT(email) FROM users WHERE email = "%s"' % email)[0].get('COUNT(email)') == 0:
                    # Check the username does not exist in the database
                    if query_db('SELECT COUNT(username) FROM profiles WHERE username = "%s"' % username) and \
                            query_db('SELECT COUNT(username) FROM profiles WHERE username = "%s"' % username)[0].get('COUNT(username)') == 0:
                        # Check the passwords match each other
                        if request.form['password'] == request.form['verifyPassword']:
                            # Check the password is valid, according to the rules we set out
                            if functions.validatePassword(request.form['password']):
                                # Check the reCaptcha has been completed properly
                                if functions.verifyCaptcha():
                                    # Generate random uuid to be the user id
                                    # TODO: 25/02/2020 Learn how this works again
                                    userId = str(uuid.uuid4())

                                    # Get the current date and time
                                    dateAndTime = datetime.datetime.today().strftime('%d/%m/%y %H:%M')

                                    # Create the salt and pass it into the hashing algorithm with the password
                                    userSalt = functions.generateSalt()

                                    hashedPassword = functions.generateHashedPass(userSalt, request.form['password'])
                                    userSalt = b64encode(userSalt)

                                    # Compose the queries for adding a new user to the database
                                    userQuery = 'INSERT INTO users(id, created_on, password, salt, email) VALUES ("%s", "%s", "%s", "%s", "%s")' \
                                                % (userId, dateAndTime, hashedPassword, userSalt.decode('utf-8'), email)
                                    profileQuery = 'INSERT INTO profiles(id, username, last_active, level, school) VALUES ("%s", "%s", "%s", "%s", "%s")' \
                                                   % (userId, username, dateAndTime, level, school)

                                    # Execute the queries and commit the changes
                                    query_db(userQuery)
                                    query_db(profileQuery)
                                    get_db().commit()

                                    # Create random key for password reset
                                    key = b64encode(os.urandom(32))
                                    hashedKey = functions.generateHashedKey(key)

                                    verifyEmailQuery = 'INSERT INTO verifyEmails(key, id) VALUES ("%s", "%s")' % (hashedKey, userId)
                                    query_db(verifyEmailQuery)
                                    get_db().commit()

                                    # send an email with a link to verify_email page with the id given
                                    # TODO: 03/03/2020 change link to https before submitting
                                    link = 'http://127.0.0.1:5000/verify_email?key=%s&id=%s' % (key.decode(), userId)
                                    msg = Message("Verify Email - UEA Life", sender="uealifedss@gmail.com",
                                                  recipients=[email])
                                    messageBody = 'Hi %s, please click this link to verify your email: %s' % (
                                        username, link)
                                    msg.body = messageBody
                                    mail.send(msg)

                                    flash('Account has been created, please login!')
                                    return redirect('/')
                                else:
                                    flash('Invalid reCaptcha!')
                            else:
                                flash('Invalid password! Please follow the rules')
                        else:
                            flash('Passwords do not match!')
                    else:
                        flash("Invalid username. Please pick another one.")
                else:
                    flash('Invalid email. Please pick another one.')
            else:
                flash('Username contained invalid characters!')
        else:
            flash('Email address was invalid!')
    else:
        flash('All fields must not be empty!')
    return redirect('/register')


@app.route('/verify_email', methods=['GET'])
def verify_account():
    # get id from url
    linkKey = request.args.get('key')
    userId = request.args.get('id')

    # this if statement maks sure the logged in user or the non-logged in user cannot see the error messages for verify email
    if linkKey is not None:
        # check if verified already
        if query_db('SELECT verified FROM users WHERE id = "%s"' % userId)[0].get('verified') == 1:
            flash('Your account is already verified!')
        else:
            # check against db
            if functions.generateHashedKey(linkKey.encode()) == query_db('SELECT key FROM verifyEmails WHERE id = "%s"' % userId)[0].get('key'):
                # set verify in db to true
                query_db('UPDATE users SET verified = 1 WHERE id = "%s"' % userId)
                get_db().commit()
                flash('The account is now verified.')
            else:
                flash(
                    'Something went wrong. Try logging in to send another email (and don\'t forget to check your spam folder!)')
        return render_template('dashboard.html')
    else:
        return redirect('/')


# @app.route('/resend_verify/', methods=['POST'])
# def resend_verify():
#     # get uuid from database
#     id = str(uuid.uuid4())
#     hashedID = bcrypt.generate_password_hash(id).decode('utf-8')
#     query_db('UPDATE users SET uuid = "%s" WHERE username = "%s"' % (hashedID, session['username']))
#     get_db().commit()
#     email = query_db('SELECT email FROM users WHERE username = "%s"' % session['username'])[0].get('email')
#
#     # send an email with a link to verify_email page with the id given
#     link = 'https://127.0.0.1:5000/verify_email?id=%s&username=%s' % (id, session['username'])
#     msg = Message("Verify Email - Norfolk Music", sender="se2cwk@gmail.com",
#                   recipients=[email])
#     messageBody = 'Hi %s, please click this link to verify your email: %s' % (session['username'], link)
#     msg.body = messageBody
#     mail.send(msg)
#     flash('Email has been sent')
#     return redirect('/dashboard/')


if __name__ == '__main__':
    # TODO: 11/02/2020 Change debug to False before submitting
    # app.run(host='127.0.0.1', port=5000, debug=True, ssl_context=sslContext)
    app.run(host='127.0.0.1', port=5000, debug=True)
