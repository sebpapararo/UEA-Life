from flask import Flask, redirect, render_template, request, flash, make_response, g, Markup
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
    MAIL_PORT=465,
    MAIL_USE_SSL=True,
    MAIL_USERNAME='uealifedss@gmail.com',
    MAIL_PASSWORD='8pw9X$a%bHZkHz8&@ZeU',
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
    # Is Authed Guard, redirects to the login
    userCookie = functions.getCookie()
    if validSessions.checkSession(userCookie) is not False:
        flash('You are already logged in you baboon!')
        return redirect('/dashboard')

    return render_template('/index.html', title="UEA Life | Home")


@app.route('/login', methods=['POST'])
def login():
    # Is Authed Guard, redirects to the login
    userCookie = functions.getCookie()
    if validSessions.checkSession(userCookie) is not False:
        flash('You are already logged in you baboon!')
        return redirect('/dashboard')

    # If the fields are not emtpy
    if request.form['email'] != '' and request.form['password'] != '':
        email = functions.sanitiseInputs(request.form['email'])
        # If the user exists in the database
        if query_db('SELECT COUNT(email) FROM users WHERE email = "%s"' % email) and \
                query_db('SELECT COUNT(email) FROM users WHERE email = "%s"' % email)[0].get('COUNT(email)') == 1:
            # Check if the password is correct
            retrieved_salt = query_db('SELECT salt FROM users where email = "%s"' % email)[0].get('salt')
            retrieved_salt = b64decode(retrieved_salt.encode())
            if query_db('SELECT password FROM users WHERE email = "%s"' % email)[0].get('password') == functions.generateHashedPass(retrieved_salt, request.form['password']):
                # Check if the reCaptcha is valid
                if functions.verifyCaptcha():

                    cookie_id = os.urandom(64)
                    cookie_id = b64encode(cookie_id)
                    expiry_date = datetime.datetime.today() + datetime.timedelta(days=7)
                    user_id = query_db('SELECT id FROM users where email = "%s"' % email)[0].get('id')
                    ip_addr = request.remote_addr
                    cookie_value = [user_id, expiry_date, ip_addr]
                    validSessions.addSession(cookie_id, cookie_value)

                    new_last_active = datetime.datetime.today()
                    new_last_active = datetime.datetime.strftime(new_last_active, '%Y-%m-%d %H:%M')
                    uid = query_db('SELECT id FROM users WHERE email = "%s"' % email)[0].get('id')
                    query_db('UPDATE profiles SET last_active="%s" WHERE id="%s"' % (new_last_active, uid))
                    get_db().commit()

                    response = make_response(redirect('/dashboard'))
                    # TODO: 03/03/2020 change secure to True
                    response.set_cookie('userSession', cookie_id, samesite='strict', secure=False, httponly=True,
                                        expires=expiry_date)

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
    user_cookie = functions.getCookie()
    if validSessions.checkSession(user_cookie) is False:
        flash('You can\'t logout if you weren\'t logged in, you meathead!')
        return redirect('/')

    validSessions.removeSession(user_cookie)

    cookie_id = os.urandom(64)
    cookie_id = b64encode(cookie_id)
    response = make_response(redirect('/'))
    # TODO: 03/03/2020 change secure to True
    response.set_cookie('userSession', cookie_id, samesite='strict', secure=False, httponly=True, expires=0)

    flash('Successfully logged out!')
    return response


@app.route('/dashboard', methods=['GET'])
def dashboard():
    # Is Authed Guard, redirects to the login
    user_cookie = functions.getCookie()
    if validSessions.checkSession(user_cookie) is False:
        flash('Mate, you dont have a session hackerman! Go and login')
        return redirect('/')

    uid = validSessions.checkSession(user_cookie)
    logged_in_as = query_db('SELECT username FROM profiles where id = "%s"' % uid)[0].get('username')

    verified = query_db('SELECT verified FROM users where id = "%s"' % uid)[0].get('verified')
    if verified == 0:
        flash(Markup('Your account is not verified! <a href="/resend_verify" class="alert-link">Click here</a> '
                     'to resend the verification email!'))

    # TODO(C): Check this actually works properly
    query = "SELECT posts.id AS id, posts.Posted_on, posts.Category, posts.Title, posts.Content, profiles.Username  FROM posts INNER JOIN profiles ON posts.posted_by = profiles.id"
    results = query_db(query)

    query = "SELECT replies.id, replies.posted_on, replies.posted_to, profiles.username AS posted_by, replies.content FROM replies INNER JOIN profiles ON replies.posted_by = profiles.id"
    replies = query_db(query)

    return render_template('/dashboard.html', title="UEA Life | Dashboard", data=results, user=logged_in_as, replies=replies)


# TODO: Add session checks
@app.route('/profile', methods=['GET'])
def profile():
    # Is Authed Guard, redirects to the login
    user_cookie = functions.getCookie()
    if validSessions.checkSession(user_cookie) is False:
        flash('Mate, you dont have a session hackerman! Go and login')
        return redirect('/')

    uid = validSessions.checkSession(user_cookie)
    logged_in_as = query_db('SELECT username FROM profiles where id = "%s"' % uid)[0].get('username')

    # Gets the username from the URL, if one is not sent defaults to None
    username = request.args.get('username', None)

    # Check the username field has been sent
    if username is None:
        flash('No username sent mate!')
        return redirect('/dashboard')

    # Gets the users profile
    user_profile = query_db('SELECT * FROM profiles WHERE username = "%s"' % username)

    # When more than expected profiles are received, throw error.
    if(len(user_profile) != 1):
        flash('User Does Not Exist!')
        return redirect('/dashboard')

    # Get single profile
    user_profile = user_profile[0]

    # gets the users post
    post_count = query_db('SELECT COUNT(*) FROM posts WHERE posted_by = "%s";' % user_profile['id'])

    # TODO: hacky way of getting this, change if have time!
    user_profile['post_count'] = post_count[0]['COUNT(*)']

    # Get Date Joined
    date_joined = query_db('SELECT Created_on FROM users WHERE id = "%s";' % user_profile['id'])
    user_profile['date_joined'] = date_joined[0]['created_on']

    # Get the Content of the posts
    posts = query_db('SELECT * FROM posts WHERE posted_by = "%s";' % user_profile['id'])

    # TODO: dont use [0]
    return render_template('/profile.html', title="UEA Life | Someones profile", userProfile=user_profile,
                           usersPosts=posts, user=logged_in_as)


@app.route('/newPost', methods=['GET'])
def newPost():
    # Is Authed Guard, redirects to the login
    user_cookie = functions.getCookie()
    if validSessions.checkSession(user_cookie) is False:
        flash('Mate, you dont have a session hackerman! Go and login')
        return redirect('/')
    uid = validSessions.checkSession(user_cookie)
    logged_in_as = query_db('SELECT username FROM profiles where id = "%s"' % uid)[0].get('username')

    if query_db('SELECT verified FROM users WHERE id = "%s"' % uid)[0].get('verified') == 1:
        return render_template('/newPost.html', username=uid, user=logged_in_as)
    else:
        flash('Behave - Verify account before posting')
        return redirect('/dashboard')


@app.route('/createPost', methods=['POST'])
def createPost():
    # Is Authed Guard, redirects to the login
    user_cookie = functions.getCookie()
    if validSessions.checkSession(user_cookie) is False:
        flash('Mate, you dont have a session hackerman! Go and login')
        return redirect('/')

    # username = request.form.get('username', None)
    cats = ['General', 'Finance', 'Accommodation', 'Student Union', 'Local Area', 'Travel']
    category = request.form.get('category', None)
    title = request.form.get('title', None)
    content = request.form.get('content', None)

    posted_by = validSessions.checkSession(user_cookie)

    tod = datetime.datetime.today().strftime('%d/%m/%Y %H:%M')

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

    query = 'INSERT INTO posts (posted_by, category, title, content, posted_on) VALUES("%s","%s","%s","%s","%s");' % \
            (posted_by, category, title, content, tod)
    query_db(query)
    get_db().commit()
    return redirect('/dashboard')

@app.route('/createReply', methods=['POST'])
def createReply():

    # Check user is logged in
    user_cookie = functions.getCookie()
    if validSessions.checkSession(user_cookie) is False:
        flash('Mate, you dont have a session hackerman! Go and login')
        return redirect('/')

    # Reply to the post with the ID:
    replyTo = request.form.get('postId', None)
        # Check this field is being sent
    if replyTo is None:
        flash('You have not sent a reply field mate!')
        return redirect('/dashboard')

        # Check this field is correct (post with the ID exists)
    postExists = query_db('SELECT * FROM posts WHERE id="%s"' % replyTo)

        # If no post with provided ID exists, throw error and redirect
    if(len(postExists) != 1):
        flash('Mate, the post you are replying to does not exist!')
        return redirect('/dashboard')

        # Extract ID from query
    postId = postExists[0]['id']

    # Content of the reply:
    replyContent = request.form.get('replyBody', None)

    if replyContent is None:
        flash('You have not sent any reply content mate!')
        return redirect('/dashboard')

    if (replyContent == ''):
        flash('A reply cannot be empty matee!')
        return redirect('/dashboard')

    # Reply posted by user with ID:
    postedBy = validSessions.checkSession(user_cookie)
    # Time which user posted the reply:
    postedOn = datetime.datetime.today().strftime('%d/%m/%Y %H:%M')

    # Construct Insert Query
    query = 'INSERT INTO replies (posted_on, posted_to, posted_by, content) VALUES("%s","%s","%s","%s");' % \
            (postedOn, postId, postedBy, replyContent)
    query_db(query)
    get_db().commit()

    flash('Reply has been created')
    return redirect('/dashboard')


@app.route('/accountSettings', methods=['GET', 'POST'])
def accountSettings():
    # Is Authed Guard, redirects to the login
    user_cookie = functions.getCookie()
    if validSessions.checkSession(user_cookie) is False:
        flash('Mate, you dont have a session hackerman! Go and login')
        return redirect('/')

    uid = validSessions.checkSession(user_cookie)

    logged_in_as = query_db('SELECT username FROM profiles where id = "%s"' % uid)[0].get('username')

    if validSessions.checkSession(user_cookie) is False:
        flash('Mate, you dont have a session hackerman! Go and login')
        return redirect('/')

    uid = validSessions.checkSession(user_cookie)
    logged_in_as = query_db('SELECT username FROM profiles where id = "%s"' % uid)[0].get('username')

    return render_template('/settings.html', title="UEA Life | Profile Settings", user=logged_in_as)


@app.route('/accountSettings/updateUsername', methods=['POST'])
def updateUsername():
    # Is Authed Guard, redirects to the login
    user_cookie = functions.getCookie()
    if validSessions.checkSession(user_cookie) is False:
        flash('Mate, you dont have a session hackerman! Go and login')
        return redirect('/')

    # TODO: add more checks here (see createAccount as example)
    # TODO: 05/03/2020 Do not allow for current username
    # TODO: Get these from the request
    username = request.form.get('username', None)

    uid = validSessions.checkSession(user_cookie) # TODO: get from request

    # Check they have sent a field called username
    if username is None:
        flash('Username field not sent mate')
        return redirect('/accountSettings')

    if not re.match("^[A-Za-z0-9_-]*$", username):
        flash('Username contained invalid characters')
        return redirect('/accountSettings')

    # Sanitising inputs
    username = functions.sanitiseInputs(username)

    #  Check username is not empty
    if username == '':
        flash('Username cannot be empty you cheeky pr**k')
        return redirect('/accountSettings')

    # Check if username has already been taken
    if query_db('SELECT COUNT(username) FROM profiles WHERE username = "%s"' % username) and \
            query_db('SELECT COUNT(username) FROM profiles WHERE username = "%s"' % username)[0].get('COUNT(username)') != 0:
        flash("Username was invalid. Please pick another one.")
        return redirect('/accountSettings')

    # Update requesting users username to the supplied
    query_db('UPDATE profiles SET username="%s" WHERE id="%s"' % (username, uid))
    get_db().commit()

    flash('Username updated successfully!')
    return redirect('/accountSettings')

@app.route('/accountSettings/updateEmail', methods=['POST'])
def updateEmail():
    # Is Authed Guard, redirects to the login
    user_cookie = functions.getCookie()
    if validSessions.checkSession(user_cookie) is False:
        flash('Mate, you dont have a session hackerman! Go and login')
        return redirect('/')

    # TODO: add more checks here (see createAccount as example)
    # TODO: 05/03/2020 do not allow for current email
    # TODO: Get these from the request
    email = request.form.get('email', None)

    uid = validSessions.checkSession(user_cookie) # TODO: get from request

    # Check they have sent a field called username
    if email is None:
        flash('Email field not sent mate')
        return redirect('/accountSettings')

    # Verify the email is in the correct format using a regular expression
    if not re.match('^[A-Za-z0-9\.\+_-]+@[A-Za-z0-9\._-]+\.[a-zA-Z]*$', email):
        flash('Email contained invalid character!')
        return redirect('/accountSettings')

    # Sanitising inputs
    email = functions.sanitiseInputs(email)

    #  Check username is not empty
    if email == '':
        flash('Email cannot be empty you cheeky pr**k')
        return redirect('/accountSettings')

    # Check if email has already been taken
    if query_db('SELECT COUNT(email) FROM users WHERE email = "%s"' % email) and \
            query_db('SELECT COUNT(email) FROM users WHERE email = "%s"' % email)[0].get('COUNT(email)') != 0:
        flash("Email invalid. Please pick another one.")
        return redirect('/accountSettings')

    # Update requesting users email to the supplied
    query_db('UPDATE users SET email="%s" WHERE id="%s"' % (email, uid))
    query_db('UPDATE users SET verified=0 WHERE id="%s"' % uid)
    get_db().commit()

    flash('Email updated successfully!')
    return redirect('/accountSettings')


@app.route('/accountSettings/updatePassword', methods=['POST'])
def updatePassword():
    # Is Authed Guard, redirects to the login
    user_cookie = functions.getCookie()
    if validSessions.checkSession(user_cookie) is False:
        flash('Mate, you dont have a session hackerman! Go and login')
        return redirect('/')

    currentPassword = request.form.get('password', None)
    newPassword = request.form.get('newPassword', None)
    newPasswordCheck = request.form.get('newPasswordCheck', None)

    uid = validSessions.checkSession(user_cookie) # TODO: get from request

    # Check they have sent a field called password
    if currentPassword is None or currentPassword == '':
        flash('Email field not sent mate')
        return redirect('/accountSettings')

    if newPassword != newPasswordCheck:
        flash('Passwords did not match!')
        return redirect('/accountSettings')

    # Verify the email is in the correct format using a regular expression
    if not functions.validatePassword(newPassword):
        flash('Password was not valid!')
        return redirect('/accountSettings')

    # Make sure current password is correct
    userSalt = query_db('SELECT salt FROM users WHERE id = "%s"' % uid)[0].get('salt')
    userSalt = b64decode(userSalt.encode())
    if functions.generateHashedPass(userSalt, currentPassword) != query_db('SELECT password FROM users WHERE id = "%s"' % uid)[0].get('password'):
        flash('Current password was incorrect!')
        return redirect('/accountSettings')

    if currentPassword == newPassword:
        flash('Your new password was the same as the old one you melt!')
        return redirect('/accountSettings')

    newSalt = functions.generateSalt()
    newHashedPass = functions.generateHashedPass(newSalt, newPassword)
    newSalt = b64encode(newSalt)

    # Update requesting users email to the supplied
    query_db('UPDATE users SET password="%s", salt="%s" WHERE id="%s"' % (newHashedPass, newSalt.decode(), uid))
    get_db().commit()

    flash('Password updated successfully!')
    return redirect('/accountSettings')


@app.route('/forgotPassword', methods=['GET', 'POST'])
def forgotPassword():
    # Is Authed Guard, redirects to the login
    userCookie = functions.getCookie()
    if validSessions.checkSession(userCookie) is not False:
        flash('You are already logged in you donkey!')
        return redirect('/dashboard')

    if request.method == 'GET':
        return render_template('/forgotPassword.html', title="UEA Life | Forgot Password")
    else:

        email = functions.sanitiseInputs(request.form['email'])
        # Check the email entered  is valid
        if re.match('^[A-Za-z0-9\.\+_-]+@[A-Za-z0-9\._-]+\.[a-zA-Z]*$', email):
            # Check the reCaptcha was completed
            if functions.verifyCaptcha():

                # Create random key for email verification
                key = b64encode(os.urandom(32))
                hashedKey = functions.generateHashedKey(key)
                timestamp = datetime.datetime.today() + datetime.timedelta(minutes=15)
                timestamp = datetime.datetime.strftime(timestamp, '%Y-%m-%d %H:%M')

                # Make sure the email exists in teh database
                if query_db('SELECT COUNT(email) FROM users WHERE email = "%s"' % email) and \
                        query_db('SELECT COUNT(email) FROM users WHERE email = "%s"' % email)[0].get('COUNT(email)') == 0:
                    flash('Email has been sent')
                    return redirect('/')

                uid = query_db('SELECT id FROM users WHERE email = "%s"' % email)[0].get('id')
                username = query_db('SELECT username FROM profiles WHERE id = "%s"' % uid)[0].get('username')

                forgotPasswordQuery = 'INSERT INTO forgotPasswordRequests(key, id, expiresOn) VALUES ("%s", "%s", "%s")' % (hashedKey, uid, timestamp)
                query_db(forgotPasswordQuery)
                get_db().commit()

                # TODO: 03/03/2020 change link to https before submitting
                link = 'http://127.0.0.1:5000/passwordReset?key=%s&id=%s' % (key.decode(), uid)
                msg = Message("Password Reset - UEA Life", sender="uealifedss@gmail.com",
                              recipients=[email])
                messageBody = 'Hi %s,\n Please click the following link to reset your password:\n %s\n\nNotes: ' \
                              'This email expires 15 minutes after being requested.' % (username, link)
                msg.body = messageBody
                mail.send(msg)

                flash('Email has been sent')
                return redirect('/')
            else:
                flash('Invalid reCaptcha!')
        else:
            flash('Email address was invalid!')
    return redirect('/forgotPassword')


@app.route('/passwordReset', methods=['GET', 'POST'])
def passwordReset():
    # Is Authed Guard, redirects to the login
    userCookie = functions.getCookie()
    if validSessions.checkSession(userCookie) is not False:
        flash('You are already logged in you baboon!')
        return redirect('/dashboard')

    if request.method == 'GET':
        linkKey = request.args.get('key')
        linkKey = linkKey.replace(' ', '+')
        hashedKey = functions.generateHashedKey(linkKey.encode())
        userId = request.args.get('id')

        # this if statement make sure the logged in user or the non-logged in user cannot see the error messages for verify email
        if linkKey is not None:
            # Check the key in the url is valid and has no expired.

            if hashedKey == query_db('SELECT key FROM forgotPasswordRequests WHERE id = "%s"' % userId)[-1].get('key'):
                if datetime.datetime.today() < datetime.datetime.strptime(
                        query_db('SELECT expiresOn FROM forgotPasswordRequests WHERE key = "%s"' % hashedKey)[0].get('expiresOn'), '%Y-%m-%d %H:%M'):
                    return render_template('/passwordReset.html', title="UEA Life | Password Reset")
                else:
                    flash(Markup('Email has expired! <a href="/forgotPassword" class="alert-link">Click here</a> to request another!'))
            else:
                flash(Markup('Something went wrong. Try requesting another email  <a href="/forgotPassword" class="alert-link"> here!</a>'))
        return redirect('/')
    else:
        if request.form['password'] == request.form['verifyPassword']:
            if functions.validatePassword(request.form.get('password')):
                newSalt = functions.generateSalt()
                hashedPass = functions.generateHashedPass(newSalt, request.form['password'])
                newSalt = b64encode(newSalt)

                uid = request.form['id']

                query_db('UPDATE users SET password="%s", salt="%s" WHERE id="%s"' % (hashedPass, newSalt.decode(), uid))
                get_db().commit()
                flash('Password updated!')
                return redirect('/')
            else:
                flash('Invalid password! Please follow the rules')
        else:
            flash("Passwords do not match")
        return redirect('/passwordReset')


# Render the register html
@app.route('/register', methods=['GET'])
def register():
    return render_template('/register.html', title="UEA Life | Register")


########################################################################################################################
# Delete user account
@app.route('/accountSetting/delete_account', methods=['GET', 'POST'])
def delete_account():

    user_cookie = functions.getCookie()
    if validSessions.checkSession(user_cookie) is False:
        flash('Really?! You can\'t delete an account your not logged in to!')
        return redirect('/')
    uid = validSessions.checkSession(user_cookie)

    if request.form['verifyEmail'] is not None:

        email_to_delete = functions.sanitiseInputs(request.form['verifyEmail'])

        # If the user exists in the database
        if query_db('SELECT COUNT(email) FROM users WHERE email = "%s"' % email_to_delete) and \
                query_db('SELECT COUNT(email) FROM users WHERE email = "%s"' % email_to_delete)[0].\
                get('COUNT(email)') == 1:

            if functions.verifyCaptcha():

                update_query = 'UPDATE posts SET posted_by = "Deleted User" WHERE posted_by = "%s";' % uid
                query_db(update_query)
                delete_query = 'DELETE FROM users WHERE id = "%s";' % uid
                # TODO: 06/03/2020 remove from profiles
                # TODO: 06/03/2020 update the replies table to deleted user
                # TODO: 06/03/2020  delete from forgotpassword and verifyemail tables

                query_db(delete_query)
                get_db().commit()

                cookie_id = os.urandom(64)
                cookie_id = b64encode(cookie_id)
                response = make_response(redirect('/'))
                response.set_cookie('userSession', cookie_id, samesite='strict', secure=False, httponly=True, expires=0)

                return response
            else:
                flash('Are you a robot?')
        else:
            flash('Re-enter email address of account to be deleted')
    else:
        flash('Verify email of the account to be deleted')

    return redirect('/')


########################################################################################################################


# Creates a new user account
@app.route('/register/createAccount', methods=['POST'])
def createAccount():
    # Is Authed Guard, redirects to the login
    user_cookie = functions.getCookie()
    if validSessions.checkSession(user_cookie) is not False:
        flash('You are already logged in you donkey!')
        return redirect('/dashboard')

    # If none of the fields are emtpy
    # TODO: 25/02/2020 check if XSS works in password field as it is not being sanitised
    if request.form['username'] != '' and request.form['email'] != '' and request.form['password'] != '' and \
            request.form['verifyPassword'] != '':
        username = functions.sanitiseInputs(request.form['username'])
        email = functions.sanitiseInputs(request.form['email'])
        level = functions.sanitiseInputs(request.form['level'])
        school = functions.sanitiseInputs(request.form['school'])
        # Verify the email is in the correct format using a regular expression
        if re.match('^[A-Za-z0-9\.\+_-]+@[A-Za-z0-9\._-]+\.[a-zA-Z]*$', email):
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
                                    user_id = str(uuid.uuid4())

                                    # Get the current date and time
                                    date_and_time = datetime.datetime.today().strftime('%d/%m/%y %H:%M')

                                    # Create the salt and pass it into the hashing algorithm with the password
                                    user_salt = functions.generateSalt()

                                    hashed_password = functions.generateHashedPass(user_salt, request.form['password'])
                                    user_salt = b64encode(user_salt)

                                    # Compose the queries for adding a new user to the database
                                    user_query = 'INSERT INTO users(id, created_on, password, salt, email) VALUES ("%s", "%s", "%s", "%s", "%s")' \
                                                % (user_id, date_and_time, hashed_password, user_salt.decode('utf-8'), email)
                                    profile_query = 'INSERT INTO profiles(id, username, last_active, level, school) VALUES ("%s", "%s", "%s", "%s", "%s")' \
                                                   % (user_id, username, date_and_time, level, school)

                                    # Execute the queries and commit the changes
                                    query_db(user_query)
                                    query_db(profile_query)
                                    get_db().commit()

                                    # Create random key for email verification
                                    key = b64encode(os.urandom(32))
                                    hashed_key = functions.generateHashedKey(key)
                                    timestamp = datetime.datetime.today() + datetime.timedelta(minutes=15)
                                    timestamp = datetime.datetime.strftime(timestamp, '%Y-%m-%d %H:%M')

                                    verify_email_query = 'INSERT INTO verifyEmails(key, id, expiresOn) VALUES ("%s", "%s", "%s")' % (hashed_key, user_id, timestamp)
                                    query_db(verify_email_query)
                                    get_db().commit()

                                    # send an email with a link to verify_email page with the id given
                                    # TODO: 03/03/2020 change link to https before submitting
                                    link = 'http://127.0.0.1:5000/verify_email?key=%s&id=%s' % (key.decode(), user_id)
                                    msg = Message("Verify Email - UEA Life", sender="uealifedss@gmail.com",
                                                  recipients=[email])
                                    message_body = 'Hi %s,\n Please click the following link to verify your email:\n %s\n\nNotes: ' \
                                                  'This email expires 15 minutes after being requested.' % (username, link)
                                    msg.body = message_body
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
    linkKey = linkKey.replace(' ', '+')
    hashedKey = functions.generateHashedKey(linkKey.encode())
    userId = request.args.get('id')

    # this if statement make sure the logged in user or the non-logged in user cannot see the error messages for verify email
    if linkKey is not None:
        # check if verified already
        if query_db('SELECT verified FROM users WHERE id = "%s"' % userId)[0].get('verified') == 1:
            flash('Your account is already verified!')
        else:
            # check against db
            if hashedKey == query_db('SELECT key FROM verifyEmails WHERE id = "%s"' % userId)[-1].get('key'):
                if datetime.datetime.today() < datetime.datetime.strptime(
                        query_db('SELECT expiresOn FROM verifyEmails WHERE key = "%s"' % hashedKey)[0].get('expiresOn'), '%Y-%m-%d %H:%M'):
                    # set verify in db to true
                    query_db('UPDATE users SET verified = 1 WHERE id = "%s"' % userId)
                    get_db().commit()
                    flash('The account is now verified.')
                else:
                    flash(Markup('Email has expired! <a href="/resend_verify" class="alert-link">Click here</a> to resend the verification email!'))
            else:
                flash('Something went wrong. Try logging in to send another email (and don\'t forget to check your spam folder!)')
        return render_template('dashboard.html')
    else:
        return redirect('/')


@app.route('/resend_verify', methods=['GET'])
def resend_verify():
    # Is Authed Guard, redirects to the login
    userCookie = functions.getCookie()
    if validSessions.checkSession(userCookie) is False:
        flash('Mate, you dont have a session hackerman! Go and login')
        return redirect('/')

    uid = validSessions.checkSession(userCookie)
    username = query_db('SELECT username FROM profiles WHERE id = "%s"' % uid)[0].get('username')
    email = query_db('SELECT email FROM users WHERE id = "%s"' % uid)[0].get('email')

    # get uuid from database
    key = b64encode(os.urandom(32))
    hashedKey = functions.generateHashedKey(key)
    timestamp = datetime.datetime.today() + datetime.timedelta(minutes=15)
    timestamp = datetime.datetime.strftime(timestamp, '%Y-%m-%d %H:%M')

    verifyEmailQuery = 'INSERT INTO verifyEmails(id, key, expiresOn) VALUES ("%s", "%s", "%s")' % (uid, hashedKey, timestamp)
    query_db(verifyEmailQuery)
    get_db().commit()

    # send an email with a link to verify_email page with the id given
    # TODO: 03/03/2020 change link to https before submitting
    link = 'http://127.0.0.1:5000/verify_email?key=%s&id=%s' % (key.decode(), uid)
    msg = Message("Verify Email - UEA Life", sender="uealifedss@gmail.com",
                  recipients=[email])
    messageBody = 'Hi %s,\n Please click the following link to verify your email:\n %s\n\nNotes: ' \
                  'This email expires 15 minutes after being requested.' % (username, link)
    msg.body = messageBody
    mail.send(msg)

    flash('Email has been sent')
    return redirect('/dashboard')


if __name__ == '__main__':
    # TODO: 11/02/2020 Change debug to False before submitting
    # app.run(host='127.0.0.1', port=5000, debug=True, ssl_context=sslContext)
    app.run(host='127.0.0.1', port=5000, debug=True)
