from flask import *
import functions
import sqlite3
import urllib
import re
import uuid
import datetime
import secrets
from base64 import b64encode, b64decode

# Configuration Statements
app = Flask(__name__, template_folder="templates")
DATABASE = 'database.db'
sslContext = ('server.crt', 'server.key')
# TODO: 25/02/2020 research what this does
app.secret_key = secrets.token_hex(64)


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
                    session['user'] = email
                    flash('Successfully logged in as %s' % email)
                    return redirect('/dashboard')
                else:
                    flash('Invalid Captcha!')
            else:
                flash('The username or password is incorrect!')
        else:
            flash('The username or password is incorrect!222')
    else:
        flash('The username and password fields cannot be left blank!')
    return redirect('/')


@app.route('/logout/')
def logout():
    session.pop('user', None)
    return redirect('/')


@app.route('/dashboard', methods=['GET'])
def dashboard():
    return render_template('/dashboard.html', title="UEA Life | Dashboard")


@app.route('/createPost', methods=['GET', 'POST'])
def createPost():
    return render_template('/newPost.html', title="UEA Life | Create Post")


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
                                    # get_db().commit()
                                    query_db(profileQuery)
                                    get_db().commit()

                                    # TODO: 25/02/2020 Set up the email verification

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

if __name__ == '__main__':
    # TODO: 11/02/2020 Change debug to False before submitting
    # app.run(host='127.0.0.1', port=5000, debug=True, ssl_context=sslContext)
    app.run(host='127.0.0.1', port=5000, debug=True)
