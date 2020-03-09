import os
import sqlite3
import functions
import uuid
from base64 import b64encode

DATABASE = 'database.db'


# Function to create the database tables and populate some fake users and posts
def create():
    db = sqlite3.connect(DATABASE)
    c = db.cursor()

    # Create the users table
    c.execute('''
        CREATE TABLE users (
            id varchar PRIMARY KEY,
            created_on varchar,
            verified DEFAULT 0,
            password varchar,
            salt varchar,
            email varchar UNIQUE
        );
    ''')

    # Create the profiles table
    c.execute('''
                CREATE TABLE profiles (
                    id varchar PRIMARY KEY,
                    username varchar UNIQUE,
                    last_active varchar,
                    level varchar,
                    school varchar         	
                );
        ''')

    # Create the posts table
    c.execute('''
        CREATE TABLE posts (
            id integer PRIMARY KEY AUTOINCREMENT,
            posted_on varchar,
            category varchar,
            title varchar,
            content varchar,
            posted_by varchar
        );
    ''')

    # Create the replies table
    c.execute('''
            CREATE TABLE replies (
                id integer PRIMARY KEY AUTOINCREMENT,
                posted_on varchar,                      
                posted_to integer,
                posted_by varchar,
                content varchar              
            );
        ''')

    # Create the table for forgot password requests
    c.execute('''
        CREATE TABLE forgotPasswordRequests (
            key varchar PRIMARY KEY,
            id varchar,
            expiresOn varchar
        );
    ''')

    # Create the verify emails requests table
    c.execute('''
            CREATE TABLE verifyEmails (
                key varchar PRIMARY KEY,
                id varchar,
                expiresOn varchar 
            );
        ''')

    # Create and add some test users
    salt1 = functions.generateSalt()
    # TODO: 04/03/2020 change passwords to follow rules
    hashedPass1 = functions.generateHashedPass(salt1, 'a')
    salt1 = b64encode(salt1)
    uid = str(uuid.uuid4())
    c.execute('INSERT INTO users VALUES("%s", "04/03/2020 12:28", 1, "%s", "%s", "s.papararo@gmail.com")' % (uid, hashedPass1, salt1.decode()))
    c.execute('INSERT INTO profiles VALUES("%s", "seb", "04/03/2020 12:28", "PGT", "CMP")' % uid)

    salt2 = functions.generateSalt()
    # TODO: 04/03/2020 change passwords to follow rules
    hashedPass2 = functions.generateHashedPass(salt2, 'a')
    salt2 = b64encode(salt2)
    uid2 = str(uuid.uuid4())
    c.execute('INSERT INTO users VALUES("%s", "04/03/2020 12:32", 1, "%s", "%s", "a@a.com")' % (uid2, hashedPass2, salt2.decode()))
    c.execute('INSERT INTO profiles VALUES("%s", "callum", "04/03/2020 12:28", "PGT", "CMP")' % uid2)

    salt3 = functions.generateSalt()
    # TODO: 04/03/2020 change passwords to follow rules
    hashedPass3 = functions.generateHashedPass(salt3, 'a')
    salt3 = b64encode(salt3)
    uid3 = str(uuid.uuid4())
    c.execute('INSERT INTO users VALUES("%s", "04/03/2020 12:28", 1, "%s", "%s", "a.davies964@gmail.com")' % (uid3, hashedPass3, salt3.decode()))
    c.execute('INSERT INTO profiles VALUES("%s", "andy", "04/03/2020 12:28", "PGT", "CMP")' % uid3)

    # Create some fake posts
    c.execute('INSERT INTO posts (posted_by, category, title, content, posted_on) VALUES("%s","%s","%s","%s","%s");' % \
              (uid, "General", "This is the first post", "This site is absolutely incredible!", "07/03/2020 14:04"))
    c.execute('INSERT INTO posts (posted_by, category, title, content, posted_on) VALUES("%s","%s","%s","%s","%s");' % \
              (uid3, "Student Union", "The SU is trash!", "My rep is useless and does not listen to anything I say", "07/03/2020 14:10"))
    c.execute('INSERT INTO posts (posted_by, category, title, content, posted_on) VALUES("%s","%s","%s","%s","%s");' % \
              (uid, "Accommodation", "My flat is lovely!", "Apart from my housemate is super messy!", "07/03/2020 14:13"))
    c.execute('INSERT INTO posts (posted_by, category, title, content, posted_on) VALUES("%s","%s","%s","%s","%s");' % \
              (uid2, "Finance", "I am super poor!", "I spend all my money on lego!", "07/03/2020 14:17"))
    c.execute('INSERT INTO posts (posted_by, category, title, content, posted_on) VALUES("%s","%s","%s","%s","%s");' % \
              (uid2, "Finance", "I am no longer poor!", "Student loans are amazing! Just need to not spend it on lego. xD", "07/03/2020 14:15"))

    # Create some fake replies
    c.execute('INSERT INTO replies (posted_on, posted_to, posted_by, content) VALUES("%s","%s","%s","%s");' % \
              ("07/03/2020 14:20", 2, uid, "I totally agree, they are completely incompetent, almost as bad as the hub!"))
    c.execute('INSERT INTO replies (posted_on, posted_to, posted_by, content) VALUES("%s","%s","%s","%s");' % \
              ("07/03/2020 14:29", 4, uid3, "Haha, I love lego as well. I prefer Beyblade's though!"))

    # Commit all changes to the database
    db.commit()


# Delete the database, ready to create a new one
def delete_db():
    if os.path.exists(DATABASE):
        os.remove(DATABASE)


if __name__ == '__main__':
    delete_db()
    create()
