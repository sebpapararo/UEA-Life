import os
import sqlite3
import functions
import uuid
from base64 import b64encode, b64decode

DATABASE = 'database.db'


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
                postId integer,
                posted_by varchar,
                content varchar              
            );
        ''')

    # Create the table for forgot password requests
    c.execute('''
        CREATE TABLE forgotPasswordRequests (
            key varchar PRIMARY KEY,
            id varchar,
            timestamp varchar
        );
    ''')

    c.execute('''
            CREATE TABLE verifyEmails (
                id varchar PRIMARY KEY,
                key varchar
            );
        ''')

    # Create and add some test users
    salt1 = functions.generateSalt()
    # TODO: 04/03/2020 change passwords to follow rules
    hashedPass1 = functions.generateHashedPass(salt1, 'a')
    salt1 = b64encode(salt1)
    uid = str(uuid.uuid4())
    user1Query = 'INSERT INTO users VALUES("%s", "04/03/2020 12:28", 1, "%s", "%s", "s.papararo@gmail.com")' % (uid, hashedPass1, salt1.decode())
    user1ProfileQuery = 'INSERT INTO profiles VALUES("%s", "seb", "04/03/2020 12:28", "PGT", "CMP")' % (uid)
    c.execute(user1Query)
    c.execute(user1ProfileQuery)

    salt2 = functions.generateSalt()
    # TODO: 04/03/2020 change passwords to follow rules
    hashedPass2 = functions.generateHashedPass(salt2, 'a')
    salt2 = b64encode(salt2)
    uid2 = str(uuid.uuid4())
    user2Query = 'INSERT INTO users VALUES("%s", "04/03/2020 12:32", 1, "%s", "%s", "a@a.com")' % (uid2, hashedPass2, salt2.decode())
    user2ProfileQuery = 'INSERT INTO profiles VALUES("%s", "callum", "04/03/2020 12:28", "PGT", "CMP")' % (uid2)
    c.execute(user2Query)
    c.execute(user2ProfileQuery)

    salt3 = functions.generateSalt()
    # TODO: 04/03/2020 change passwords to follow rules
    hashedPass3 = functions.generateHashedPass(salt3, 'a')
    salt3 = b64encode(salt3)
    uid3 = str(uuid.uuid4())
    user3Query = 'INSERT INTO users VALUES("%s", "04/03/2020 12:28", 1, "%s", "%s", "andy.davies@gmail.com")' % (uid3, hashedPass3, salt3.decode())
    user3ProfileQuery = 'INSERT INTO profiles VALUES("%s", "andy", "04/03/2020 12:28", "PGT", "CMP")' % (uid3)
    c.execute(user3Query)
    c.execute(user3ProfileQuery)

    # Commit all changes to the database
    db.commit()


# Delete the database, ready to create a new one
def delete_db():
    if os.path.exists(DATABASE):
        os.remove(DATABASE)


if __name__ == '__main__':
    delete_db()
    create()
