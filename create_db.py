import os
import sqlite3

DATABASE = 'database.sqlite'


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
            body varchar,
            author varchar
        );
    ''')

    # Create the replies table
    c.execute('''
            CREATE TABLE replies (
                id integer PRIMARY KEY AUTOINCREMENT,
                posted_on varchar,
                postId integer,
                author varchar,
                body varchar              
            );
        ''')

    # Create the table for forgot password requests
    c.execute('''
        CREATE TABLE forgotPasswordRequests (
            id varchar PRIMARY KEY,
            email varchar
        );
    ''')

    # Commit all changes to the database
    db.commit()


# Delete the database, ready to create a new one
def delete_db():
    if os.path.exists(DATABASE):
        os.remove(DATABASE)


if __name__ == '__main__':
    delete_db()
    create()
