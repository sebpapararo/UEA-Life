import datetime
import os
import random
import re
import sqlite3

DATABASE = 'database.sqlite'

def create():
    db = sqlite3.connect(DATABASE)

    c = db.cursor()

    c.execute('''
        CREATE TABLE users (
            id varchar PRIMARY KEY,
            created_on varchar,
            verified DEFAULT 0,
            password varchar,
            email varchar UNIQUE
        );
    ''')

    c.execute(
        '''INSERT INTO users VALUES('1', '20/02/2020 13:17', '0', 'TestPassword123', 's.papararo@uea.ac.uk');''')

    c.execute('''
                CREATE TABLE profiles (
                    id varchar PRIMARY KEY,
                    username varchar UNIQUE,
                    last_active varchar,
                    firstname varchar,
                    surname varchar,
                    level varchar,
                    school varchar         	
                );
        ''')

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

    c.execute('''
            CREATE TABLE replies (
                id integer PRIMARY KEY AUTOINCREMENT,
                posted_on varchar,
                postId integer,
                author varchar,
                body varchar              
            );
        ''')

    c.execute('''
        CREATE TABLE forgotPasswordRequests (
            id varchar PRIMARY KEY,
            email varchar
        );
    ''')



    db.commit()



def delete_db():
    if os.path.exists(DATABASE):
        os.remove(DATABASE)

if __name__=='__main__':
    delete_db()
    create()