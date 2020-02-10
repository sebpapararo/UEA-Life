from flask import *
import functions
import sqlite3


app = Flask(__name__)
DATABASE = 'database.db'



@app.route('/')
def hello_world():
    return 'Hello Students!'



## Database Methods
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

if __name__ == '__main__':
    app.run(host='127.0.0.1', debug=False, ssl_context='adhoc')
