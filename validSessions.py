import datetime
from flask import request

validSessions = {}


# Function to add a cookie to the list of valid sessions when a user logs in
def addSession(key, value):
    validSessions[key] = value


# Function used when logging out to invalidate the cookie on the server side
def removeSession(key):
    validSessions.pop(key)


# Check if the users cookie is valid. If it is valid return the users id
def checkSession(key):
    # Valid cookie id
    if key in validSessions:
        # The cookie has not expired
        if validSessions.get(key)[1] > datetime.datetime.today():
            # The ip address used to create the cookie is the same as the one trying to use the cookie
            if validSessions.get(key)[2] == request.remote_addr:
                return validSessions.get(key)[0]
            else:
                return False
        else:
            return False
    else:
        return False
