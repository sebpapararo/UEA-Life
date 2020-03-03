
validSessions = {}


def addSession(key, value):
    validSessions[key] = value


def removeSession(key):
    validSessions.pop(key)


# Check if the users cookie is valid
def checkSession(key):
    if key in validSessions:
        return validSessions.get(key)[0]
    else:
        return False