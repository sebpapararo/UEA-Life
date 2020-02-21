from string import ascii_uppercase, ascii_lowercase, digits
from flask import flash
import hashlib
import os


# Method to sanitise the inputs by replacing suspect characters with its HTML numeric code counterpart
def sanitiseInputs(input):
    input = input.replace('"', '&#34')
    input = input.replace('#', '&#35')
    input = input.replace('&', '&#38')
    input = input.replace("'", '&#39')
    input = input.replace('(', '&#40')
    input = input.replace(')', '&#41')
    input = input.replace('/', '&#47')
    input = input.replace(';', '&#59')
    input = input.replace('<', '&#60')
    return input.replace('>', '&#62')


# Used to desanitise inputs so that text can be displayed properly on the screen
def desanitiseInputs(input):
    input = input.replace('&#62', '>')
    input = input.replace('&#60', '<')
    input = input.replace('&#59', ';')
    input = input.replace('&#47', '/')
    input = input.replace('&#41', ')')
    input = input.replace('&#40', '(')
    input = input.replace('&#39', "'")
    input = input.replace('&#38', '&')
    input = input.replace('&#35', '#')
    return input.replace('&#34', '"')


# Used to check if a string contains a given character
def contains(required_chars, s):
    return any(c in required_chars for c in s)


# String contains a uppercase character
def contains_upper(s):
    return contains(ascii_uppercase, s)


# String contains a lowercase character
def contains_lower(s):
    return contains(ascii_lowercase, s)


# String contains a digit
def contains_digit(s):
    return contains(digits, s)


# String contains a special character
def contains_special(s):
    return contains(r"""!@$%^&*()_-+={}[]|\,.></?~`"':;""", s)


# String is 8 characters or greater in length
def long_enough(s):
    return len(s) >= 8


# Use the above functions to the enforce all the password rules
def validate_password(password):
    error = None
    # list of all possible errors with password input
    VALIDATIONS = (
        (contains_upper, 'Password needs at least one upper-case character.'),
        (contains_lower, 'Password needs at least one lower-case character.'),
        (contains_digit, 'Password needs at least one number.'),
        (contains_special, 'Password needs at least one special character.'),
        (long_enough, 'Password needs to be at least 8 characters in length.'),
    )
    failures = [
        msg for validator, msg in VALIDATIONS if not validator(password)
    ]
    if not failures:
        return True
    else:
        for msg in failures:
            flash(msg)
        return False


# Generate a hash of the message using sha3_512 combined with the salt
def generateHashedPass(salt, message):
    # Strings must be encoded before being hashed
    salt = salt.encode('utf-8')
    message = message.encode('utf-8')

    return hashlib.sha3_512(salt + message).hexdigest()


# Use inbuilt python os library to generate a random string of 64 bytes suitable for cryptographic use to act as a salt
def generateSeasoning():
    return os.urandom(64)
