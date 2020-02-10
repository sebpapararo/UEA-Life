from string import ascii_uppercase, ascii_lowercase, digits
from flask import flash


# Method to sanitise the inputs by replacing suspect characters
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


# Used to densanitise inputs so the edit post text displays correctly and it doesn't resanitise already sanitised text
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

def contains(required_chars, s):
    return any(c in required_chars for c in s)

def contains_upper(s):
    return contains(ascii_uppercase, s)


def contains_lower(s):
    return contains(ascii_lowercase, s)


def contains_digit(s):
    return contains(digits, s)


def contains_special(s):
    return contains(r"""!@$%^&*()_-+={}[]|\,.></?~`"':;""", s)


def long_enough(s):
    return len(s) >= 8


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

