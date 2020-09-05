from consent import *
import random
import string

# invalid inputs
r = provider_reg('a', 'b', 'c', 'd', 'e')
assert r['success']     == False
assert r['status_code'] == 403

org = { "name" : "acme",
        "website"   : "www.gmail.com",
        "city"      : "Bengaluru",
        "state"     : "ka",
        "country"   : "IN"
        }

name = { "title"        : "mr.",
         "firstName"    : "abc",
         "lastName"     : "xyz"
         }

csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIICjDCCAXQCAQAwRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQK\nDAtNeU9yZywgSW5jLjEVMBMGA1UEAwwMbXlkb21haW4uY29tMIIBIjANBgkqhkiG\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyhF2a5PeL72zGdL47/6zVQQQtZJcO01iVbjR\nSSyswUa2jcfYfoQEVKo1JAz25G3nYfSW1Te3OWjuihvPhZeatFSUwTxcZJFxzIWm\n4/gOQIhJKCA/Wry3liW2sjIGLuHxeH2BoQCIEZyYcqVpRWEJ9RusRFcwPgvROigh\nhMXhgE86uaIRs0yPqzhc7sl53T4qx6qvQJ6uTXBWBvUELgSSgeyaT0gwU1mGmPck\n7Svo6tsWfBFfgT5Ecbqsc2nqChAExgocp5tkPJYcy8FB/tU/FW0rFthqecSvMrpS\ncZW9+iyzseyPrcK9ka6XSlVu9EoX82RW7SRyRL2T5VN3JemXfQIDAQABoAAwDQYJ\nKoZIhvcNAQELBQADggEBAJRFEYn6dSzEYpgYLItUm7Sp3LzquJw7QfMyUvsy45rp\n0VTdQdYp/hVR2aCLiD33ht4FxlhbZm/8XcTuYolP6AbF6FldxWmmFFS9LRAj7nTV\ndU1pZftwFPp6JsKUCYHVsuxs7swliXbEcBVtD6QktzZNrRJmUKi38DAFcbFwgLaM\nG/iRIm4DDj2hmanKp+vUWjXfj13naa7bDtIlzW96y24jsu+naabg8MVShfGCStIv\nrX3T2JkkSjpTw7YzIpgI8/Zg9VR1l0udvfh9bn7mjmOYc3EYwJKvuJDn1TzVuIIi\n9NmVasTjhZJ0PyWithWuZplo/LXUwSoid8HVyqe5ZVI=\n-----END CERTIFICATE REQUEST-----\n"

# random email 
email = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6)) + '@gmail.com'

# invalid phone
r = provider_reg(email, '780w021-', name , org, csr)
assert r['success']     == False
assert r['status_code'] == 403

# invalid csr
bad_csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIICjDCCAXQCAQAwRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQK\nDAtNeU9yZywgSW5jLjEVMBMGA1UEAwwMbXlkb21haW4uY29tMIIBIjANBgkqhkiG\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyhF2a5PeL72zGdL47/6zVQQQtZJcO01iVbjR\nSSyswUa2jcfYfoQEVKo1JAz25G3nYfSW1Te3OWjuihvPhZeatFSUwTxcZJFxzIWm\n4/gOQIhJKCA/Wry3liW2sjIGLuHxeH2BoQCIEZyYcqVpRWEJ9RusRFcwPgvROigh\nhMXhgE86uaIRs0yPqzhc7sl53T4qx6qvQJ6uTXBWBvUELgSSgeyaT0gwU1mGmPck\n7Svo6tsWfBFfgT5Ecbqsc2nqChAExgocp5tkPJYcy8FB/tU/FW0rFthqecSvMrpS\ncZW9+iyzseyPrcK9ka6XSlVu9EoX82RW7SRyRL2T5VN3JemXfQIDAQABoAAwDQYJ\nKoZIhvcNAQELBQADggEBAJRFEYn6dSzEYpgYLItUm7Sp3LzquJw7QfMyUvsy45rp\n0VTdQdYp/hVR2aCLiD33ht4FxlhbZm/8XcTuYolP6AbF6FldxWmmFFS9LRAj7nTV\ndU1pZftwFPp6JsKUCYHVsuxs7swliXbEcBVtD\n-----END CERTIFICATE REQUEST-----\n"
r = provider_reg(email, '9845596200', name , org, bad_csr)
assert r['success']     == False
assert r['status_code'] == 403

# large csr input
bad_csr = "-----BEGIN CERTIFICATE REQUEST-----\n" + 'DEADCAFE' * 3000 + "\n-----END CERTIFICATE REQUEST-----\n"
r = provider_reg(email, '9845596200', name , org, bad_csr)
assert r['success']     == False
assert r['status_code'] == 403

# very large csr input, gets blocked by express itself?
bad_csr = "-----BEGIN CERTIFICATE REQUEST-----\n" + 'DEADCAFE' * 30000 + "\n-----END CERTIFICATE REQUEST-----\n"
r = provider_reg(email, '9845596200', name , org, bad_csr)
assert r['success']     == False

# valid
r = provider_reg(email, '9845596200', name , org, csr)
assert r['success']     == True
assert r['status_code'] == 200

# same email
r = provider_reg(email, '9845596200', name , org, csr)
assert r['success']     == False
assert r['status_code'] == 403

# invalid org website
email = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6)) + '@gmail.com'
org['website'] = "abcjd.coada.$89/1"
r = provider_reg(email, '9845596200', name , org, csr)
assert r['success']     == False
assert r['status_code'] == 403

# invalid email
email = "verylargeemail@x.y.z"
r = provider_reg(email, '9845596200', name , org, csr)
assert r['success']     == False
assert r['status_code'] == 403
