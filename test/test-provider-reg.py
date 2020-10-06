from consent import *
from add_org import add_organization
import random
import string

# invalid inputs
r = provider_reg('a', 'b', 'c', 'd', 'e')
assert r['success']     == False
assert r['status_code'] == 400

name = { "title"        : "mr.",
         "firstName"    : "abc",
         "lastName"     : "xyz"
         }

website = ''.join(random.choice(string.ascii_lowercase) for _ in range(8)) + '.com'

org_id = add_organization(website)

csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIICjDCCAXQCAQAwRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQK\nDAtNeU9yZywgSW5jLjEVMBMGA1UEAwwMbXlkb21haW4uY29tMIIBIjANBgkqhkiG\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyhF2a5PeL72zGdL47/6zVQQQtZJcO01iVbjR\nSSyswUa2jcfYfoQEVKo1JAz25G3nYfSW1Te3OWjuihvPhZeatFSUwTxcZJFxzIWm\n4/gOQIhJKCA/Wry3liW2sjIGLuHxeH2BoQCIEZyYcqVpRWEJ9RusRFcwPgvROigh\nhMXhgE86uaIRs0yPqzhc7sl53T4qx6qvQJ6uTXBWBvUELgSSgeyaT0gwU1mGmPck\n7Svo6tsWfBFfgT5Ecbqsc2nqChAExgocp5tkPJYcy8FB/tU/FW0rFthqecSvMrpS\ncZW9+iyzseyPrcK9ka6XSlVu9EoX82RW7SRyRL2T5VN3JemXfQIDAQABoAAwDQYJ\nKoZIhvcNAQELBQADggEBAJRFEYn6dSzEYpgYLItUm7Sp3LzquJw7QfMyUvsy45rp\n0VTdQdYp/hVR2aCLiD33ht4FxlhbZm/8XcTuYolP6AbF6FldxWmmFFS9LRAj7nTV\ndU1pZftwFPp6JsKUCYHVsuxs7swliXbEcBVtD6QktzZNrRJmUKi38DAFcbFwgLaM\nG/iRIm4DDj2hmanKp+vUWjXfj13naa7bDtIlzW96y24jsu+naabg8MVShfGCStIv\nrX3T2JkkSjpTw7YzIpgI8/Zg9VR1l0udvfh9bn7mjmOYc3EYwJKvuJDn1TzVuIIi\n9NmVasTjhZJ0PyWithWuZplo/LXUwSoid8HVyqe5ZVI=\n-----END CERTIFICATE REQUEST-----\n"

# random email 
email = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(6)) + '@gmail.com'

# invalid phone
r = provider_reg(email, '780w021-', name , org_id, csr)
assert r['success']     == False
assert r['status_code'] == 400

# invalid csr
bad_csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIICjDCCAXQCAQAwRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQK\nDAtNeU9yZywgSW5jLjEVMBMGA1UEAwwMbXlkb21haW4uY29tMIIBIjANBgkqhkiG\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyhF2a5PeL72zGdL47/6zVQQQtZJcO01iVbjR\nSSyswUa2jcfYfoQEVKo1JAz25G3nYfSW1Te3OWjuihvPhZeatFSUwTxcZJFxzIWm\n4/gOQIhJKCA/Wry3liW2sjIGLuHxeH2BoQCIEZyYcqVpRWEJ9RusRFcwPgvROigh\nhMXhgE86uaIRs0yPqzhc7sl53T4qx6qvQJ6uTXBWBvUELgSSgeyaT0gwU1mGmPck\n7Svo6tsWfBFfgT5Ecbqsc2nqChAExgocp5tkPJYcy8FB/tU/FW0rFthqecSvMrpS\ncZW9+iyzseyPrcK9ka6XSlVu9EoX82RW7SRyRL2T5VN3JemXfQIDAQABoAAwDQYJ\nKoZIhvcNAQELBQADggEBAJRFEYn6dSzEYpgYLItUm7Sp3LzquJw7QfMyUvsy45rp\n0VTdQdYp/hVR2aCLiD33ht4FxlhbZm/8XcTuYolP6AbF6FldxWmmFFS9LRAj7nTV\ndU1pZftwFPp6JsKUCYHVsuxs7swliXbEcBVtD6QktzZNrRJmUKi38DAFcbFwgLaM\nG/iRIm4DDj2hmanKp+vUWjXfj13nasaswwa7bDtIlzW96y24jsu+naabg8MVShfGCStIv\nrX3T2JkkSjpTw7YzIpgI8/Zg9VR1l0udvfh9bn7sdakjsd92jkamjmOYc3EYwJKvuJDn1TzVuIIi\n9NmVasTjhZJ0PyWithWuZplo/LXUwSoid8HVyqe5ZVI=\n-----END CERTIFICATE REQUEST-----\n"
r = provider_reg(email, '9845596200', name , org_id, bad_csr)
assert r['success']     == False
assert r['status_code'] == 400

# large csr input
bad_csr = "-----BEGIN CERTIFICATE REQUEST-----\n" + 'DEADCAFE' * 3000 + "\n-----END CERTIFICATE REQUEST-----\n"
r = provider_reg(email, '9845596200', name , org_id, bad_csr)
assert r['success']     == False
assert r['status_code'] == 400

# very large csr input, gets blocked by express itself?
bad_csr = "-----BEGIN CERTIFICATE REQUEST-----\n" + 'DEADCAFE' * 30000 + "\n-----END CERTIFICATE REQUEST-----\n"
r = provider_reg(email, '9845596200', name , org_id, bad_csr)
assert r['success']     == False

# valid
r = provider_reg(email, '9845596200', name , org_id, csr)
assert r['success']     == True
assert r['status_code'] == 200

# same email
r = provider_reg(email, '9845596200', name , org_id, csr)
assert r['success']     == False
assert r['status_code'] == 403

# invalid org ID
email = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(6)) + '@gmail.com'
r = provider_reg(email, '9845596200', name , '22329932', csr)
assert r['success']     == False
assert r['status_code'] == 403

# invalid email
email = "abcde1234--><><@x.y.z"
r = provider_reg(email, '9845596200', name , org_id, csr)
assert r['success']     == False
assert r['status_code'] == 400
