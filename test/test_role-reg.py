from add_org import add_organization
from consent import *
import random
import string

name = { "title"        : "mr.",
         "firstName"    : "abc",
         "lastName"     : "xyz"
         }

csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIICjDCCAXQCAQAwRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQK\nDAtNeU9yZywgSW5jLjEVMBMGA1UEAwwMbXlkb21haW4uY29tMIIBIjANBgkqhkiG\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyhF2a5PeL72zGdL47/6zVQQQtZJcO01iVbjR\nSSyswUa2jcfYfoQEVKo1JAz25G3nYfSW1Te3OWjuihvPhZeatFSUwTxcZJFxzIWm\n4/gOQIhJKCA/Wry3liW2sjIGLuHxeH2BoQCIEZyYcqVpRWEJ9RusRFcwPgvROigh\nhMXhgE86uaIRs0yPqzhc7sl53T4qx6qvQJ6uTXBWBvUELgSSgeyaT0gwU1mGmPck\n7Svo6tsWfBFfgT5Ecbqsc2nqChAExgocp5tkPJYcy8FB/tU/FW0rFthqecSvMrpS\ncZW9+iyzseyPrcK9ka6XSlVu9EoX82RW7SRyRL2T5VN3JemXfQIDAQABoAAwDQYJ\nKoZIhvcNAQELBQADggEBAJRFEYn6dSzEYpgYLItUm7Sp3LzquJw7QfMyUvsy45rp\n0VTdQdYp/hVR2aCLiD33ht4FxlhbZm/8XcTuYolP6AbF6FldxWmmFFS9LRAj7nTV\ndU1pZftwFPp6JsKUCYHVsuxs7swliXbEcBVtD6QktzZNrRJmUKi38DAFcbFwgLaM\nG/iRIm4DDj2hmanKp+vUWjXfj13naa7bDtIlzW96y24jsu+naabg8MVShfGCStIv\nrX3T2JkkSjpTw7YzIpgI8/Zg9VR1l0udvfh9bn7mjmOYc3EYwJKvuJDn1TzVuIIi\n9NmVasTjhZJ0PyWithWuZplo/LXUwSoid8HVyqe5ZVI=\n-----END CERTIFICATE REQUEST-----\n"

bad_csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIICjDCCAXQCAQAwRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQK\nDAtNeU9yZywgSW5jLjEVMBMGA1UEAwwMbXlkb21haW4uY29tMIIBIjANBgkqhkiG\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyhF2a5PeL72zGdL47/6zVQQQtZJcO01iVbjR\nSSyswUa2jcfYfoQEVKo1JAz25G3nYfSW1Te3OWjuihvPhZeatFSUwTxcZJFxzIWm\n4/gOQIhJKCA/Wry3liW2sjIGLuHxeH2BoQCIEZyYcqVpRWEJ9RusRFcwPgvROigh\nhMXhgE86uaIRs0yPqzhc7sl53T4qx6qvQJ6uTXBWBvUELgSSgeyaT0gwU1mGmPck\n7Svo6tsWfBFfgT5Ecbqsc2nqChAExgocp5tkPJYcy8FB/tU/FW0rFthqecSvMrpS\ncZW9+iyzseyPrcK9ka6XSlVu9EoX82RW7SRyRL2T5VN3JemXfQIDAQABoAAwDQYJ\nKoZIhvcNAQELBQADggEBAJRFEYn6dSzEYpgYLItUm7Sp3LzquJw7QfMyUvsy45rp\n0VTdQdYp/hVR2aCLiD33ht4FxlhbZm/8XcTuYolP6AbF6FldxWmmFFS9LRAj7nTV\ndU1pZftwFPp6JsKUCYHVsuxs7swliXbEcBVtD6QktzZNrRJmUKi38DAFcbFwgLaM\nG/iRIm4DDj2hmanKp+vUWjXfj13nasaswwa7bDtIlzW96y24jsu+naabg8MVShfGCStIv\nrX3T2JkkSjpTw7YzIpgI8/Zg9VR1l0udvfh9bn7sdakjsd92jkamjmOYc3EYwJKvuJDn1TzVuIIi\n9NmVasTjhZJ0PyWithWuZplo/LXUwSoid8HVyqe5ZVI=\n-----END CERTIFICATE REQUEST-----\n"

# random website
website = ''.join(random.choice(string.ascii_lowercase) for _ in range(8)) + '.com'

# random email 
email_name  = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6)) 
email       = email_name + '@gmail.com' 

org_id = add_organization(website)

def test_no_role():
        # no role specified
        r = role_reg(email, '9454234223', name , [], None, csr)
        assert r['success']     == False
        assert r['status_code'] == 400

def test_success():
        r = role_reg(email, '9454234223', name , ["consumer"], None, csr)
        print(r)
        assert r['success']     == True
        assert r['status_code'] == 200

def test_same_role():
        # same role
        r = role_reg(email, '9454234223', name , ["consumer"], None, csr)
        assert r['success']     == False
        assert r['status_code'] == 403

def test_email_mismatch_domain():
        # email does not match domain of organization
        r = role_reg(email, '9454234223', name , ["onboarder", "data ingester"], org_id, csr)
        assert r['success']     == False
        assert r['status_code'] == 403

def test_ingester_success():
        email = email_name + '@' + website
        r = role_reg(email, '9454234223', name , ["data ingester"], org_id, csr)
        assert r['success']     == True
        assert r['status_code'] == 200

def test_no_csr():
        # no csr is valid for existing user
        email = email_name + '@' + website
        r = role_reg(email, '9454234223', name , ["onboarder"], org_id)
        assert r['success']     == True
        assert r['status_code'] == 200

def test_invalid_role():
        # invalid roles
        email = email_name + '@' + website
        r = role_reg(email, '9454234223', name , ["onboarder", "provider"], org_id, csr)
        assert r['success']     == False
        assert r['status_code'] == 400

def test_org_email_consumer():
        # register as consumer with organisation mail
        email = email_name + '@' + website
        r = role_reg(email, '9454234223', name , ["consumer"], None)
        assert r['success']     == True
        assert r['status_code'] == 200

# new random email 
new_email_name  = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6)) 

def test_non_org_email():
        # all roles - non-org email
        email       = new_email_name + '@gmail.com' 
        r = role_reg(email, '9454234223', name , ["onboarder", "data ingester", "consumer"], org_id, csr)
        assert r['success']     == False
        assert r['status_code'] == 403

def test_no_csr():
        # no csr
        email       = new_email_name + '@' + website 
        r = role_reg(email, '9454234223', name , ["onboarder", "data ingester", "consumer"], org_id)
        assert r['success']     == False
        assert r['status_code'] == 400

def test_bad_csr():
        # bad csr
        email       = new_email_name + '@' + website 
        r = role_reg(email, '9454234223', name , ["onboarder", "data ingester", "consumer"], org_id, bad_csr)
        assert r['success']     == False
        assert r['status_code'] == 400

def test_invalid_org_id():
        # invalid org ID
        email       = new_email_name + '@' + website 
        r = role_reg(email, '9454234223', name , ["onboarder", "data ingester", "consumer"], 210781030, csr)
        assert r['success']     == False
        assert r['status_code'] == 403

def test_all_role_reg():
        email       = new_email_name + '@' + website 
        r = role_reg(email, '9454234223', name , ["onboarder", "data ingester", "consumer"], org_id, csr)
        assert r['success']     == True
        assert r['status_code'] == 200

new_website = ''.join(random.choice(string.ascii_lowercase) for _ in range(8)) + '.com'
new_org_id  = add_organization(new_website)

def test_diff_email_from_org_domain():
        # onboarder, ingester cannot register with org using different domain email
        email       = new_email_name + '@gmail.com' 
        r = role_reg(email, '9454234223', name , ["onboarder", "data ingester"], new_org_id, csr)
        assert r['success']     == False
        assert r['status_code'] == 403

#### tests with provider role ####

def test_provider_reg_after_other_role_reg():
        # cannot register because the email was used for lesser role registration
        r = provider_reg(email, '9454234223', name , org_id, csr)
        assert r['success']     == False
        assert r['status_code'] == 403

prov_email_name      = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
provider_email  = prov_email_name + '@' + website

def test_provider_reg():
        # provider registers with fresh email
        r = provider_reg(provider_email, '9454234223', name , org_id, csr)
        assert r['success']     == True
        assert r['status_code'] == 200

def test_provider_cannot_get_other_roles():
        # provider can get all other role
        r = role_reg(provider_email, '9454234223', name , ["data ingester"], org_id, csr)
        assert r['success']     == False
        assert r['status_code'] == 403

        r = role_reg(provider_email, '9454234223', name , ["onboarder"], org_id, csr)
        assert r['success']     == False
        assert r['status_code'] == 403

        r = role_reg(provider_email, '9454234223', name , ["consumer"], org_id, csr)
        assert r['success']     == False
        assert r['status_code'] == 403
