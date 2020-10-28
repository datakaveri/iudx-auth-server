# abc.xyz@rbccps.org is set as admin

from add_admin import init_admin
from init import untrusted
from init import *
from consent import *
import random
import string

init_admin()

### Organization APIs ###

name = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
website = ''.join(random.choice(string.ascii_lowercase) for _ in range(8)) + '.com'
org = {
        "name":"TESTING",
        "city":"Bengaluru",
        "state": "KA",
        "country":"IN",
        "website": website
    }

org_id = 0
user_id = 0
ruser_id = 0
borg = org.copy()

# invalid state
borg["state"] = "Karnataka"
r = untrusted.organization_reg(borg)
assert r['success']     == False
assert r['status_code'] == 400

# invalid country
borg["country"] = "Karnataka"
r = untrusted.organization_reg(borg)
assert r['status_code'] == 400

# invalid name
borg["name"] = ""
r = untrusted.organization_reg(borg)
assert r['success']     == False
assert r['status_code'] == 400

# invalid domain
borg["website"] = "abc$9091.oa32.com.co.434"
r = untrusted.organization_reg(borg)
assert r['success']     == False
assert r['status_code'] == 400

# success
r = untrusted.organization_reg(org)
assert r['success']     == True
assert r['status_code'] == 200
org_id = r['response']['organizations'][0]['id']

# same website
r = untrusted.organization_reg(org)
assert r['success']     == False
assert r['status_code'] == 403

# get all orgs
r = get_orgs()
assert r['success']     == True
assert r['status_code'] == 200
orgs = r['response']['organizations']

for i in orgs:
        if(org_id == i['id']):
                assert i['name'] == org['name']
                break

### Provider Approval APIs ###

name = { "title"        : "mr.",
         "firstName"    : "abc",
         "lastName"     : "xyz"
         }

csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIICjDCCAXQCAQAwRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQK\nDAtNeU9yZywgSW5jLjEVMBMGA1UEAwwMbXlkb21haW4uY29tMIIBIjANBgkqhkiG\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyhF2a5PeL72zGdL47/6zVQQQtZJcO01iVbjR\nSSyswUa2jcfYfoQEVKo1JAz25G3nYfSW1Te3OWjuihvPhZeatFSUwTxcZJFxzIWm\n4/gOQIhJKCA/Wry3liW2sjIGLuHxeH2BoQCIEZyYcqVpRWEJ9RusRFcwPgvROigh\nhMXhgE86uaIRs0yPqzhc7sl53T4qx6qvQJ6uTXBWBvUELgSSgeyaT0gwU1mGmPck\n7Svo6tsWfBFfgT5Ecbqsc2nqChAExgocp5tkPJYcy8FB/tU/FW0rFthqecSvMrpS\ncZW9+iyzseyPrcK9ka6XSlVu9EoX82RW7SRyRL2T5VN3JemXfQIDAQABoAAwDQYJ\nKoZIhvcNAQELBQADggEBAJRFEYn6dSzEYpgYLItUm7Sp3LzquJw7QfMyUvsy45rp\n0VTdQdYp/hVR2aCLiD33ht4FxlhbZm/8XcTuYolP6AbF6FldxWmmFFS9LRAj7nTV\ndU1pZftwFPp6JsKUCYHVsuxs7swliXbEcBVtD6QktzZNrRJmUKi38DAFcbFwgLaM\nG/iRIm4DDj2hmanKp+vUWjXfj13naa7bDtIlzW96y24jsu+naabg8MVShfGCStIv\nrX3T2JkkSjpTw7YzIpgI8/Zg9VR1l0udvfh9bn7mjmOYc3EYwJKvuJDn1TzVuIIi\n9NmVasTjhZJ0PyWithWuZplo/LXUwSoid8HVyqe5ZVI=\n-----END CERTIFICATE REQUEST-----\n"

# random email 
email_name  = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(6)) 
email       = email_name + '@gmail.com' 

r = provider_reg(email, '9845596200', name , org_id, csr)
assert r['success']     == True
assert r['status_code'] == 200

r = untrusted.get_provider_regs()
assert r['success']     == True
assert r['status_code'] == 200
providers = r['response']
check = False
for i in providers:
        if i["email"] == email:
                assert i["status"] == "pending"
                user_id = i["id"]
                check = True
assert check == True

r = untrusted.get_provider_regs("hello")
assert r['success']     == False
assert r['status_code'] == 400

# should not be in approved
r = untrusted.get_provider_regs("approved")
assert r['status_code'] in [200, 400]
if r['status_code'] == 200:
        providers = r['response']
        for i in providers:
                assert i['email'] != email

# should not be in rejected
r = untrusted.get_provider_regs("rejected")
assert r['status_code'] in [200, 400]
if r['status_code'] == 200:
        providers = r['response']
        for i in providers:
                assert i['email'] != email

r = untrusted.update_provider_status(user_id, 'approved')
assert r['success']     == True
assert r['status_code'] == 200

r = untrusted.get_provider_regs("approved")
assert r['success']     == True
assert r['status_code'] == 200
providers = r['response']
r = any(i['email'] == email and i['status'] == 'approved' for i in providers)
assert r == True

# should not be in pending
r = untrusted.get_provider_regs("pending")
assert r['status_code'] in [200, 400]
if r['status_code'] == 200:
        providers = r['response']
        for i in providers:
                assert i['email'] != email

# should not be in rejected
r = untrusted.get_provider_regs("rejected")
assert r['status_code'] in [200, 400]
if r['status_code'] == 200:
        providers = r['response']
        for i in providers:
                assert i['email'] != email

# test rejected flow
remail_name  = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(6)) 
remail       = remail_name + '@gmail.com' 

r = provider_reg(remail, '9845596200', name , org_id, csr)
assert r['success']     == True
assert r['status_code'] == 200

r = untrusted.get_provider_regs()
assert r['success']     == True
assert r['status_code'] == 200
providers = r['response']
check = False
for i in providers:
        if i["email"] == remail:
                assert i["status"] == "pending"
                ruser_id = i["id"]
                check = True
assert check == True

r = untrusted.update_provider_status(ruser_id, 'rejected')
assert r['success']     == True
assert r['status_code'] == 200

# should be in rejected
r = untrusted.get_provider_regs("rejected")
assert r['success']     == True
assert r['status_code'] == 200
providers = r['response']
r = any(i['email'] == remail and i['status'] == 'rejected' for i in providers)
assert r == True

# should not be in approved
r = untrusted.get_provider_regs("approved")
assert r['success']     == True
assert r['status_code'] == 200
providers = r['response']
for i in providers:
        assert i['email'] != remail

# should not be in pending
r = untrusted.get_provider_regs()
assert r['status_code'] in [200, 400]
if r['status_code'] == 200:
        providers = r['response']
        for i in providers:
                assert i['email'] != email
