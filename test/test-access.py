from init import untrusted
from init import consumer
from access import *
from consent import role_reg
import random
import string

init_provider()

# use consumer certificate to register
email   = "barun@iisc.ac.in"
assert reset_role(email) == True
org_id = add_organization("iisc.ac.in")

# delete all old policies using acl/set API
policy = "x can access x"
r = untrusted.set_policy(policy)
assert r['success'] is True

# provider ID of abc.xyz@rbccps.org
provider_id = 'rbccps.org/f3dad987e514af08a4ac46cf4a41bd1df645c8cc'

##### consumer #####

resource_group = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
resource_id = provider_id + '/rs.example.com/' + resource_group

# token request should fail
body = {"id" : resource_id + "/someitem", "apis" : ["/ngsi-ld/v1/entities"] }
r = consumer.get_token(body)
assert r['success']     is False

r = role_reg(email, '9454234223', name , ["consumer"], None, csr)
assert r['success']     == True
assert r['status_code'] == 200

# No capabilities
req = {"user_email": email, "user_role":'consumer', "item_id":resource_id, "item_type":"resourcegroup"}
r = untrusted.provider_access([req])
assert r['success']     == False
assert r['status_code'] == 400

# Invalid capabilities
req["capability"] = ["hello", "world"]
r = untrusted.provider_access([req])
assert r['success']     == False
assert r['status_code'] == 400

req["capability"] = ['temporal'];
r = untrusted.provider_access([req])
assert r['success']     == True
assert r['status_code'] == 200

# same capability
r = untrusted.provider_access([req])
assert r['success']     == False
assert r['status_code'] == 403

# token request will not pass without API
body    = { "id"    : resource_id + "/someitem"}
r       = consumer.get_token(body)
assert r['success']     is False

body = {"id" : resource_id + "/someitem", "apis" : ["/ngsi-ld/v1/entities/" + resource_id] }
r = consumer.get_token(body)
assert r['success']     is True

# temporal does not have /entities
body = {"id" : resource_id + "/someitem", "apis" : ["/ngsi-ld/v1/entities", "/ngsi-ld/v1/temporal/entities"] }
r = consumer.get_token(body)
assert r['success']     is False

body = {"id" : resource_id + "/someitem", "apis" : ["/ngsi-ld/v1/temporal/entities"] }
r = consumer.get_token(body)
assert r['success']     is True

# will not work for other APIs
body = {"id" : resource_id + "/someitem", "apis" : ["/ngsi-ld/v1/entityOperations/query"] }
r = consumer.get_token(body)
assert r['success']     is False

# temporal rule already exists
req["capability"] = ['subscription', 'temporal'];
r = untrusted.provider_access([req])
assert r['success']     == False
assert r['status_code'] == 403

req["capability"] = ['subscription'];
r = untrusted.provider_access([req])
assert r['success']     == True
assert r['status_code'] == 200

body = {"id" : resource_id + "/someitem", "apis" : ["/ngsi-ld/v1/subscription"] }
r = consumer.get_token(body)
assert r['success']     is True

# complex
req["capability"] = ['complex']
r = untrusted.provider_access([req])
assert r['success']     == True
assert r['status_code'] == 200

body = {"id" : resource_id + "/someitem", "apis" : ["/ngsi-ld/v1/entityOperations/query"] }
r = consumer.get_token(body)
assert r['success']     is True

body = {"id" : resource_id + "/someitem", "apis" : ["/ngsi-ld/v1/entities", "/ngsi-ld/v1/temporal/entities"] }
r = consumer.get_token(body)
assert r['success']     is True

# try all 3 req["capability"]
req["item_id"] = provider_id + '/rs.example.co.in/' + resource_group
req["capability"] = ['complex','subscription', 'temporal']
r = untrusted.provider_access([req])
assert r['success']     == True
assert r['status_code'] == 200

apis = ["/ngsi-ld/v1/entityOperations/query", "/ngsi-ld/v1/entities", "/ngsi-ld/v1/temporal/entities","/ngsi-ld/v1/entities/" + resource_id, "/ngsi-ld/v1/subscription"]
body = {"id" : resource_id + "/someitem", "apis" : apis }
r = consumer.get_token(body)
assert r['success']     is True

# rule exists
r = untrusted.provider_access([req])
assert r['success']     == False
assert r['status_code'] == 403

# user does not exist
req["user_role"] = "onboarder"
r = untrusted.provider_access([req])
assert r['success']     == False
assert r['status_code'] == 403

##### onboarder #####

body = { "id"    : provider_id + "/catalogue.iudx.io/catalogue/crud" }

# onboarder token request should fail
r = consumer.get_token(body)
assert r['success']     is False

r = role_reg(email, '9454234223', name , ["onboarder"], org_id)
assert r['success']     == True
assert r['status_code'] == 200

req["user_role"] = "onboarder"
r = untrusted.provider_access([req])
assert r['success']     == True
assert r['status_code'] == 200

r = consumer.get_token(body)
assert r['success']     is True
assert None != r['response']['token']

req["user_role"] = "onboarder"
r = untrusted.provider_access([req])
assert r['success']     == False
assert r['status_code'] == 403

##### data ingester #####

resource_group = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
resource_id = provider_id + "/rs.example.com/" + resource_group

body        = {"id" : resource_id + "/someitem", "api" : "/iudx/v1/adapter" }

# data ingester token request should fail
r = consumer.get_token(body)
assert r['success']     is False

r = role_reg(email, '9454234223', name , ["data ingester"], org_id)
assert r['success']     == True
assert r['status_code'] == 200

# invalid resource type
req["user_role"]    = "data ingester"
req["item_id"]      = resource_id
req["item_type"]    = "catalogue"
r = untrusted.provider_access([req])
assert r['success']     == False
assert r['status_code'] == 400

req["item_type"]    = "resourcegroup"
r = untrusted.provider_access([req])
assert r['success']     == True
assert r['status_code'] == 200

# without adapter API
body = {"id"    : resource_id + "/*" }

r = consumer.get_token(body)
assert r['success']     is False

body["api"] = "/iudx/v1/adapter"
r = consumer.get_token(body)
assert r['success']     is True

# request for other items in resource group
body = {"id" : resource_id + "/someitem/someotheritem", "api" : "/iudx/v1/adapter" }
r = consumer.get_token(body)
assert r['success']     is True

# invalid resource ID
req["item_id"]      = '/aaaaa/sssss/sada/'
r = untrusted.provider_access([req])
assert r['success']     == False
assert r['status_code'] == 400

req["item_id"]      = '/aaaaa/sssss'
r = untrusted.provider_access([req])
assert r['success']     == False
assert r['status_code'] == 400

# get all rules
r = untrusted.get_provider_access()
assert r['success']     == True
assert r['status_code'] == 200
rules = r['response']
for r in rules:
        if r['email'] == email and r['role'] == 'consumer':
                assert set(r['capabilities']).issubset(set(['temporal', 'subscription', 'complex']))
                assert len(r['capabilities']) <= 3 and len(r['capabilities']) >= 1
        if r['email'] == email and r['role'] == 'onboarder':
                assert r['item_type'] == 'catalogue'
        if r['email'] == email and r['role'] == 'data ingester':
                assert r['policy'].endswith('"/iudx/v1/adapter"')

### setting multiple rules ###

email_name  = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(6)) 
email = email_name + '@iisc.ac.in'

req = {"user_email": email, "user_role":'consumer', "item_id":resource_id, "item_type":"resourcegroup", "capability":["temporal"]}
req1 = {"user_email": email, "user_role":'onboarder'}

r = role_reg(email, '9454234223', name , ["onboarder", "consumer", "data ingester"], org_id, csr)
assert r['success']     == True
assert r['status_code'] == 200

# duplicate rule
r = untrusted.provider_access([req1, req1, req])
assert r['success']     == False
assert r['status_code'] == 400

# valid
r = untrusted.provider_access([req1, req])
assert r['success']     == True
assert r['status_code'] == 200

# setting same rule again
r = untrusted.provider_access([req, req, req])
assert r['success']     == False
assert r['status_code'] == 403

req2 = req.copy()
req2["capability"] = ["subscription"]

# duplicate rule
r = untrusted.provider_access([req2, req2])
assert r['success']     == False
assert r['status_code'] == 400

# setting same rule again
r = untrusted.provider_access([req2, req])
assert r['success']     == False
assert r['status_code'] == 403

# duplicate rule
req["capability"] = ["complex"]
r = untrusted.provider_access([req2, req, req2])
assert r['success']     == False
assert r['status_code'] == 400

# duplicates in caps array
req["capability"] = ["complex", "subscription"]
r = untrusted.provider_access([req2, req])
assert r['success']     == False
assert r['status_code'] == 400

# existing in caps array
req["capability"] = ["complex", "temporal"]
r = untrusted.provider_access([req2, req])
assert r['success']     == False
assert r['status_code'] == 403

# setting complex and subscription
req["capability"] = ["complex"]
r = untrusted.provider_access([req2, req])
assert r['success']     == True
assert r['status_code'] == 200

req2["user_role"] = "data ingester"
r = untrusted.provider_access([req2, req])
assert r['success']     == False
assert r['status_code'] == 403

r = untrusted.provider_access([req2, req2])
assert r['success']     == False
assert r['status_code'] == 400

resource_group = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
resource_id = provider_id + "/rs.example.com/" + resource_group
req["item_id"] = resource_id

# set different resources
r = untrusted.provider_access([req2, req])
assert r['success']     == True
assert r['status_code'] == 200

# get all rules for new email
check_con = False
check_onb = False
check_dti = False
r = untrusted.get_provider_access()
assert r['success']     == True
assert r['status_code'] == 200
rules = r['response']
for r in rules:
        if r['email'] == email and r['role'] == 'consumer':
                assert set(r['capabilities']).issubset(set(['temporal', 'subscription', 'complex']))
                assert len(r['capabilities']) <= 3 and len(r['capabilities']) >= 1
                check_con = True
        if r['email'] == email and r['role'] == 'onboarder':
                assert r['item_type'] == 'catalogue'
                check_onb = True
        if r['email'] == email and r['role'] == 'data ingester':
                assert r['policy'].endswith('"/iudx/v1/adapter"')
                check_dti = True

assert check_con == True
assert check_onb == True
assert check_dti == True
