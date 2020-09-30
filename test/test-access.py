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
r = untrusted.provider_access(email, 'consumer', resource_id, 'resourcegroup')
assert r['success']     == False
assert r['status_code'] == 400

# Invalid capabilities
caps = ["hello", "world"]
r = untrusted.provider_access(email, 'consumer', resource_id, 'resourcegroup', caps)
assert r['success']     == False
assert r['status_code'] == 400

caps = ['temporal'];
r = untrusted.provider_access(email, 'consumer', resource_id, 'resourcegroup', caps)
assert r['success']     == True
assert r['status_code'] == 200

# same capability
r = untrusted.provider_access(email, 'consumer', resource_id, 'resourcegroup', caps)
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
caps = ['subscription', 'temporal'];
r = untrusted.provider_access(email, 'consumer', resource_id, 'resourcegroup', caps)
assert r['success']     == False
assert r['status_code'] == 403

caps = ['subscription'];
r = untrusted.provider_access(email, 'consumer', resource_id, 'resourcegroup', caps)
assert r['success']     == True
assert r['status_code'] == 200

body = {"id" : resource_id + "/someitem", "apis" : ["/ngsi-ld/v1/subscription"] }
r = consumer.get_token(body)
assert r['success']     is True

# complex
caps = ['complex']
r = untrusted.provider_access(email, 'consumer', resource_id, 'resourcegroup', caps)
assert r['success']     == True
assert r['status_code'] == 200

body = {"id" : resource_id + "/someitem", "apis" : ["/ngsi-ld/v1/entityOperations/query"] }
r = consumer.get_token(body)
assert r['success']     is True

body = {"id" : resource_id + "/someitem", "apis" : ["/ngsi-ld/v1/entities", "/ngsi-ld/v1/temporal/entities"] }
r = consumer.get_token(body)
assert r['success']     is True

# try all 3 caps
resource_id = provider_id + '/rs.example.co.in/' + resource_group
caps = ['complex','subscription', 'temporal']
r = untrusted.provider_access(email, 'consumer', resource_id, 'resourcegroup', caps)
assert r['success']     == True
assert r['status_code'] == 200

apis = ["/ngsi-ld/v1/entityOperations/query", "/ngsi-ld/v1/entities", "/ngsi-ld/v1/temporal/entities","/ngsi-ld/v1/entities/" + resource_id, "/ngsi-ld/v1/subscription"]
body = {"id" : resource_id + "/someitem", "apis" : apis }
r = consumer.get_token(body)

assert r['success']     is True

# rule exists
r = untrusted.provider_access(email, 'consumer', resource_id, 'resourcegroup', caps)
assert r['success']     == False
assert r['status_code'] == 403

# user does not exist
r = untrusted.provider_access(email, 'onboarder', resource_id, 'resourcegroup')
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

r = untrusted.provider_access(email, 'onboarder')
assert r['success']     == True
assert r['status_code'] == 200

r = consumer.get_token(body)
assert r['success']     is True
assert None != r['response']['token']

r = untrusted.provider_access(email, 'onboarder')
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
r = untrusted.provider_access(email, 'data ingester', resource_id, 'catalogue')
assert r['success']     == False
assert r['status_code'] == 400

r = untrusted.provider_access(email, 'data ingester', resource_id, 'resourcegroup')
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
r = untrusted.provider_access(email, 'data ingester', '/aaaaa/sssss/sada/', 'resourcegroup')
assert r['success']     == False
assert r['status_code'] == 400

r = untrusted.provider_access(email, 'data ingester', '/aaaaa/sssss', 'resourcegroup')
assert r['success']     == False
assert r['status_code'] == 400

# get all rules
r = untrusted.get_provider_access()
assert r['success']     == True
assert r['status_code'] == 200
rules = r['response']
for r in rules:
        print(r['capabilities'])
        if r['email'] == email and r['role'] == 'consumer':
                assert set(r['capabilities']).issubset(set(['temporal', 'subscription', 'complex']))
                assert len(r['capabilities']) <= 3 and len(r['capabilities']) >= 1
        if r['email'] == email and r['role'] == 'onboarder':
                assert r['item_type'] == 'catalogue'
        if r['email'] == email and r['role'] == 'data ingester':
                assert r['policy'].endswith('"/iudx/v1/adapter"')

