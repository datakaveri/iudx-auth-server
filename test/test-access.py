from init import untrusted
from init import consumer
from access import *

init()

# use consumer certificate to register
email   = "barun@iisc.ac.in"
r       = provider_reg(email, '7529547992', name , org, csr)

# delete all old policies
policy = "x can access x"
r = untrusted.set_policy(policy)
assert r['success'] is True

provider_id = 'rbccps.org/f3dad987e514af08a4ac46cf4a41bd1df645c8cc'

##### consumer #####

resource_id = provider_id + '/rs.example.com/somegroup'
body        = { "id"    : resource_id + "/someitem"}

# token request should fail
r = consumer.get_token(body)
assert r['success']     is False

r = change_role(email, 'consumer')
assert r == True

r = untrusted.provider_access(email, 'consumer', resource_id, 'resourcegroup')
assert r['success']     == True
assert r['status_code'] == 200

# token request should pass
r = consumer.get_token(body)
assert r['success']     is True
assert None != r['response']['token']

# request for other items in resource group
body = {"id" : resource_id + "/someitem/someotheritem", "api" : "/iudx/v1/adapter" }
r = consumer.get_token(body)
assert r['success']     is True

# rule exists for provider+accesser+role+resource
r = untrusted.provider_access(email, 'consumer', resource_id, 'resourcegroup')
assert r['success']     == False
assert r['status_code'] == 403

# user does not exist
r = untrusted.provider_access(email, 'onboarder', resource_id, 'resourcegroup')
assert r['success']     == False
assert r['status_code'] == 404

##### onboarder #####

body = { "id"    : provider_id + "/catalogue.iudx.io/catalogue/crud" }

# onboarder token request should fail
r = consumer.get_token(body)
assert r['success']     is False

r = change_role(email, 'onboarder')
assert r == True

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

resource_id = provider_id + "/rs.example.com/someothergroup"
body        = {"id" : resource_id + "/someitem", "api" : "/iudx/v1/adapter" }

# data ingester token request should fail
r = consumer.get_token(body)
assert r['success']     is False

r = change_role(email, 'data ingester')
assert r == True

# invalid resource type
r = untrusted.provider_access(email, 'data ingester', resource_id, 'catalogue')
assert r['success']     == False
assert r['status_code'] == 403

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
assert r['status_code'] == 403

r = untrusted.provider_access(email, 'data ingester', '/aaaaa/sssss', 'resourcegroup')
assert r['success']     == False
assert r['status_code'] == 403

