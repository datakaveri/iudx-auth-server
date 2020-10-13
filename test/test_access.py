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

ingester_id = 0 
consumer_id = 0
onboarder_id = 0
cat_id = ''

# delete all old policies using acl/set API
policy = "x can access x"
r = untrusted.set_policy(policy)
assert r['success'] is True

# provider ID of abc.xyz@rbccps.org
provider_id = 'rbccps.org/f3dad987e514af08a4ac46cf4a41bd1df645c8cc'


##### consumer #####

resource_group = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
resource_id = provider_id + '/rs.example.com/' + resource_group

req = {"user_email": email, "user_role":'consumer', "item_id":resource_id, "item_type":"resourcegroup"}

def test_consumer_no_rule_set():
        # token request should fail
        body = {"id" : resource_id + "/someitem", "apis" : ["/ngsi-ld/v1/entities"] }
        r = consumer.get_token(body)
        assert r['success']     is False

def test_consumer_reg():
        r = role_reg(email, '9454234223', name , ["consumer"], None, csr)
        assert r['success']     == True
        assert r['status_code'] == 200

def test_no_caps():
        # No capabilities
        global req
        r = untrusted.provider_access([req])
        assert r['success']     == False
        assert r['status_code'] == 400

def test_invalid_caps():
        # Invalid capabilities
        global req
        req["capability"] = ["hello", "world"]
        r = untrusted.provider_access([req])
        assert r['success']     == False
        assert r['status_code'] == 400

def test_get_temporal_cap():
        global req
        req["capability"] = ['temporal'];
        r = untrusted.provider_access([req])
        assert r['success']     == True
        assert r['status_code'] == 200

def test_get_same_cap():
        # same capability
        global req
        r = untrusted.provider_access([req])
        assert r['success']     == False
        assert r['status_code'] == 403

def test_get_token_no_api():
        # token request will not pass without API
        body    = { "id"    : resource_id + "/someitem"}
        r       = consumer.get_token(body)
        assert r['success']     is False

def test_get_temporal_token():
        body = {"id" : resource_id + "/someitem", "apis" : ["/ngsi-ld/v1/entities/" + resource_id] }
        r = consumer.get_token(body)
        assert r['success']     is True

        body = {"id" : resource_id + "/someitem", "apis" : ["/ngsi-ld/v1/temporal/entities"] }
        r = consumer.get_token(body)
        assert r['success']     is True

def test_get_token_no_access():
        # temporal does not have /entities
        body = {"id" : resource_id + "/someitem", "apis" : ["/ngsi-ld/v1/entities", "/ngsi-ld/v1/temporal/entities"] }
        r = consumer.get_token(body)
        assert r['success']     is False

def test_get_complex_api_token():
        # will not work for other APIs
        body = {"id" : resource_id + "/someitem", "apis" : ["/ngsi-ld/v1/entityOperations/query"] }
        r = consumer.get_token(body)
        assert r['success']     is False

def test_get_same_cap_in_set():
        # temporal rule already exists
        global req
        req["capability"] = ['subscription', 'temporal'];
        r = untrusted.provider_access([req])
        assert r['success']     == False
        assert r['status_code'] == 403

def test_get_subscription_cap():
        global req
        req["capability"] = ['subscription'];
        r = untrusted.provider_access([req])
        assert r['success']     == True
        assert r['status_code'] == 200

def test_get_subscription_token():
        body = {"id" : resource_id + "/someitem", "apis" : ["/ngsi-ld/v1/subscription"] }
        r = consumer.get_token(body)
        assert r['success']     is True

def test_get_complex_cap():
        # complex
        global req
        req["capability"] = ['complex']
        r = untrusted.provider_access([req])
        assert r['success']     == True
        assert r['status_code'] == 200

def test_get_complex_token():
        body = {"id" : resource_id + "/someitem", "apis" : ["/ngsi-ld/v1/entityOperations/query"] }
        r = consumer.get_token(body)
        assert r['success']     is True

        body = {"id" : resource_id + "/someitem", "apis" : ["/ngsi-ld/v1/entities", "/ngsi-ld/v1/temporal/entities"] }
        r = consumer.get_token(body)
        assert r['success']     is True

def test_get_all_caps():
        # try all 3 caps
        global req
        req["item_id"] = provider_id + '/rs.example.co.in/' + resource_group
        req["capability"] = ['complex','subscription', 'temporal']
        r = untrusted.provider_access([req])
        assert r['success']     == True
        assert r['status_code'] == 200

def get_token_all_apis():
        apis = ["/ngsi-ld/v1/entityOperations/query", "/ngsi-ld/v1/entities", "/ngsi-ld/v1/temporal/entities","/ngsi-ld/v1/entities/" +  provider_id + '/rs.example.co.in/' + resource_group, "/ngsi-ld/v1/subscription"]
        body = {"id" : provider_id + '/rs.example.co.in/' + "/someitem", "apis" : apis }
        r = consumer.get_token(body)
        assert r['success']     is True

def test_set_existing_rule():
        # rule exists
        global req
        r = untrusted.provider_access([req])
        assert r['success']     == False
        assert r['status_code'] == 403

def test_set_rule_for_invalid_user():
        # user does not exist
        global req
        req["user_role"] = "onboarder"
        r = untrusted.provider_access([req])
        assert r['success']     == False
        assert r['status_code'] == 403

##### onboarder #####

def test_get_onboarder_token_fail():
        body = { "id"    : provider_id + "/catalogue.iudx.io/catalogue/crud" }

        # onboarder token request should fail
        r = consumer.get_token(body)
        assert r['success']     is False

def test_reg_onboarder():
        r = role_reg(email, '9454234223', name , ["onboarder"], org_id)
        assert r['success']     == True
        assert r['status_code'] == 200

def test_set_onboarder_rule():
        global req
        req["user_role"] = "onboarder"
        r = untrusted.provider_access([req])
        assert r['success']     == True
        assert r['status_code'] == 200

def test_get_onboarder_token():
        body = { "id"    : provider_id + "/catalogue.iudx.io/catalogue/crud" }

        r = consumer.get_token(body)
        assert r['success']     is True
        assert None != r['response']['token']

def test_set_onboarder_rule_again():
        global req
        req["user_role"] = "onboarder"
        r = untrusted.provider_access([req])
        assert r['success']     == False
        assert r['status_code'] == 403

##### data ingester #####

diresource_group = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
diresource_id = provider_id + "/rs.example.com/" + diresource_group

body        = {"id" : diresource_id + "/someitem", "api" : "/iudx/v1/adapter" }

def test_get_ingester_token_fail():
        # data ingester token request should fail
        r = consumer.get_token(body)
        assert r['success']     is False

def test_reg_ingester():
        r = role_reg(email, '9454234223', name , ["data ingester"], org_id)
        assert r['success']     == True
        assert r['status_code'] == 200

def test_invalid_resource_type():
        # invalid resource type
        global req
        req["user_role"]    = "data ingester"
        req["item_id"]      = diresource_id
        req["item_type"]    = "catalogue"
        r = untrusted.provider_access([req])
        assert r['success']     == False
        assert r['status_code'] == 400

def test_set_ingester_rule():
        global req
        req["user_role"]    = "data ingester"
        req["item_id"]      = diresource_id
        req["item_type"]    = "resourcegroup"
        r = untrusted.provider_access([req])
        assert r['success']     == True
        assert r['status_code'] == 200

def test_token_without_api():
        # without adapter API
        body = {"id"    : diresource_id + "/*" }

        r = consumer.get_token(body)
        assert r['success']     is False

def test_get_ingester_token():
        body = {"id"    : diresource_id + "/*" }
        body["api"] = "/iudx/v1/adapter"
        r = consumer.get_token(body)
        assert r['success']     is True

def test_token_for_item():
        # request for other items in resource group
        body = {"id" : diresource_id + "/someitem/someotheritem", "api" : "/iudx/v1/adapter" }
        r = consumer.get_token(body)
        assert r['success']     is True

def test_token_invalid_rid():
        # invalid resource ID
        global req
        req["item_id"]      = '/aaaaa/sssss/sada/'
        r = untrusted.provider_access([req])
        assert r['success']     == False
        assert r['status_code'] == 400

        req["item_id"]      = '/aaaaa/sssss'
        r = untrusted.provider_access([req])
        assert r['success']     == False
        assert r['status_code'] == 400

def test_get_access_rules():
        global ingester_id, consumer_id, onboarder_id
        r = untrusted.get_provider_access()
        assert r['success']     == True
        assert r['status_code'] == 200
        rules = r['response']
        for r in rules:
                if r['email'] == email and r['role'] == 'consumer' and resource_id == r['item']['cat_id']:
                        assert set(r['capabilities']).issubset(set(['temporal', 'subscription', 'complex']))
                        assert len(r['capabilities']) <= 3 and len(r['capabilities']) >= 1
                        consumer_id = r['id']
                if r['email'] == email and r['role'] == 'onboarder':
                        assert r['item_type'] == 'catalogue'
                        onboarder_id = r['id']
                if r['email'] == email and r['role'] == 'data ingester' and diresource_id == r['item']['cat_id']:
                        assert r['policy'].endswith('"/iudx/v1/adapter"')
                        ingester_id = r['id']

### deleting rules ###

def test_delete_onboarder_rule():
        global onboarder_id

        token_body = { "id"    : provider_id + "/catalogue.iudx.io/catalogue/crud" }

        r = consumer.get_token(token_body)
        assert r['success']     is True
        assert None != r['response']['token']

        body = {"id" : onboarder_id}
        r = untrusted.delete_rule([body])
        assert r['success']     == True
        assert r['status_code'] == 200

        # onboarder token request should fail
        r = consumer.get_token(token_body)
        assert r['success']     is False

def test_delete_ingester_temporal():
        global ingester_id, consumer_id
        
        token_body = {"id" : diresource_id + "/someitem/someotheritem", "api" : "/iudx/v1/adapter" }
        r = consumer.get_token(token_body)
        assert r['success']     is True

        token_body = {"id" : resource_id + "/something", "apis" : ["/ngsi-ld/v1/temporal/entities"] }
        r = consumer.get_token(token_body)
        assert r['success']     is True

        body = [{"id": ingester_id}, {"id": consumer_id, "capability": ["temporal"]}]
        r = untrusted.delete_rule(body)
        assert r['success']     == True
        assert r['status_code'] == 200

        token_body = {"id" : diresource_id + "/someitem/someotheritem", "api" : "/iudx/v1/adapter" }
        r = consumer.get_token(token_body)
        assert r['success']     is False

        token_body = {"id" : resource_id + "/something", "apis" : ["/ngsi-ld/v1/temporal/entities"] }
        r = consumer.get_token(token_body)
        assert r['success']     is False

        body = [{"id": ingester_id}, {"id": consumer_id, "capability": ["temporal"]}]
        r = untrusted.delete_rule(body)
        assert r['success']     == False
        assert r['status_code'] == 403

def test_delete_consumer_rule():
        global consumer_id

        apis = ["/ngsi-ld/v1/entityOperations/query", "/ngsi-ld/v1/entities","/ngsi-ld/v1/entities/" +  resource_id, "/ngsi-ld/v1/subscription"]
        token_body = {"id" : resource_id + "/someitem", "apis" : apis }
        r = consumer.get_token(token_body)
        assert r['success']     is True

        body = [{"id": consumer_id, "capability": ["temporal", "subscription", "complex"]}]
        r = untrusted.delete_rule(body)
        assert r['success']     == False
        assert r['status_code'] == 403

        token_body = {"id" : resource_id + "/someitem", "apis" : apis }
        r = consumer.get_token(token_body)
        assert r['success']     is True

        body = [{"id": consumer_id}]
        r = untrusted.delete_rule(body)
        assert r['success']     == True
        assert r['status_code'] == 200

        token_body = {"id" : resource_id + "/someitem", "apis" : apis }
        r = consumer.get_token(token_body)
        assert r['success']     is False

        token_body = {"id" : resource_id + "/someitem", "apis" : ["/ngsi-ld/v1/subscription"] }
        r = consumer.get_token(token_body)
        assert r['success']     is False

### setting multiple rules ###
remail_name  = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(6)) 
remail = remail_name + '@iisc.ac.in'

r = role_reg(remail, '9454234223', name , ["onboarder", "consumer", "data ingester"], org_id, csr)
assert r['success']     == True
assert r['status_code'] == 200

_req = {"user_email": remail, "user_role":'consumer', "item_id":resource_id, "item_type":"resourcegroup", "capability":["temporal"]}
_req1 = {"user_email": remail, "user_role":'onboarder'}

_req2 = _req.copy()
_req2["capability"] = ["subscription"]

def test_multiple_duplicate():
        r = untrusted.provider_access([_req1, _req1, _req])
        assert r['success']     == False
        assert r['status_code'] == 400

def test_multiple_onb_temporal():
        r = untrusted.provider_access([_req1, _req])
        assert r['success']     == True
        assert r['status_code'] == 200

def test_multiple_same_rule():
        r = untrusted.provider_access([_req, _req, _req])
        assert r['success']     == False
        assert r['status_code'] == 403

def test_multiple_duplicate_subs():
        r = untrusted.provider_access([_req2, _req2])
        assert r['success']     == False
        assert r['status_code'] == 400

        r = untrusted.provider_access([_req2, _req])
        assert r['success']     == False
        assert r['status_code'] == 403

def test_multiple_complex_sub_dup():
        global _req
        _req["capability"] = ["complex"]
        r = untrusted.provider_access([_req2, _req, _req2])
        assert r['success']     == False
        assert r['status_code'] == 400

def test_multiple_duplicate_in_caps_array():
        global _req
        _req["capability"] = ["complex", "subscription"]
        r = untrusted.provider_access([_req2, _req])
        assert r['success']     == False
        assert r['status_code'] == 400

def test_multiple_existing_in_caps_array():
        global _req
        _req["capability"] = ["complex", "temporal"]
        r = untrusted.provider_access([_req2, _req])
        assert r['success']     == False
        assert r['status_code'] == 403

def test_multiple_complex_sub_success():
        global _req
        # success
        _req["capability"] = ["complex"]
        r = untrusted.provider_access([_req2, _req])
        assert r['success']     == True
        assert r['status_code'] == 200

def test_multiple_ingester_consumer():
        global _req2, _req
        _req2["user_role"] = "data ingester"
        r = untrusted.provider_access([_req2, _req])
        assert r['success']     == False
        assert r['status_code'] == 403

        r = untrusted.provider_access([_req2, _req2])
        assert r['success']     == False
        assert r['status_code'] == 400

        resource_group = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
        resource_id = provider_id + "/rs.example.com/" + resource_group
        _req["item_id"] = resource_id

        r = untrusted.provider_access([_req2, _req])
        assert r['success']     == True
        assert r['status_code'] == 200

def test_multiple_get_all_rules():
        # get all rules for new email
        check_con = False
        check_onb = False
        check_dti = False
        r = untrusted.get_provider_access()
        assert r['success']     == True
        assert r['status_code'] == 200
        rules = r['response']
        for r in rules:
                if r['email'] == remail and r['role'] == 'consumer':
                        assert set(r['capabilities']).issubset(set(['temporal', 'subscription', 'complex']))
                        assert len(r['capabilities']) <= 3 and len(r['capabilities']) >= 1
                        check_con = True
                if r['email'] == remail and r['role'] == 'onboarder':
                        assert r['item_type'] == 'catalogue'
                        check_onb = True
                if r['email'] == remail and r['role'] == 'data ingester':
                        assert r['policy'].endswith('"/iudx/v1/adapter"')
                        check_dti = True

        assert check_con == True
        assert check_onb == True
        assert check_dti == True
