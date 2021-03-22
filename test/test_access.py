from init import untrusted
from init import consumer
from access import *
from session import *
from consent import role_reg
import random
import string
import pytest

# use consumer certificate to register
email   = "barun@iisc.ac.in"
org_id = add_organization("iisc.ac.in")

remail_name  = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(6)) 
remail = remail_name + '@iisc.ac.in'

ingester_id = 0 
consumer_id = 0
onboarder_id = 0
cat_id = ''

# provider ID of abc.xyz@rbccps.org
provider_id = 'rbccps.org/f3dad987e514af08a4ac46cf4a41bd1df645c8cc'

@pytest.fixture(scope="session", autouse=True)
def init():
        init_provider("xyz.abc@rbccps.org")
        assert reset_role(email) == True

        ######### session ID setup ###########
        r = untrusted.get_session_id(ALL_SECURE_ENDPOINTS_BODY)
        assert r['success'] is True

        untrusted.set_user_session_id(fetch_sessionId('abc.xyz@rbccps.org'))

        ##### for multiple rule tests #####
        r = role_reg(remail, '9454234223', name , ["onboarder", "consumer", "data ingester", "delegate"], org_id, csr)
        assert r['success']     == True
        assert r['status_code'] == 200


##### consumer #####

resource_group = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
resource_id = provider_id + '/rs.iudx.io/' + resource_group

fileresource_group = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
fileresource_id = provider_id + "/file.iudx.io/" + fileresource_group

file_diresource_group = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
file_diresource_id = provider_id + "/file.iudx.io/" + file_diresource_group

req = {"user_email": email, "user_role":'consumer', "item_id":resource_id, "item_type":"resourcegroup"}

def test_consumer_unregistered():
        # token request should fail - not registered 
        body = {"request" : [resource_id] }
        r = consumer.get_token(body)
        assert r['success']     is False
        assert r['status_code'] == 401

def test_consumer_reg():
        assert reset_role(email) == True
        r = role_reg(email, '9454234223', name , ["consumer"], None, csr)
        assert r['success']     == True
        assert r['status_code'] == 200

def test_consumer_no_rule_set():
        # token request should fail - not registered 
        body = {"request" : [resource_id] }
        r = consumer.get_token(body)
        assert r['success']     is False
        assert r['status_code'] == 403

def test_consumer_rule_no_caps():
        # No capabilities
        req = { "user_email": email, 
                "user_role":'consumer', 
                "item_id":resource_id, 
                "item_type":"resourcegroup"}

        r = untrusted.provider_access([req])
        assert r['success']     == False
        assert r['status_code'] == 400

def test_invalid_caps():
        # Invalid capabilities
        req = { "user_email": email, 
                "user_role":'consumer', 
                "item_id":resource_id, 
                "item_type":"resourcegroup"}
        req["capabilities"] = ["hello", "world"]

        r = untrusted.provider_access([req])
        assert r['success']     == False
        assert r['status_code'] == 400

def test_get_temporal_cap():
        req = { "user_email": email, 
                "user_role":'consumer', 
                "item_id":resource_id, 
                "item_type":"resourcegroup"}
        req["capabilities"] = ['temporal'];

        r = untrusted.provider_access([req])
        assert r['success']     == True
        assert r['status_code'] == 200

        check = False
        r = consumer.view_consumer_resources()
        assert r['success']     == True
        assert r['status_code'] == 200

        for i in r['response']:
                if resource_id == i['cat_id']:
                        assert 'temporal' in i['capabilities']
                        check = True

        assert check is True

def test_get_same_cap():
        # same capabilities
        req = { "user_email": email, 
                "user_role":'consumer', 
                "item_id":resource_id, 
                "item_type":"resourcegroup"}
        req["capabilities"] = ['temporal'];

        r = untrusted.provider_access([req])
        assert r['success']     == False
        assert r['status_code'] == 403

        # token request will not pass without API
        body = { "id"    : resource_id + "/someitem"}
        r       = consumer.get_token(body)
        assert r['success']     is False

def test_get_same_cap_in_set():
        # temporal rule already exists
        req = { "user_email": email, 
                "user_role":'consumer', 
                "item_id":resource_id, 
                "item_type":"resourcegroup"}
        req["capabilities"] = ['subscription', 'temporal'];

        r = untrusted.provider_access([req])
        assert r['success']     == False
        assert r['status_code'] == 403

def test_get_subscription_cap():
        req = { "user_email": email, 
                "user_role":'consumer', 
                "item_id":resource_id, 
                "item_type":"resourcegroup"}
        req["capabilities"] = ['subscription'];

        r = untrusted.provider_access([req])
        assert r['success']     == True
        assert r['status_code'] == 200

        body = {"request" : [resource_id + "/someitem"]}
        r = consumer.get_token(body)
        assert r['success']     is True

def test_get_complex_cap():
        req = { "user_email": email, 
                "user_role":'consumer', 
                "item_id":resource_id, 
                "item_type":"resourcegroup"}
        req["capabilities"] = ['complex']

        r = untrusted.provider_access([req])
        assert r['success']     == True
        assert r['status_code'] == 200

def test_get_all_caps():
        # try all 3 caps
        req = { "user_email": email, 
                "user_role":'consumer', 
                "item_id":resource_id, 
                "item_type":"resourcegroup"}
        req["item_id"] = provider_id + '/rs.iudx.org.in/' + resource_group
        req["capabilities"] = ['complex','subscription', 'temporal']

        r = untrusted.provider_access([req])
        assert r['success']     == True
        assert r['status_code'] == 200

def test_set_existing_rule():
        req = { "user_email": email, 
                "user_role":'consumer', 
                "item_id":resource_id, 
                "item_type":"resourcegroup"}
        req["item_id"] = provider_id + '/rs.iudx.org.in/' + resource_group
        req["capabilities"] = ['complex','subscription', 'temporal']

        r = untrusted.provider_access([req])
        assert r['success']     == False
        assert r['status_code'] == 403

def test_set_rule_for_invalid_user():
        req = { "user_email": email, 
                "user_role":'consumer', 
                "item_id":resource_id, 
                "item_type":"resourcegroup"}
        req["user_role"] = "onboarder"

        r = untrusted.provider_access([req])
        assert r['success']     == False
        assert r['status_code'] == 403

def test_file_server_caps():
        body = {"request" : [fileresource_id + "/someitem"]}
        r = consumer.get_token(body)
        assert r['success']     is False
        assert r['status_code'] == 403

        # Invalid capabilities for file server
        req = {"user_email": email, "user_role":'consumer', "item_id":fileresource_id, "item_type":"resourcegroup"}
        req["capabilities"] = ["temporal", "complex"]
        r = untrusted.provider_access([req])
        assert r['success']     == False
        assert r['status_code'] == 400

        # Valid capabilities
        req["capabilities"] = ["download"]
        r = untrusted.provider_access([req])
        assert r['success']     == True
        assert r['status_code'] == 200

        # token successful
        r = consumer.get_token(body)
        assert r['success']     is True
        assert r['status_code'] == 200

##### onboarder #####

def test_get_onboarder_token_fail():
        body = {"request": [provider_id + "/catalogue.iudx.io/catalogue/crud"] }

        # onboarder token request should fail
        r = consumer.get_token(body)
        assert r['success']     is False
        assert r['status_code'] == 403

def test_reg_onboarder():
        r = role_reg(email, '9454234223', name , ["onboarder"], org_id)
        assert r['success']     == True
        assert r['status_code'] == 200

def test_set_onboarder_rule():
        req = { "user_email": email, 
                "user_role":'onboarder'}

        r = untrusted.provider_access([req])
        assert r['success']     == True
        assert r['status_code'] == 200

def test_get_onboarder_token():
        body = {"request": [provider_id + "/catalogue.iudx.io/catalogue/crud"] }

        r = consumer.get_token(body)
        assert r['success']     is True
        assert None != r['response']['token']

def test_set_onboarder_rule_again():
        req = { "user_email": email, 
                "user_role":'onboarder'}

        r = untrusted.provider_access([req])
        assert r['success']     == False
        assert r['status_code'] == 403

##### delegate #####

def test_reg_delegate():
        r = role_reg(email, '9454234223', name , ["delegate"], org_id)
        assert r['success']     == True
        assert r['status_code'] == 200

def test_set_delegate_rule():
        req = { "user_email": email, 
                "user_role":'delegate'}

        r = untrusted.provider_access([req])
        assert r['success']     == True
        assert r['status_code'] == 200

def test_set_delegate_rule_again():
        req = { "user_email": email, 
                "user_role":'delegate'}

        r = untrusted.provider_access([req])
        assert r['success']     == False
        assert r['status_code'] == 403

##### data ingester #####

diresource_group = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
diresource_id = provider_id + "/rs.iudx.io/" + diresource_group

def test_get_ingester_token_fail():
        body = {"request" : [diresource_id + "/someitem"] }
        r = consumer.get_token(body)
        assert r['success']     is False
        assert r['status_code'] == 403

def test_reg_ingester():
        r = role_reg(email, '9454234223', name , ["data ingester"], org_id)
        assert r['success']     == True
        assert r['status_code'] == 200

def test_invalid_resource_type():
        # invalid resource type
        req = { "user_email": email, 
                "user_role":'data ingester', 
                "item_id":diresource_id, 
                "item_type":"catalogue"}

        r = untrusted.provider_access([req])
        assert r['success']     == False
        assert r['status_code'] == 400

def test_set_ingester_rule():
        req = { "user_email": email, 
                "user_role":'data ingester', 
                "item_id":diresource_id, 
                "item_type":"resourcegroup"}

        r = untrusted.provider_access([req])
        assert r['success']     == True
        assert r['status_code'] == 200

def test_get_ingester_token():
        body = {"request" : [diresource_id] }
        body["api"] = "/iudx/v1/adapter"
        r = consumer.get_token(body)
        assert r['success']     is True

def test_get_token_for_item():
        # request for other items in resource group
        body = {"request" : [diresource_id + "/someitem"] }
        r = consumer.get_token(body)
        assert r['success']     is True

def test_set_access_invalid_rid():
        # invalid resource ID
        req = { "user_email": email, 
                "user_role":'data ingester', 
                "item_id":diresource_id, 
                "item_type":"resourcegroup"}
        req["item_id"]      = '/aaaaa/sssss/sada/'

        r = untrusted.provider_access([req])
        assert r['success']     == False
        assert r['status_code'] == 400

        req["item_id"]      = '/aaaaa/sssss'
        r = untrusted.provider_access([req])
        assert r['success']     == False
        assert r['status_code'] == 400

def test_file_server_set_access():

        body = {"request" : [file_diresource_id + "/someitem"] }

        # token request should fail
        r = consumer.get_token(body)
        assert r['success']     is False
        assert r['status_code'] == 403

        req = { "user_email": email, 
                "user_role":'data ingester', 
                "item_id":file_diresource_id, 
                "item_type":"resourcegroup"}
        r = untrusted.provider_access([req])
        assert r['success']     is True
        assert r['status_code'] == 200

        r = consumer.get_token(body)
        assert r['success']     is True
        assert r['status_code'] == 200

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
                if r['email'] == email and r['role'] == 'consumer' and fileresource_id == r['item']['cat_id']:
                        assert set(r['capabilities']).issubset(set(['download']))
                        assert len(r['capabilities']) <= 1 and len(r['capabilities']) >= 1
                if r['email'] == email and r['role'] == 'onboarder':
                        assert r['item_type'] == 'catalogue'
                        onboarder_id = r['id']
                if r['email'] == email and r['role'] == 'data ingester' and diresource_id == r['item']['cat_id']:
                        assert r['item_type'] == 'resourcegroup'
                        ingester_id = r['id']
                if r['email'] == email and r['role'] == 'data ingester' and file_diresource_id == r['item']['cat_id']:
                        assert r['item_type'] == 'resourcegroup'

### deleting rules ###

def test_delete_onboarder_rule():
        global onboarder_id

        body = {"request" : [provider_id + "/catalogue.iudx.io/catalogue/crud"] }

        r = consumer.get_token(body)
        assert r['success']     is True
        assert None != r['response']['token']

        body = {"id" : onboarder_id}
        r = untrusted.delete_rule([body])
        assert r['success']     == True
        assert r['status_code'] == 200

        body = {"id" : onboarder_id}
        r = untrusted.delete_rule([body])
        assert r['success']     == False
        assert r['status_code'] == 403

        # onboarder token request should fail
        body = {"request" : [provider_id + "/catalogue.iudx.io/catalogue/crud"] }
        r = consumer.get_token(body)
        assert r['success']     is False
        assert r['status_code'] == 403

def test_delete_ingester_temporal():
        global ingester_id, consumer_id
        
        body = {"request" : [diresource_id + "/someitem/someotheritem"]}
        r = consumer.get_token(body)
        assert r['success']     is True

        body = {"request" : [resource_id + "/something"] }
        r = consumer.get_token(body)
        assert r['success']     is True
        
        # temporal must be there
        check = False
        r = consumer.view_consumer_resources()
        assert r['success']     == True
        assert r['status_code'] == 200

        for i in r['response']:
                if resource_id == i['cat_id']:
                        assert 'temporal' in i['capabilities']
                        check = True

        assert check is True

        # invalid body, some items not objects
        body = [ingester_id, ["complex"], {"id": consumer_id, "capabilities": ["temporal"]}]
        r = untrusted.delete_rule(body)
        assert r['success']     == False
        assert r['status_code'] == 400

        body = [{"id": ingester_id}, {"id": consumer_id, "capabilities": ["temporal"]}]
        r = untrusted.delete_rule(body)
        assert r['success']     == True
        assert r['status_code'] == 200

        body = {"request" : [diresource_id + "/someitem/someotheritem"]}
        r = consumer.get_token(body)
        assert r['success']     is False
        assert r['status_code'] == 403

        check = False
        r = consumer.view_consumer_resources()
        assert r['success']     == True
        assert r['status_code'] == 200

        for i in r['response']:
                if resource_id == i['cat_id']:
                        assert 'temporal' not in i['capabilities']
                        check = True

        assert check is True
        
        # will still be able to get token, as other caps are there
        body = {"request" : [resource_id + "/something"] }
        r = consumer.get_token(body)
        assert r['success']     is True
        assert r['status_code'] == 200

        body = [{"id": ingester_id}, {"id": consumer_id, "capabilities": ["temporal"]}]
        r = untrusted.delete_rule(body)
        assert r['success']     == False
        assert r['status_code'] == 403

def test_delete_consumer_rule():
        global consumer_id

        body = {"request" : [resource_id + "/something"] }
        r = consumer.get_token(body)
        assert r['success']     is True

        check = False
        r = consumer.view_consumer_resources()
        assert r['success']     == True
        assert r['status_code'] == 200

        for i in r['response']:
                if resource_id == i['cat_id']:
                        assert len(i['capabilities']) > 1
                        check = True

        assert check is True
        
        # temporal already deleted
        body = [{"id": consumer_id, "capabilities": ["temporal", "subscription", "complex"]}]
        r = untrusted.delete_rule(body)
        assert r['success']     == False
        assert r['status_code'] == 403

        body = {"request" : [resource_id + "/something"] }
        r = consumer.get_token(body)
        assert r['success']     is True

        body = [{"id": consumer_id}]
        r = untrusted.delete_rule(body)
        assert r['success']     == True
        assert r['status_code'] == 200
        
        # delete again
        body = [{"id": consumer_id}]
        r = untrusted.delete_rule(body)
        assert r['success']     == False
        assert r['status_code'] == 403

        body = {"request" : [resource_id + "/something"] }
        r = consumer.get_token(body)
        assert r['success']     is False
        assert r['status_code'] == 403

### setting multiple rules ###
def test_multiple_duplicate():
        req1 = {"user_email": remail, 
                "user_role":'consumer', 
                "item_id":resource_id, 
                "item_type":"resourcegroup", 
                "capabilities":["temporal"]}
        req2 = {"user_email": remail, 
                "user_role":'onboarder'}

        r = untrusted.provider_access([req1, req1, req2])
        assert r['success']     == False
        assert r['status_code'] == 400

def test_multiple_onb_temporal():
        req1 = {"user_email": remail, 
                "user_role":'consumer', 
                "item_id":resource_id, 
                "item_type":"resourcegroup", 
                "capabilities":["temporal"]}
        req2 = {"user_email": remail, 
                "user_role":'onboarder'}

        r = untrusted.provider_access([req2, req1, {"user_email": remail, "user_role":'delegate'}])
        assert r['success']     == True
        assert r['status_code'] == 200

def test_multiple_same_rule():
        req1 = {"user_email": remail, 
                "user_role":'consumer', 
                "item_id":resource_id, 
                "item_type":"resourcegroup", 
                "capabilities":["temporal"]}

        r = untrusted.provider_access([req1, req1, req1])
        assert r['success']     == False
        assert r['status_code'] == 403

def test_multiple_duplicate_subs():
        req1 = {"user_email": remail, 
                "user_role":'consumer', 
                "item_id":resource_id, 
                "item_type":"resourcegroup", 
                "capabilities":["subscription"]}
        r = untrusted.provider_access([req1, req1])
        assert r['success']     == False
        assert r['status_code'] == 400

        req2 = req1.copy()
        req2['capabilities'] = ['temporal']
        r = untrusted.provider_access([req1, req2])
        assert r['success']     == False
        assert r['status_code'] == 403

def test_multiple_complex_sub_dup():
        req1 = {"user_email": remail, 
                "user_role":'consumer', 
                "item_id":resource_id, 
                "item_type":"resourcegroup", 
                "capabilities":["subscription"]}

        req2 = {"user_email": remail, 
                "user_role":'consumer', 
                "item_id":resource_id, 
                "item_type":"resourcegroup", 
                "capabilities":["complex"]}

        r = untrusted.provider_access([req1, req2, req1])
        assert r['success']     == False
        assert r['status_code'] == 400

def test_multiple_duplicate_in_caps_array():
        req1 = {"user_email": remail, 
                "user_role":'consumer', 
                "item_id":resource_id, 
                "item_type":"resourcegroup", 
                "capabilities":["complex", "subscription"]}

        req2 = {"user_email": remail, 
                "user_role":'consumer', 
                "item_id":resource_id, 
                "item_type":"resourcegroup", 
                "capabilities":["subscription"]}

        r = untrusted.provider_access([req1, req2])
        assert r['success']     == False
        assert r['status_code'] == 400

def test_multiple_existing_in_caps_array():
        req1 = {"user_email": remail, 
                "user_role":'consumer', 
                "item_id":resource_id, 
                "item_type":"resourcegroup", 
                "capabilities":["subscription"]}

        req2 = {"user_email": remail, 
                "user_role":'consumer', 
                "item_id":resource_id, 
                "item_type":"resourcegroup", 
                "capabilities":["complex", "temporal"]}
 
        r = untrusted.provider_access([req1, req2])
        assert r['success']     == False
        assert r['status_code'] == 403

def test_multiple_complex_sub_success():
        req1 = {"user_email": remail, 
                "user_role":'consumer', 
                "item_id":resource_id, 
                "item_type":"resourcegroup", 
                "capabilities":["complex"]}

        req2 = {"user_email": remail, 
                "user_role":'consumer', 
                "item_id":resource_id, 
                "item_type":"resourcegroup", 
                "capabilities":["subscription"]}

        r = untrusted.provider_access([req1, req2])
        assert r['success']     == True
        assert r['status_code'] == 200

def test_multiple_ingester_consumer():
        req1 = {"user_email": remail, 
                "user_role":'data ingester', 
                "item_id":resource_id, 
                "item_type":"resourcegroup"}
        req2 = {"user_email": remail, 
                "user_role":'consumer', 
                "item_id":resource_id, 
                "item_type":"resourcegroup", 
                "capabilities":["complex"]}
        r = untrusted.provider_access([req1, req2])
        assert r['success']     == False
        assert r['status_code'] == 403

        r = untrusted.provider_access([req1, req1])
        assert r['success']     == False
        assert r['status_code'] == 400

        newresource_group = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
        newresource_id = provider_id + "/rs.iudx.io/" + newresource_group
        req2["item_id"] = newresource_id

        r = untrusted.provider_access([req2, req1])
        assert r['success']     == True
        assert r['status_code'] == 200

def test_multiple_get_all_rules():
        # get all rules for new email
        check_con = False
        check_onb = False
        check_dti = False
        check_del = False

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
                if r['email'] == remail and r['role'] == 'delegate':
                        assert r['item_type'] == 'provider-caps'
                        check_del = True
                if r['email'] == remail and r['role'] == 'data ingester':
                        assert r['item_type'] == 'resourcegroup'
                        check_dti = True

        assert check_con == True
        assert check_onb == True
        assert check_dti == True
        assert check_del == True
