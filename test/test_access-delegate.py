from init import untrusted
from init import alt_provider
from init import consumer
from access import *
from consent import role_reg
import random
import string
import pytest

# use consumer certificate to register
email   = "barun@iisc.ac.in"
org_id = add_organization("iisc.ac.in")

# use alt_provider certificate as delegate
delegate_email = "abc.123@iisc.ac.in"

# provider ID of abc.xyz@rbccps.org
provider_id = 'rbccps.org/f3dad987e514af08a4ac46cf4a41bd1df645c8cc'

resource_group = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
resource_id = provider_id + '/rs.example.com/' + resource_group

pr_resource_group = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
pr_resource_id = provider_id + '/rs.example.in/' + resource_group

diresource_group = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
diresource_id = provider_id + "/rs.example.com/" + diresource_group

consumer_id = -1
onboarder_id = -1
ingester_id = -1
delegate_id = -1
provider_set_consumer_id = -1

@pytest.fixture(scope="session", autouse=True)
def init():
        init_provider()
        assert reset_role(email) == True
        assert reset_role(delegate_email) == True

        # delete all old policies using acl/set API
        policy = "x can access x"
        r = untrusted.set_policy(policy)
        assert r['success'] is True

        # register abc.123 as delegate and set delegate rule
        r = role_reg(delegate_email, '9454234223', name , ["delegate"], org_id, csr)
        assert r['success']     == True
        assert r['status_code'] == 200

        # register barun user as all roles
        r = role_reg(email, '9454234223', name , ["consumer","onboarder","data ingester", "delegate"], org_id, csr)
        assert r['success']     == True
        assert r['status_code'] == 200

def test_set_rule_unassigned_delegate():

        # token request should fail
        body = {"id" : resource_id + "/someitem", "apis" : ["/ngsi-ld/v1/entities"] }
        r = consumer.get_token(body)
        assert r['success']     is False

        # set temporal consumer rule as delegate
        req = {"user_email": email, "user_role":'consumer', "item_id":resource_id, "item_type":"resourcegroup"}
        req["capabilities"] = ['temporal']

        # should fail because unapproved delegate
        r = alt_provider.provider_access([req], 'abc.xyz@rbccps.org')
        assert r['success']     == False
        assert r['status_code'] == 401

        # check if unreg'd delegate can use delegate API
        r = alt_provider.get_delegate_providers()
        assert r['success']     == False
        assert r['status_code'] == 404

def test_provider_use_delegate_api():

        # check if provider can use delegate API
        r = untrusted.get_delegate_providers()
        assert r['success']     == False
        assert r['status_code'] == 401

def test_assign_delegate_register_consumer():

        # check if provider given access to delegate - no
        r = alt_provider.get_delegate_providers()
        assert r['success']     == False
        assert r['status_code'] == 404

        req = {"user_email": delegate_email, "user_role":'delegate'}
        r = untrusted.provider_access([req])
        assert r['success']     == True
        assert r['status_code'] == 200

        # check if provider given access to delegate - yes
        r = alt_provider.get_delegate_providers()
        assert r['success']     == True
        assert r['status_code'] == 200
        assert r['response'][0]['email'] == 'abc.xyz@rbccps.org'

def test_delegate_invalid_provider_email():
        req = {"user_email": email, "user_role":'consumer', "item_id":resource_id, "item_type":"resourcegroup"}
        req["capabilities"] = ['temporal']

        # fail because provider_email missing
        r = alt_provider.provider_access([req])
        assert r['success']     == False
        assert r['status_code'] == 400

        # invalid provider_email
        r = alt_provider.provider_access([req], 'abc.xyz@rbccps$$.')
        assert r['success']     == False
        assert r['status_code'] == 400

        # non-existent provider
        r = alt_provider.provider_access([req], 'provider@rbccps.org')
        assert r['success']     == False
        assert r['status_code'] == 401

def test_delegate_set_consumer_rule():
        req = {"user_email": email, "user_role":'consumer', "item_id":resource_id, "item_type":"resourcegroup"}
        req["capabilities"] = ['temporal']
        r = alt_provider.provider_access([req], 'abc.xyz@rbccps.org')
        assert r['success']     == True
        assert r['status_code'] == 200

        body = {"id" : resource_id + "/someitem", "apis" : ["/ngsi-ld/v1/entities/" + resource_id] }
        r = consumer.get_token(body)
        assert r['success']     is True

def test_provider_update_rule_set_by_delegate():
        # provider can update consumer rule set by delegate

        req = {"user_email": email, "user_role":'consumer', "item_id":resource_id, "item_type":"resourcegroup"}
        req["capabilities"] = ['complex'];
        r = untrusted.provider_access([req], 'abc.xyz@rbccps.org')
        assert r['success']     == True
        assert r['status_code'] == 200

        body = {"id" : resource_id + "/someitem", "apis" : ["/ngsi-ld/v1/entities"] }
        r = consumer.get_token(body)
        assert r['success']     is True

def test_delegate_update_provider_rule():
        # delegate can update rule set by provider

        req = {"user_email": email, "user_role":'consumer', "item_id":pr_resource_id, "item_type":"resourcegroup"}
        req["capabilities"] = ['complex'];
        r = untrusted.provider_access([req])
        assert r['success']     == True
        assert r['status_code'] == 200

        req = {"user_email": email, "user_role":'consumer', "item_id":pr_resource_id, "item_type":"resourcegroup"}
        req["capabilities"] = ['temporal'];
        r = alt_provider.provider_access([req], 'abc.xyz@rbccps.org')
        assert r['success']     == True
        assert r['status_code'] == 200

        body = {"id" : pr_resource_id + "/someitem", "apis" : ["/ngsi-ld/v1/entities"] }
        r = consumer.get_token(body)
        assert r['success']     is True

        body = {"id" : pr_resource_id + "/someitem", "apis" : ["/ngsi-ld/v1/temporal/entities"] }
        r = consumer.get_token(body)
        assert r['success']     is True

def test_delegate_set_onboarder_rule():
        # delegate can set onboarder rule

        body = { "id"    : provider_id + "/catalogue.iudx.io/catalogue/crud" }

        # onboarder token request should fail
        r = consumer.get_token(body)
        assert r['success']     is False

        req = {"user_email": email, "user_role":'onboarder'}
        r = alt_provider.provider_access([req], 'abc.xyz@rbccps.org')
        assert r['success']     == True
        assert r['status_code'] == 200

        r = consumer.get_token(body)
        assert r['success']     is True
        assert None != r['response']['token']

def test_delegate_set_ingester_rule():
        # delegate can set ingester rule
        body        = {"id" : diresource_id + "/someitem", "api" : "/iudx/v1/adapter" }

        # data ingester token request should fail
        r = consumer.get_token(body)
        assert r['success']     is False

        req = {"user_email": email, "user_role":'data ingester', "item_id":diresource_id, "item_type":"resourcegroup"}
        r = alt_provider.provider_access([req], 'abc.xyz@rbccps.org')
        assert r['success']     == True
        assert r['status_code'] == 200

        # without adapter API
        body        = {"id" : diresource_id + "/someitem", "api" : "/iudx/v1/adapter" }
        r = consumer.get_token(body)
        assert r['success']     is True

def test_delegate_set_delegate_rule():
        # delegate cannot set delegate rule

        req = {"user_email": email, "user_role":'delegate'}
        r = alt_provider.provider_access([req], 'abc.xyz@rbccps.org')
        assert r['success']     == False
        assert r['status_code'] == 403

def test_delegate_get_all_rules():
        # test getting all access rules
        global consumer_id, onboarder_id, ingester_id, delegate_id, provider_set_consumer_id

        r = alt_provider.get_provider_access('abc.xyz@rbccps.org')
        assert r['success']     == True
        assert r['status_code'] == 200
        rules = r['response']

        check_con = False
        check_onb = False
        check_dti = False
        check_del = False

        for r in rules:
                if r['email'] == email and r['role'] == 'consumer' and resource_id == r['item']['cat_id']:
                        consumer_id = r['id']
                        assert set(r['capabilities']).issubset(set(['temporal', 'subscription', 'complex']))
                        assert len(r['capabilities']) <= 3 and len(r['capabilities']) >= 1
                        check_con = True
                if r['email'] == email and r['role'] == 'consumer' and pr_resource_id == r['item']['cat_id']:
                        provider_set_consumer_id = r['id']
                if r['email'] == email and r['role'] == 'onboarder':
                        onboarder_id = r['id']
                        assert r['item_type'] == 'catalogue'
                        check_onb = True
                if r['email'] == email and r['role'] == 'data ingester' and diresource_id == r['item']['cat_id']:
                        ingester_id = r['id']
                        assert r['item_type'] == 'resourcegroup'
                        check_dti = True
                if r['email'] == delegate_email and r['role'] == 'delegate':
                        delegate_id = r['id']
                        assert r['item_type'] == 'provider-caps'
                        check_del = True

        assert check_con == True
        assert check_onb == True
        assert check_dti == True
        assert check_del == True

# deleting rules

def test_delegate_delete_rules_set_by_self():
        # delete rules set by delegate
        r = alt_provider.delete_rule([{"id" : onboarder_id}, {"id": consumer_id}], 'abc.xyz@rbccps.org')
        assert r['success']     == True
        assert r['status_code'] == 200

def test_provider_delete_rule_set_by_delegate():
        # provider can delete rules set by delegate
        r = untrusted.delete_rule([{"id": ingester_id}])
        assert r['success']     == True
        assert r['status_code'] == 200

        r = alt_provider.delete_rule([{"id": ingester_id}], 'abc.xyz@rbccps.org')
        assert r['success']     == False
        assert r['status_code'] == 403

def test_delegate_delete_provider_rule():
        # delegate can delete rule set by provider
        body = {"id" : provider_set_consumer_id}
        r = alt_provider.delete_rule([body], 'abc.xyz@rbccps.org')
        assert r['success']     == True
        assert r['status_code'] == 200

def test_delegate_delete_delegate_rule():
        # cannot delete delegate rule
        body = {"id" : delegate_id}
        r = alt_provider.delete_rule([body], 'abc.xyz@rbccps.org')
        assert r['success']     == False
        assert r['status_code'] == 403

def test_multiple_delegates():
        # tests with 2 delegates

        # make consumer a delegate
        req = {"user_email": email, "user_role":'delegate'}
        r = untrusted.provider_access([req])
        assert r['success']     == True
        assert r['status_code'] == 200

        resource_group = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
        resource_id = provider_id + '/rs.example.com/' + resource_group

        req = {"user_email": email, "user_role":'consumer', "item_id":resource_id, "item_type":"resourcegroup"}
        req["capabilities"] = ['complex'];
        r = consumer.provider_access([req], 'abc.xyz@rbccps.org')
        assert r['success']     == True
        assert r['status_code'] == 200

        # cannot update rule set by other provider
        req["capabilities"] = ['subscription'];
        r = alt_provider.provider_access([req], 'abc.xyz@rbccps.org')
        assert r['success']     == True
        assert r['status_code'] == 200
        
        r = consumer.get_provider_access('abc.xyz@rbccps.org')
        assert r['success']     == True
        assert r['status_code'] == 200
        rules = r['response']

        for r in rules:
                if r['email'] == email and r['role'] == 'consumer' and resource_id == r['item']['cat_id']:
                        consumer_id = r['id']

        # delegate can delete other delegate's rule
        body = {"id" : consumer_id}
        r = alt_provider.delete_rule([body], 'abc.xyz@rbccps.org')
        assert r['success']     == True
        assert r['status_code'] == 200

        # already deleted
        body = {"id" : consumer_id}
        r = consumer.delete_rule([body], 'abc.xyz@rbccps.org')
        assert r['success']     == False
        assert r['status_code'] == 403

        # delegate cannot delete delegate rule
        r = consumer.delete_rule([{"id": delegate_id}], 'abc.xyz@rbccps.org')
        assert r['success']     == False
        assert r['status_code'] == 403

def test_deleted_delegate():
        # provider deletes delegate

        global consumer_id

        r = untrusted.delete_rule([{"id": delegate_id}])
        assert r['success']     == True
        assert r['status_code'] == 200

        # deleted delegate cannot do anything
        req = {"user_email": email, "user_role":'consumer', "item_id":resource_id, "item_type":"resourcegroup"}
        req["capabilities"] = ['complex'];
        r = alt_provider.provider_access([req], 'abc.xyz@rbccps.org')
        assert r['success']     == False
        assert r['status_code'] == 401

        r = alt_provider.get_provider_access('abc.xyz@rbccps.org')
        assert r['success']     == False
        assert r['status_code'] == 401

        body = {"id" : consumer_id}
        r = alt_provider.delete_rule([body], 'abc.xyz@rbccps.org')
        assert r['success']     == False
        assert r['status_code'] == 401

        # check if provider given access to delegate - no
        r = alt_provider.get_delegate_providers()
        assert r['success']     == False
        assert r['status_code'] == 404
