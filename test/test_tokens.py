# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

import os
import pytest

from init import consumer
from init import provider
from init import alt_provider

from init import expect_failure

# for registration and resetting roles
from access import *
from consent import role_reg

# for setting session ID 
from session import *

from expire_token import expire_token

import hashlib

email = "barun@iisc.ac.in"

def rand_rsg():
        return ''.join(random.choice(string.ascii_lowercase) for _ in range(10))

def set_policy():
        resource_id = "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs.iudx.io/" + rand_rsg()
        access_req = {"user_email": email, 
                    "user_role":'consumer', 
                    "item_id":resource_id, 
                    "item_type":"resourcegroup",
                    "capabilities":["complex","subscription","temporal"]
                    }
        r = provider.provider_access([access_req])
        assert r['success']     == True
        assert r['status_code'] == 200

        return resource_id

@pytest.fixture(scope="session", autouse=True)
def init():
        init_provider("arun.babu@rbccps.org") # provider
        init_provider("abc.123@iisc.ac.in") # alt_provider

        ######### session ID setup for provider, alt_provider ###########
        r = provider.get_session_id(ALL_SECURE_ENDPOINTS_BODY)
        assert r['success'] is True

        provider.set_user_session_id(fetch_sessionId("arun.babu@rbccps.org"))

        r = alt_provider.get_session_id(ALL_SECURE_ENDPOINTS_BODY)
        assert r['success'] is True

        alt_provider.set_user_session_id(fetch_sessionId("abc.123@iisc.ac.in"))

        # register the consumer
        assert reset_role(email) == True
        org_id = add_organization("iisc.ac.in")

        r = role_reg(email, '9454234223', name , ["consumer", "data ingester"], org_id, csr)
        assert r['success']     == True
        assert r['status_code'] == 200

def test_empty_body():
        body = {}
        r = consumer.get_token(body)
        assert r['success'] is False
        assert r['status_code'] == 400

def test_invalid_request():
        body = {'request':'rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs.iudx.io/rg1'}
        r = consumer.get_token(body)
        assert r['success'] is False
        assert r['status_code'] == 400

        body = {'request':['rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs.iudx.io/rg1',
                            ['rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs.iudx.io/rg7']
            ]}
        r = consumer.get_token(body)
        assert r['success'] is False
        assert r['status_code'] == 400

        body = {'request':['rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs.iudx.io/rg1/item',
                            'rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs.iudx.io/rg7/*'
            ]}
        r = consumer.get_token(body)
        assert r['success'] is False
        assert r['status_code'] == 400

def test_invalid_resource():
        body = {}
        body['request'] = ["rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs.iudx.io/(hello)"]
        r = consumer.get_token(body)
        assert r['success'] is False
        assert r['status_code'] == 400

def test_duplicate_resources():
        body = {}
        body['request'] = ["rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs.iudx.io/rg1",
                            "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs.iudx.io/rg1"]
        r = consumer.get_token(body)
        assert r['success'] is False
        assert r['status_code'] == 400

def test_different_resource_servers():
        body = {}
        body['request'] = ["rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs.iudx.io/rg1",
                            "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs.iudx.org.in/rg2"]
        r = consumer.get_token(body)
        assert r['success'] is False
        assert r['status_code'] == 400

def test_different_invalid_resource_servers():
        body = {}
        body['request'] = ["rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/someserver.iudx.io/rg1"]
        r = consumer.get_token(body)
        assert r['success'] is False
        assert r['status_code'] == 403

def test_unauthorized():
        body = {}
        body['request'] = ["rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs.iudx.io/" + rand_rsg()]
        r = consumer.get_token(body)
        assert r['success'] is False
        assert r['status_code'] == 403

def test_get_valid_token():
        resource_id = set_policy()
        body = {}
        body['request'] = [resource_id]
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200
        
        token = r['response']['token']
        s = token.split("/")
        assert len(s)   == 4
        assert s[0]     == 'auth.iudx.org.in'
        uuid = s[3]

        check = False
        r = consumer.view_tokens()

        for tokens in r['response']:
                if tokens['uuid'] == uuid:
                        check = True

        assert check is True

def test_get_valid_token_multiple_resources():
        # test resource groups and resource items
        resource_id_1 = set_policy()
        resource_id_2 = set_policy() + '/item-1'
        resource_id_3 = set_policy()
        resource_id_4 = set_policy() + '/item-2'
        resource_id_5 = set_policy() + '/item-5'

        body = {}
        body['request'] = [resource_id_1, resource_id_2, resource_id_3, 
                resource_id_4,resource_id_5]
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200
        
        token = r['response']['token']
        s = token.split("/")
        uuid = s[3]

        resources = []
        r = consumer.view_tokens()
        
        for tokens in r['response']:
                if tokens['uuid'] == uuid:
                        resources = tokens['request']
                    
        for resource in resources:
                assert resource['cat_id'] in body['request']

def test_deleted_policy():
        resource_id = set_policy()

        body = {}
        body['request'] = [resource_id]
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200

        access_id = -1

        # find access ID and delete it
        r = provider.get_provider_access()
        assert r['success']     == True
        assert r['status_code'] == 200
        rules = r['response']
        for r in rules:
                if resource_id == r['item']['cat_id']:
                        access_id = r['id']
                        break

        assert  access_id != -1
        r = provider.delete_rule([{'id':access_id}])
        assert r['success']     == True
        assert r['status_code'] == 200

        body['request'] = [resource_id]
        r = consumer.get_token(body)
        assert r['success'] is False
        assert r['status_code'] == 403

def test_expired_policy():
        resource_id = set_policy()

        body = {}
        body['request'] = [resource_id]
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200

        access_id = -1

        # find access ID and delete it
        r = provider.get_provider_access()
        assert r['success']     == True
        assert r['status_code'] == 200
        rules = r['response']
        for r in rules:
                if resource_id == r['item']['cat_id']:
                        access_id = r['id']
                        break

        assert  access_id != -1
        assert expire_rule(access_id) is True

        body['request'] = [resource_id]
        r = consumer.get_token(body)
        assert r['success'] is False
        assert r['status_code'] == 403

def test_existing_token_and_request():
        body = {'existing_token':'something', 'request':['something']}
        r = consumer.get_token(body)
        assert r['success'] is False
        assert r['status_code'] == 400
        
def test_existing_token_invalid_uuid():
        body = {'existing_token':'1234'}
        r = consumer.get_token(body)
        assert r['success'] is False
        assert r['status_code'] == 400

def test_existing_token_not_expired():
        resource_id = set_policy()
        body = {}
        body['request'] = [resource_id]
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200

        token = r['response']['token']
        s = token.split("/")
        uuid = s[3]

        body = {'existing_token':uuid}
        r = consumer.get_token(body)
        assert r['success'] is False
        assert r['status_code'] == 403

def test_existing_token_success():
        resource_id = set_policy()
        body = {}
        body['request'] = [resource_id]
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200

        token = r['response']['token']
        s = token.split("/")
        uuid = s[3]

        assert expire_token(uuid) is True

        body = {'existing_token':uuid}
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200

def test_existing_token_deleted_resource():
        resource_id = set_policy()
        body = {}
        body['request'] = [resource_id]
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200

        token = r['response']['token']
        s = token.split("/")
        uuid = s[3]

        access_id = -1

        # find access ID and delete it
        r = provider.get_provider_access()
        assert r['success']     == True
        assert r['status_code'] == 200
        rules = r['response']
        for r in rules:
                if resource_id == r['item']['cat_id']:
                        access_id = r['id']
                        break

        # expire the token to allow existing_token flow
        assert expire_token(uuid) is True

        assert  access_id != -1
        r = provider.delete_rule([{'id':access_id}])
        assert r['success']     == True
        assert r['status_code'] == 200

        body = {'existing_token':uuid}
        r = consumer.get_token(body)
        assert r['success'] is False
        assert r['status_code'] == 403

def test_update_token_empty_body():
        body = {}
        r = consumer.update_token(body)
        assert r['success'] is False
        assert r['status_code'] == 400

def test_update_token_invalid_request():
        body = {'request':[]}
        r = consumer.update_token(body)
        assert r['success'] is False
        assert r['status_code'] == 400

        body = {'request':'token'}
        r = consumer.update_token(body)
        assert r['success'] is False
        assert r['status_code'] == 400

        body = {'request':['token']}
        r = consumer.update_token(body)
        assert r['success'] is False
        assert r['status_code'] == 400

        body = {'request':[{'token':'1234'}]}
        r = consumer.update_token(body)
        assert r['success'] is False
        assert r['status_code'] == 400

        body = {'request':[{'token':'ba2efb08-896a-4f0a-abe9-486fe40651dc ', 'resources':['hello']}]}
        r = consumer.update_token(body)
        assert r['success'] is False
        assert r['status_code'] == 400

        body = {'request':[{'token':'ba2efb08-896a-4f0a-abe9-486fe40651dc ', 'resources':[]}]}
        r = consumer.update_token(body)
        assert r['success'] is False
        assert r['status_code'] == 400
        
        body = {'request':[{'token':'ba2efb08-896a-4f0a-abe9-486fe40651dc ', 'resources':'hello'}]}
        r = consumer.update_token(body)
        assert r['success'] is False
        assert r['status_code'] == 400

def test_update_token_unauthorized_resource():
        resource_id = set_policy()

        body = {}
        body['request'] = [resource_id]
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200

        token = r['response']['token']
        s = token.split("/")
        uuid = s[3]
        
        unauth_resource_id = "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs.iudx.io/" + rand_rsg()

        body['request'] = [{'token':uuid,'resources':[unauth_resource_id, resource_id]}]

        r = consumer.update_token(body)
        assert r['success'] is False
        assert r['status_code'] == 403

def test_update_token_different_resource_server():
        resource_id = set_policy()

        body = {}
        body['request'] = [resource_id]
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200

        token = r['response']['token']
        s = token.split("/")
        uuid = s[3]
        
        bad_resource_id = "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs.iudx.org.in/" + rand_rsg()

        body['request'] = [{'token':uuid,'resources':[bad_resource_id, resource_id]}]

        r = consumer.update_token(body)
        assert r['success'] is False
        assert r['status_code'] == 400

def test_update_token_add_resource():
        resource_id_1 = set_policy()
        resource_id_2 = set_policy()

        body = {}
        body['request'] = [resource_id_1]
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200

        token = r['response']['token']
        s = token.split("/")
        uuid = s[3]

        resources = []

        r = consumer.view_tokens()
        for tokens in r['response']:
                if tokens['uuid'] == uuid:
                    resources = tokens['request']

        for resource in resources:
                assert resource_id_1 == resource['cat_id']
                assert resource['status'] == 'active'

        assert len(resources) == 1

        body['request'] = [{'token':uuid,'resources':[resource_id_1, resource_id_2]}]

        r = consumer.update_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200

        resources = []

        r = consumer.view_tokens()
        for tokens in r['response']:
                if tokens['uuid'] == uuid:
                    resources = tokens['request']
        check = 0
        for i in resources:
                if i['cat_id'] == resource_id_1 and i['status'] == 'active':
                    check = check + 1
                if i['cat_id'] == resource_id_2 and i['status'] == 'active':
                    check = check + 1

        assert check == 2

def test_update_token_delete_and_undelete_resource():
        resource_id_1 = set_policy()
        resource_id_2 = set_policy()

        body = {}
        body['request'] = [resource_id_1, resource_id_2]
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200

        token = r['response']['token']
        s = token.split("/")
        uuid = s[3]

        resources = []

        r = consumer.view_tokens()
        for tokens in r['response']:
                if tokens['uuid'] == uuid:
                    resources = tokens['request']

        assert len(resources) == 2
        for i in resources:
                assert i['status'] == 'active'

        body['request'] = [{'token':uuid,'resources':[resource_id_2]}]

        r = consumer.update_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200
        assert resource_id_1 in r['response'][0]['deleted_resources']
        assert resource_id_2 in r['response'][0]['active_resources']

        resources = []

        r = consumer.view_tokens()
        for tokens in r['response']:
                if tokens['uuid'] == uuid:
                    resources = tokens['request']
        check = 0
        for i in resources:
                if i['cat_id'] == resource_id_1:
                        assert i['status'] == 'deleted'
                        check = check + 1
                if i['cat_id'] == resource_id_2:
                        assert i['status'] == 'active'
                        check = check + 1

        assert check == 2
        
        # undelete the resource/add it again
        body['request'] = [{'token':uuid,'resources':[resource_id_1, resource_id_2]}]

        r = consumer.update_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200
        assert len(r['response'][0]['deleted_resources']) == 0

        resources = []

        r = consumer.view_tokens()
        for tokens in r['response']:
                if tokens['uuid'] == uuid:
                    resources = tokens['request']
        check = 0
        for i in resources:
                assert i['status'] == 'active'

def test_update_token_revoked_resource():
        resource_id_1 = set_policy()

        body = {}
        body['request'] = [resource_id_1]
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200

        token = r['response']['token']
        s = token.split("/")
        uuid = s[3]

        access_id = -1
        # find access ID and delete it
        r = provider.get_provider_access()
        assert r['success']     == True
        assert r['status_code'] == 200
        rules = r['response']
        for r in rules:
                if resource_id_1 == r['item']['cat_id']:
                        access_id = r['id']
                        break

        assert  access_id != -1
        r = provider.delete_rule([{'id':access_id}])
        assert r['success']     == True
        assert r['status_code'] == 200

        body['request'] = [{'token':uuid,'resources':[resource_id_1]}]
        r = consumer.update_token(body)
        assert r['success'] is False
        assert r['status_code'] == 403
        
        # add another resource
        resource_id_2 = set_policy()

        body['request'] = [{'token':uuid,'resources':[resource_id_2]}]
        r = consumer.update_token(body)
        assert r['success'] is True 
        assert r['status_code'] == 200
        
        # resource_id is not deleted, since it was already revoked by provider
        assert len(r['response'][0]['deleted_resources']) == 0

def test_delete_token_empty_body():
        body = {}
        r = consumer.delete_token(body)
        assert r['success'] is False
        assert r['status_code'] == 400

def test_delete_token_invalid_request():
        body = {'tokens':[]}
        r = consumer.delete_token(body)
        assert r['success'] is False
        assert r['status_code'] == 400

        body = {'tokens':['12345']}
        r = consumer.delete_token(body)
        assert r['success'] is False
        assert r['status_code'] == 400

        body = {'tokens':[{'1234':5678}]}
        r = consumer.delete_token(body)
        assert r['success'] is False
        assert r['status_code'] == 400

        body = {'tokens':[['12345']]}
        r = consumer.delete_token(body)
        assert r['success'] is False
        assert r['status_code'] == 400

def test_delete_token_invalid_uuid():
        body = {'tokens':['df64092c-93a9-4ec4-9e86-3ca23a7d46a7']}
        r = consumer.delete_token(body)
        assert r['success'] is False
        assert r['status_code'] == 400
        
def test_delete_token_success():
        resource_id_1 = set_policy()
        resource_id_2 = set_policy()

        body = {}
        # get first token
        body['request'] = [resource_id_1]
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200

        token = r['response']['token']
        s = token.split("/")
        uuid_1 = s[3]

        # get second token
        body['request'] = [resource_id_2]
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200

        token = r['response']['token']
        s = token.split("/")
        uuid_2 = s[3]

        body = {'tokens':[uuid_1, uuid_2]}
        r = consumer.delete_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200

        r = consumer.view_tokens()

        for tokens in r['response']:
                assert tokens['uuid'] != uuid_1
                assert tokens['uuid'] != uuid_2

def test_delete_expired_token():
        resource_id = set_policy()

        body = {}
        body['request'] = [resource_id]
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200

        token = r['response']['token']
        s = token.split("/")
        uuid = s[3]

        assert expire_token(uuid) is True

        body = {'tokens':[uuid]}
        r = consumer.delete_token(body)
        assert r['success'] is False
        assert r['status_code'] == 400

def test_delete_token_again():
        resource_id = set_policy()

        body = {}
        body['request'] = [resource_id]
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200

        token = r['response']['token']
        s = token.split("/")
        uuid = s[3]

        body = {'tokens':[uuid]}
        r = consumer.delete_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200

        r = consumer.view_tokens()

        for tokens in r['response']:
                assert tokens['uuid'] != uuid

        body = {'tokens':[uuid]}
        r = consumer.delete_token(body)
        assert r['success'] is False
        assert r['status_code'] == 400

def test_get_tokens_deleted_token():
        resource_id = set_policy()

        body = {}
        body['request'] = [resource_id]
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200

        token = r['response']['token']
        s = token.split("/")
        uuid = s[3]

        body = {'tokens':[uuid]}
        r = consumer.delete_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200

        r = consumer.view_tokens()

        for tokens in r['response']:
                assert tokens['uuid'] != uuid

def test_get_tokens_expired_token():
        resource_id = set_policy()

        body = {}
        body['request'] = [resource_id]
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200

        token = r['response']['token']
        s = token.split("/")
        uuid = s[3]

        assert expire_token(uuid) is True

        r = consumer.view_tokens()
        
        check = False
        for tokens in r['response']:
                if uuid == tokens['uuid']:
                        assert tokens['status'] == 'expired'
                        check =  True
        
        assert check is True

def test_get_tokens_revoked_resource():
        resource_id = set_policy()

        body = {}
        body['request'] = [resource_id]
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200

        token = r['response']['token']
        s = token.split("/")
        uuid = s[3]

        access_id = -1

        # find access ID and delete it
        r = provider.get_provider_access()
        assert r['success']     == True
        assert r['status_code'] == 200
        rules = r['response']
        for r in rules:
                if resource_id == r['item']['cat_id']:
                        access_id = r['id']
                        break

        assert  access_id != -1
        r = provider.delete_rule([{'id':access_id}])
        assert r['success']     == True
        assert r['status_code'] == 200

        r = consumer.view_tokens()
        
        check = False
        for tokens in r['response']:
                if uuid == tokens['uuid']:
                        assert tokens['request'][0]['status'] == 'revoked'
                        check = True
        
        assert check is True

def test_get_tokens_deleted_resource():
        resource_id_1 = set_policy()
        resource_id_2 = set_policy()

        body = {}
        body['request'] = [resource_id_1, resource_id_2]
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200

        token = r['response']['token']
        s = token.split("/")
        uuid = s[3]

        body['request'] = [{'token':uuid,'resources':[resource_id_2]}]
        r = consumer.update_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200

        r = consumer.view_tokens()
        resources =[]
        
        check = False
        for tokens in r['response']:
                if uuid == tokens['uuid']: 
                        resources = tokens['request']
        
        for i in resources:
                if i['cat_id'] == resource_id_1:
                        assert i['status'] == 'deleted'
                        check = True

        assert check is True

def test_same_resource_same_user_diff_role():
        # policy set for same resource for a user registered as consumer
        # and data ingester. Getting a token for the resource will result
        # in a token with '2' resources, one reflecting the consumer
        # policy, the other for the ingester policy
        resource_id = set_policy()

        access_req = {"user_email": email, 
                    "user_role":'data ingester', 
                    "item_id":resource_id, 
                    "item_type":"resourcegroup"
                    }
        r = provider.provider_access([access_req])
        assert r['success']     == True
        assert r['status_code'] == 200

        body = {}
        body['request'] = [resource_id]
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200

        token = r['response']['token']
        s = token.split("/")
        uuid = s[3]

        r = consumer.view_tokens()
        
        check = False
        for tokens in r['response']:
                if uuid == tokens['uuid']:
                        assert len(tokens['request']) == 2
                        check = True
        
        assert check is True

def test_different_provider_tokens():
        resource_id = set_policy()

        # let alt_provider set a policy
        resource_id_alt = "iisc.ac.in/2052f450ac2dde345335fb18b82e21da92e3388c/rs.iudx.io/" + rand_rsg()
        access_req = {"user_email": email, 
                    "user_role":'consumer', 
                    "item_id":resource_id_alt, 
                    "item_type":"resourcegroup",
                    "capabilities":["complex","subscription","temporal"]
                    }
        r = alt_provider.provider_access([access_req])
        assert r['success']     == True
        assert r['status_code'] == 200


        body = {}
        body['request'] = [resource_id, resource_id_alt]
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200

        token = r['response']['token']
        s = token.split("/")
        uuid = s[3]

        r = consumer.view_tokens()
        
        check = False
        for tokens in r['response']:
                if uuid == tokens['uuid']:
                        assert len(tokens['request']) == 2
                        resources = [i['cat_id'] for i in tokens['request']]
                        assert set(resources) == set(body['request'])
                        check = True
        
        assert check is True
