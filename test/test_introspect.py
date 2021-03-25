import os
import pytest

from init import consumer
from init import provider
from init import resource_server
from init import catalogue_server
from init import file_server

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

@pytest.fixture(scope="session", autouse=True)
def init():
        init_provider("arun.babu@rbccps.org") # provider
        init_provider("abc.123@iisc.ac.in") # alt_provider

        ######### session ID setup for provider, alt_provider ###########
        r = provider.get_session_id(ALL_SECURE_ENDPOINTS_BODY)
        assert r['success'] is True

        provider.set_user_session_id(fetch_sessionId("arun.babu@rbccps.org"))
        '''
        r = alt_provider.get_session_id(ALL_SECURE_ENDPOINTS_BODY)
        assert r['success'] is True
       
        alt_provider.set_user_session_id(fetch_sessionId("abc.123@iisc.ac.in"))
        '''
        # register the consumer
        assert reset_role(email) == True
        org_id = add_organization("iisc.ac.in")
        
        r = role_reg(email, '9454234223', name , ["consumer", "onboarder", "data ingester"], org_id, csr)
        assert r['success']     == True
        assert r['status_code'] == 200

def test_empty_token():
        r = resource_server.introspect_token(' ')
        assert r['success'] is False
        assert r['status_code'] == 400

def test_invalid_token():
        token = 'auth.iudx.io/xyz.abc@datakaveri.org/e7444fab9a74ffb6da795a69c0eeb3b5/4238265a-611f-41c0-813a-6e16cf8cc228'
        r = resource_server.introspect_token(token)
        assert r['success'] is False
        assert r['status_code'] == 400

        token = 'auth.iudx.org.in/xy#)(@datakaveri.org/e7444fab9a74ffb6da795a69c0eeb3b5/4238265a-611f-41c0-813a-6e16cf8cc228'
        r = resource_server.introspect_token(token)
        assert r['success'] is False
        assert r['status_code'] == 400

        token = 'auth.iudx.org.in/xyz.abc@datakaveri.org/eAZZfab9a74ffb6da795a69c0eeb3b5/4238265a-611f-41c0-813a-6e16cf8cc228'
        r = resource_server.introspect_token(token)
        assert r['success'] is False
        assert r['status_code'] == 400

        token = 'auth.iudx.org.in/xyz.abc@datakaveri.org/e7444fab9a74ffb6da795a69c0eeb3b5/4238265a611f-41c0-813a-6e16cf8cc228'
        r = resource_server.introspect_token(token)
        assert r['success'] is False
        assert r['status_code'] == 400

        token = 'auth.iudx.org.in/xyz.abc@datakaveri.org/e7444fab9a74ffb6da795a69c0eeb3b5/4238265a-z11f-41c0-813a-6e16cf8cc228'
        r = resource_server.introspect_token(token)
        assert r['success'] is False
        assert r['status_code'] == 400

def test_valid_token():
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

        body = {}
        body['request'] = [resource_id]
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200

        token = r['response']['token']
        r = resource_server.introspect_token(token)
        assert r['success'] is True
        assert r['status_code'] == 200
        
        response = r['response']
        assert response['consumer'] == token.split('/')[1]
        assert response['request'][0]['id'] == resource_id + '/*' # since its res group
        assert len(response['request'][0]['apis']) > 1
        
def test_expired_token():
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

        body = {}
        body['request'] = [resource_id]
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200
        token = r['response']['token']

        r = resource_server.introspect_token(token)
        assert r['success'] is True
        assert r['status_code'] == 200
        assert len(r['response']['request']) == 1

        s = token.split("/")
        uuid = s[3]

        assert expire_token(uuid) is True

        r = resource_server.introspect_token(token)
        assert r['success'] is False
        assert r['status_code'] == 403

def test_deleted_token():
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

        body = {}
        body['request'] = [resource_id]
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200
        token = r['response']['token']

        r = resource_server.introspect_token(token)
        assert r['success'] is True
        assert r['status_code'] == 200

        s = token.split("/")
        uuid = s[3]

        body = {'tokens':[uuid]}
        r = consumer.delete_token(body)
        assert r['success'] is True 
        assert r['status_code'] == 200

        r = resource_server.introspect_token(token)
        assert r['success'] is False
        assert r['status_code'] == 403

def test_token_belonging_diff_server():
        resource_id = "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/file.iudx.io/" + rand_rsg()
        access_req = {"user_email": email, 
                    "user_role":'consumer', 
                    "item_id":resource_id, 
                    "item_type":"resourcegroup",
                    "capabilities":["download"]
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

        r = resource_server.introspect_token(token)
        assert r['success'] is False
        assert r['status_code'] == 403

        r = file_server.introspect_token(token)
        assert r['success'] is True
        assert r['status_code'] == 200
        assert len(r['response']['request']) == 1

def test_revoked_rule():
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

        body = {}
        body['request'] = [resource_id]
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200

        token = r['response']['token']
        r = resource_server.introspect_token(token)
        assert r['success'] is True
        assert r['status_code'] == 200

        # delete rule
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
        
        r = resource_server.introspect_token(token)
        assert r['success'] is False
        assert r['status_code'] == 403

def test_onboarder_token():
        access_req = {"user_email": email, 
                    "user_role":'onboarder' 
                    }
        r = provider.provider_access([access_req])
        assert r['success']     == True
        assert r['status_code'] == 200

        body = {}
        resource_id = "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/catalogue.iudx.io/catalogue/crud"
        body['request'] = [resource_id]
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200

        token = r['response']['token']
        r = catalogue_server.introspect_token(token)
        assert r['success'] is True
        assert r['status_code'] == 200
        resp = r['response']
        
        assert len(resp['request']) == 1
        assert resp['request'][0]['id'] == resource_id
        assert len(resp['request'][0]['apis']) == 0

def test_rs_consumer_caps():
        with open('../capabilities.json') as f:
                caps = json.load(f)
                for cap, apis in caps['rs.iudx.io']['consumer'].items():
                        resource_id = "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs.iudx.io/" + rand_rsg()
                        access_req = {"user_email": email, 
                                    "user_role":'consumer', 
                                    "item_id":resource_id, 
                                    "item_type":"resourcegroup",
                                    "capabilities":[cap]
                                    }
                        r = provider.provider_access([access_req])
                        assert r['success']     == True
                        assert r['status_code'] == 200

                        apis = [str.replace('{{RESOURCE_GROUP_ID}}',resource_id) for str in apis]

                        body = {}
                        body['request'] = [resource_id]
                        r = consumer.get_token(body)
                        assert r['success'] is True
                        assert r['status_code'] == 200

                        token = r['response']['token']
                        r = resource_server.introspect_token(token)
                        assert r['success'] is True
                        assert r['status_code'] == 200

                        resp = r['response']
                        
                        assert len(resp['request']) == 1
                        assert resp['request'][0]['id'] == resource_id + '/*'
                        assert set(resp['request'][0]['apis']) == set(apis)

def test_file_consumer_caps():
        with open('../capabilities.json') as f:
                caps = json.load(f)
                for cap, apis in caps['file.iudx.io']['consumer'].items():
                        resource_id = "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/file.iudx.io/" + rand_rsg()
                        access_req = {"user_email": email, 
                                    "user_role":'consumer', 
                                    "item_id":resource_id, 
                                    "item_type":"resourcegroup",
                                    "capabilities":[cap]
                                    }
                        r = provider.provider_access([access_req])
                        assert r['success']     == True
                        assert r['status_code'] == 200

                        apis = [str.replace('{{RESOURCE_GROUP_ID}}',resource_id) for str in apis]

                        body = {}
                        body['request'] = [resource_id]
                        r = consumer.get_token(body)
                        assert r['success'] is True
                        assert r['status_code'] == 200

                        token = r['response']['token']
                        r = file_server.introspect_token(token)
                        assert r['success'] is True
                        assert r['status_code'] == 200

                        resp = r['response']
                        
                        assert len(resp['request']) == 1
                        assert resp['request'][0]['id'] == resource_id + '/*'
                        assert set(resp['request'][0]['apis']) == set(apis)

def test_ingester_rs():
        with open('../capabilities.json') as f:
                caps = json.load(f)
                for cap, apis in caps['rs.iudx.io']['data ingester'].items():
                        resource_id = "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs.iudx.io/" + rand_rsg()
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
                        r = resource_server.introspect_token(token)
                        assert r['success'] is True
                        assert r['status_code'] == 200

                        resp = r['response']
                        
                        assert len(resp['request']) == 1
                        assert resp['request'][0]['id'] == resource_id + '/*'
                        assert set(resp['request'][0]['apis']) == set(apis)

def test_ingester_file():
        with open('../capabilities.json') as f:
                caps = json.load(f)
                for cap, apis in caps['file.iudx.io']['data ingester'].items():
                        resource_id = "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/file.iudx.io/" + rand_rsg()
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
                        r = file_server.introspect_token(token)
                        assert r['success'] is True
                        assert r['status_code'] == 200

                        resp = r['response']
                        
                        assert len(resp['request']) == 1
                        assert resp['request'][0]['id'] == resource_id + '/*'
                        assert set(resp['request'][0]['apis']) == set(apis)

def test_rs_all_caps():
        with open('../capabilities.json') as f:
                caps = json.load(f)
                all_caps = list(caps['rs.iudx.io']['consumer'].keys())
                all_apis = set()
                apis = list(caps['rs.iudx.io']['consumer'].values())

                for i in apis:
                    all_apis.update(i)
                
                resource_id = "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs.iudx.io/" + rand_rsg()
                access_req = {"user_email": email, 
                            "user_role":'consumer', 
                            "item_id":resource_id, 
                            "item_type":"resourcegroup",
                            "capabilities":all_caps
                            }
                r = provider.provider_access([access_req])
                assert r['success']     == True
                assert r['status_code'] == 200

                all_apis = {str.replace('{{RESOURCE_GROUP_ID}}',resource_id) for str in all_apis}

                body = {}
                body['request'] = [resource_id]
                r = consumer.get_token(body)
                assert r['success'] is True
                assert r['status_code'] == 200

                token = r['response']['token']
                r = resource_server.introspect_token(token)
                assert r['success'] is True
                assert r['status_code'] == 200

                resp = r['response']
                
                assert len(resp['request']) == 1
                assert resp['request'][0]['id'] == resource_id + '/*'
                assert set(resp['request'][0]['apis']) == all_apis

def test_deleted_cap():
        with open('../capabilities.json') as f:
                caps = json.load(f)
                all_caps = list(caps['rs.iudx.io']['consumer'].keys())
                all_apis = set()
                apis = list(caps['rs.iudx.io']['consumer'].values())

                for i in apis:
                    all_apis.update(i)
                
                resource_id = "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs.iudx.io/" + rand_rsg()
                access_req = {"user_email": email, 
                            "user_role":'consumer', 
                            "item_id":resource_id, 
                            "item_type":"resourcegroup",
                            "capabilities":all_caps
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
                r = resource_server.introspect_token(token)
                assert r['success'] is True
                assert r['status_code'] == 200

                resp = r['response']
                
                all_apis = {str.replace('{{RESOURCE_GROUP_ID}}',resource_id) for str in all_apis}
                assert len(resp['request']) == 1
                assert resp['request'][0]['id'] == resource_id + '/*'
                assert set(resp['request'][0]['apis']) == all_apis

                # delete subscription capability and then introspect
                # find access ID and delete it
                access_id = -1
                r = provider.get_provider_access()
                assert r['success']     == True
                assert r['status_code'] == 200
                rules = r['response']
                for r in rules:
                        if r['item'] and resource_id == r['item']['cat_id']:
                                access_id = r['id']
                                break

                assert  access_id != -1
                r = provider.delete_rule([{'id':access_id, 'capabilities':['subscription']}])
                assert r['success']     == True
                assert r['status_code'] == 200
        
                subscription_api = caps['rs.iudx.io']['consumer']['subscription'][0]

                r = resource_server.introspect_token(token)
                assert r['success'] is True
                assert r['status_code'] == 200

                resp = r['response']
                
                assert len(resp['request']) == 1
                assert resp['request'][0]['id'] == resource_id + '/*'
                assert subscription_api not in set(resp['request'][0]['apis'])

def test_consumer_ingester_same_resource():
        with open('../capabilities.json') as f:
                caps = json.load(f)
                all_caps = list(caps['rs.iudx.io']['consumer'].keys())
                all_apis = set()
                consumer_apis = list(caps['rs.iudx.io']['consumer'].values())
                ingester_apis = list(caps['rs.iudx.io']['data ingester']['default'])

                for i in consumer_apis:
                    all_apis.update(i)
                
                all_apis.update(ingester_apis)
            
                resource_id = "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs.iudx.io/" + rand_rsg()
                access_req_c = {"user_email": email, 
                            "user_role":'consumer', 
                            "item_id":resource_id, 
                            "item_type":"resourcegroup",
                            "capabilities":all_caps
                            }

                access_req_di = {"user_email": email, 
                            "user_role":'data ingester', 
                            "item_id":resource_id, 
                            "item_type":"resourcegroup"
                            }
                r = provider.provider_access([access_req_c, access_req_di])
                assert r['success']     == True
                assert r['status_code'] == 200

                body = {}
                body['request'] = [resource_id]
                r = consumer.get_token(body)
                assert r['success'] is True
                assert r['status_code'] == 200

                token = r['response']['token']
                r = resource_server.introspect_token(token)
                assert r['success'] is True
                assert r['status_code'] == 200
                
                check = False

                all_apis = {str.replace('{{RESOURCE_GROUP_ID}}',resource_id) for str in all_apis}
                assert len(r['response']['request']) == 1
                for i in r['response']['request']:
                        assert i['id'] == resource_id + '/*'
                        if all_apis == set(i['apis']):
                               check = True

                assert check is True

# token w/ expired rule
def test_expired_rule():
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

        body = {}
        body['request'] = [resource_id]
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200

        token = r['response']['token']
        r = resource_server.introspect_token(token)
        assert r['success'] is True
        assert r['status_code'] == 200

        # delete rule
        # find access ID and delete it
        r = provider.get_provider_access()
        assert r['success']     == True
        assert r['status_code'] == 200
        rules = r['response']
        for r in rules:
                if r['item'] and resource_id == r['item']['cat_id']:
                        access_id = r['id']
                        break

        assert  access_id != -1
        assert expire_rule(access_id) is True

        r = resource_server.introspect_token(token)
        assert r['success'] is False
        assert r['status_code'] == 403

def test_different_items():
        resource_id = "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs.iudx.io/" + rand_rsg()
        access_req = {"user_email": email, 
                    "user_role":'consumer', 
                    "item_id":resource_id, 
                    "item_type":"resourcegroup",
                    "capabilities":["complex","subscription","temporal"]
                    }
        r = provider.provider_access([access_req])

        body = {}
        body['request'] = [resource_id, resource_id + "/item-1", resource_id + "/item-2/item-3"]
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200
        token = r['response']['token']

        r = resource_server.introspect_token(token)
        assert r['success'] is True
        assert r['status_code'] == 200

        assert len(r['response']['request']) == 3
        for i in r['response']['request']:
                assert i['id'] in [resource_id + '/*', resource_id + "/item-1", resource_id + "/item-2/item-3"]

def test_different_resources():
        resource_id_1 = "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs.iudx.io/" + rand_rsg()
        resource_id_2 = "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs.iudx.io/" + rand_rsg()

        access_req_1 = {"user_email": email, 
                    "user_role":'consumer', 
                    "item_id":resource_id_1, 
                    "item_type":"resourcegroup",
                    "capabilities":["complex","subscription","temporal"]
                    }

        access_req_2 = {"user_email": email, 
                    "user_role":'consumer', 
                    "item_id":resource_id_2, 
                    "item_type":"resourcegroup",
                    "capabilities":["complex","subscription","temporal"]
                    }

        r = provider.provider_access([access_req_1, access_req_2])

        body = {}
        body['request'] = [resource_id_1, resource_id_2, resource_id_1 + "/item-1"]
        r = consumer.get_token(body)
        assert r['success'] is True
        assert r['status_code'] == 200
        token = r['response']['token']

        r = resource_server.introspect_token(token)
        assert r['success'] is True
        assert r['status_code'] == 200

        assert len(r['response']['request']) == 3
        for i in r['response']['request']:
                assert i['id'] in [resource_id_1 + '/*', resource_id_2 + '/*', resource_id_1 + "/item-1"]
