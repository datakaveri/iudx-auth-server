from init import untrusted
from init import alt_provider
from init import consumer
from access import *
from session import fetch_sessionId
from consent import role_reg
import random
import string
import pytest

# use consumer certificate to register
email   = "barun@iisc.ac.in"
org_id = add_organization("iisc.ac.in")

# use alt_provider certificate as delegate
delegate_email = "abc.123@iisc.ac.in"

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
        r = role_reg(email, '9454234223', name , ["consumer"], org_id, csr)
        assert r['success']     == True
        assert r['status_code'] == 200
       
# provider ID of abc.xyz@rbccps.org
provider_id = 'rbccps.org/f3dad987e514af08a4ac46cf4a41bd1df645c8cc'

resource_group = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
resource_id = provider_id + '/rs.example.com/' + resource_group

consumer_id = -1
onboarder_id = -1
ingester_id = -1
delegate_id = -1
id = -1



def test_apis_missing():
        # session id req should fail since body doesnt contain 'apis'
        body ={"asdf": [
                    {
                    "method": "get",
                    "endpoint": "/auth/v1/provider/access   "
              }]}
        r = untrusted.get_session_id(body)
        assert r['success']     is False
        assert r['status_code'] == 400

def test_apis_empty():
        # session id req should fail since body has empty 'apis'
        body ={"apis": [
                    {
              }]}
        r = untrusted.get_session_id(body)
        assert r['success']     is False
        assert r['status_code'] == 400

def test_method_missing():
        # session id req should fail since 'apis'doesnt contain 'method'
        body ={"apis": [
                    {
                    "methodsss": "get",
                    "endpoint": "/auth/v1/provider/access"
              }]}
        r = untrusted.get_session_id(body)
        assert r['success']     is False
        assert r['status_code'] == 400


def test_endpoint_missing():
        # session id req should fail since 'apis'doesnt contain 'endpoint'
        body ={"apis": [
                    {
                    "method": "get",
                    "endpointss": "/auth/v1/provider/access"
              }]}
        r = untrusted.get_session_id(body)
        assert r['success']     is False
        assert r['status_code'] == 400

def test_endpoint_not_exist():
        # session id req should fail since endpoint is not a secure endpoint
        body ={"apis": [
                    {
                    "method": "get",
                    "endpoint": "/auth/v1/provider/registration"
              }]}
        r = untrusted.get_session_id(body)
        assert r['success']     is False
        assert r['status_code'] == 400

def test_userRole_not_secure():
    # user role is not a defined as a secured endpoint-role
    body ={"apis": [
                    {
                    "method": "get",
                    "endpoint": "/auth/v1/provider/access"
              }]}
    r = consumer.get_session_id(body)
    assert r['success']     is False
    assert r['status_code'] == 400


def test_Success():
    # successful flow
    body ={"apis": [
                    {
                    "method": "get",
                    "endpoint": "/auth/v1/provider/access"
              }]}
    r = untrusted.get_session_id(body)
    assert r['success']     is True
    id = fetch_sessionId('abc.xyz@rbccps.org')
    print(id)
    r = untrusted.get_provider_access(None,id)
    assert r['success']     is True
    assert r['status_code'] == 200

def test_unauthorized_session():
    #session id not valid for endpoint
    req = {"user_email": email, "user_role":'consumer','capabilities':['temporal'], "item_id":resource_id, "item_type":"resourcegroup"}
    id = fetch_sessionId('abc.xyz@rbccps.org')
    r = untrusted.provider_access([req],None,id)
    assert r['success']  is False
    assert r['status_code'] == 403 

def test_incorrect_user():
    #using sessionId by one user to check if it fails when used by any other user 
    body ={"apis": [
                    {
                    "method": "post",
                    "endpoint": "/auth/v1/provider/access"
              }]}
    r = untrusted.get_session_id(body)
    assert r['success']     is True
    id = fetch_sessionId('abc.xyz@rbccps.org')
    req = {"user_email": delegate_email, "user_role":'delegate'}
    r = untrusted.provider_access([req],None,id)
    print(r)
    assert r['success']     == True
    assert r['status_code'] == 200
    r = alt_provider.get_provider_access('abc.xyz@rbccps.org',id)
    assert r['success']     is False
    assert r['status_code'] == 403

def test_sessionId_incorrect():
    #passing incorrect session id while accessing Secure endpoint
    global id 
    body ={"apis": [
                  {
                    "method": "get",
                    "endpoint": "/auth/v1/provider/access"
            }]}
    r = untrusted.get_session_id(body)
    assert r['success']     is True
    id = ""
    r = untrusted.get_provider_access(None,id)
    assert r['success']     is False
    assert r['status_code'] == 403


def test_sessionId_multiple_sucess():
    #get session id for multiple end points and check if success      
    global id 
    body ={"apis": [
                  {
                    "method": "get",
                    "endpoint": "/auth/v1/provider/access"
                  },
                  {
                    "method": "post",
                    "endpoint": "/auth/v1/provider/access"
            
                  }
            ]}
    r = untrusted.get_session_id(body)
    assert r['success']     is True
    id = fetch_sessionId('abc.xyz@rbccps.org')
    r = untrusted.get_provider_access(None,id)
    assert r['success']     is True
    assert r['status_code'] == 200
    resource_group = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
    resource_id = provider_id + '/rs.example.com/' + resource_group
    req = {"user_email": email, "user_role":'consumer','capabilities':['temporal'], "item_id":resource_id, "item_type":"resourcegroup"}
    r = untrusted.provider_access([req],None,id)
    assert r['success']     is True
    assert r['status_code'] == 200

def test_delegate_flow():
    #check success flow for delegate and fails sessionId used with provider
    body ={"apis": [
                    {
                    "method": "get",
                    "endpoint": "/auth/v1/provider/access"
              }]}
    r = alt_provider.get_session_id(body)
    assert r['success']     is True
    assert r['status_code'] == 200
    id = fetch_sessionId(delegate_email)
    r = alt_provider.get_provider_access('abc.xyz@rbccps.org',id)
    assert r['success']     is True
    assert r['status_code'] == 200
    r = untrusted.get_provider_access(None,id)
    assert r['success']     is False
    assert r['status_code'] == 403