# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

import os
import pytest

from init import consumer
from init import provider
from init import alt_provider
from init import untrusted
from init import resource_server

from init import expect_failure

from init import restricted_consumer

# for registration and resetting roles
from access import *
from consent import role_reg

import hashlib

body = ""
RS = "iisc.iudx.org.in"
TUPLE = type(("x",))
num_tokens_before = 0
token_hash = ""
email = "barun@iisc.ac.in"

@pytest.fixture(scope="session", autouse=True)
def init():
        init_provider("arun.babu@rbccps.org") # provider
        init_provider("abc.123@iisc.ac.in") # alt_provider

        # register the consumer
        assert reset_role(email) == True
        org_id = add_organization("iisc.ac.in")

        r = role_reg(email, '9454234223', name , ["consumer"], None, csr)
        assert r['success']     == True
        assert r['status_code'] == 200

def test_token():

        global body
        global TUPLE
        global RS

        req = {
                "user_email" : email, 
                "user_role":'consumer',
                "item_id":"rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/" + RS + "/resource-xyz-yzz",
                "capabilities": ['complex'],
                "item_type":"resourcegroup"
                }
        r = provider.provider_access([req])
        assert r['success']     == True
        assert r['status_code'] == 200

        req["item_id"] = "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/abc.com/abc-xyz"
        req["capabilities"] = ['temporal']
        r = provider.provider_access([req])
        assert r['success']     == True
        assert r['status_code'] == 200

        r = provider.audit_tokens(5)
        assert r['success'] is True
        audit_report        = r['response']
        as_provider         = audit_report["as-provider"]

        num_tokens_before = len(as_provider)
        body = [
                {
                        "id"    : "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/" + RS + "/resource-xyz-yzz/*",
                        "apis"          : ["/ngsi-ld/v1/entities"],
                        "method"        : "GET",
                        "body"          : {"key":"some-key"}
                },
                {
                        "id"    : "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/abc.com/abc-xyz/item",
                        "apis"  : ["/ngsi-ld/v1/entities/rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/abc.com/abc-xyz"],
                }
        ]

def test_introspect_audit():

        global body
        global TUPLE
        global num_tokens_before
        global token_hash

        r = consumer.get_token(body)
        access_token = r['response']

        assert r['success']     is True
        assert None             != access_token
        assert 60*60*24*7       == access_token['expires-in']

        token = access_token['token'],

        if type(token) == TUPLE:
                token = token[0]

        s = token.split("/")

        assert len(s)   == 3
        assert s[0]     == 'auth.iudx.org.in'

        server_token = access_token['server-token'][RS]
        if type(server_token) == TUPLE:
                server_token = server_token[0]

        assert resource_server.introspect_token (token,server_token)['success'] is True
        # introspect once more
        assert resource_server.introspect_token (token,server_token)['success'] is True

        # introspect with request
        request = [
                    {
                        "id"    : "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/" + RS + "/resource-xyz-yzz/*",
                        "apis"          : ["/ngsi-ld/v1/entities"],
                        "methods"       : ["GET"],
                        "body"          : {"key":"some-key"}
                    }
        ]

        bad_request = [
                    {
                        "id"    : "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/" + RS + "/resource-xyz-yzz",
                        "apis"          : ["/latest-now"],
                        "methods"       : ["POST"],
                        "body"          : {"key":"some-key"}
                    }
        ]

        assert resource_server.introspect_token (token,server_token,request)['success']                 is True

        expect_failure(True)
        assert resource_server.introspect_token (token,server_token,bad_request)['success']             is False
        assert resource_server.introspect_token (token,'invalid-token-012345678901234567')['success']   is False
        assert resource_server.introspect_token (token)['success']                                      is False
        expect_failure(False)

        r = provider.audit_tokens(5)
        assert r["success"] is True
        audit_report = r['response']
        as_provider = audit_report["as-provider"]
        num_tokens_after = len(as_provider)

        # number of tokens before and after request by consumer
        assert num_tokens_after > num_tokens_before

        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()

def test_revoke_with_tokenhash():

        global token_hash
        
        token_hash_found = False
        found = None

        r = provider.audit_tokens(5)
        assert r["success"] is True
        audit_report = r['response']
        as_provider = audit_report["as-provider"]

        for a in as_provider:
                if a['token-hash'] == token_hash:
                        token_hash_found = True
                        found = a
                        break

        assert token_hash_found is True
        assert found['revoked'] is False

        r = provider.revoke_token_hashes(token_hash)
        assert r['success'] is True
        assert r["response"]["num-tokens-revoked"] >= 1

        # check if token was revoked
        r = provider.audit_tokens(5)
        assert r["success"] is True
        audit_report = r['response']
        as_provider = audit_report["as-provider"]

        token_hash_found = False
        found = None
        for a in as_provider:
                if a['token-hash'] == token_hash:
                        token_hash_found = True
                        found = a
                        break

        assert token_hash_found is True
        assert found['revoked'] is True

def test_revoke_all():

        global body
        global TUPLE
        global RS

        # test revoke-all (as provider)
        r = consumer.get_token(body)
        access_token = r['response']

        assert r['success']     is True
        assert None             != access_token
        assert 60*60*24*7       == access_token['expires-in']

        token = access_token['token']

        if type(token) == TUPLE:
                token = token[0]

        s = token.split("/")

        assert len(s)   == 3
        assert s[0]     == 'auth.iudx.org.in'

        r = provider.audit_tokens(100)
        assert r["success"] is True
        audit_report        = r['response']
        as_provider         = audit_report["as-provider"]
        num_tokens          = len(as_provider)
        assert num_tokens   >= 1

        for a in as_provider:
                if a["revoked"] is False and a['expired'] is False:
                        cert_serial         = a["certificate-serial-number"]
                        cert_fingerprint    = a["certificate-fingerprint"]
                        break

        r = provider.revoke_all(cert_serial, cert_fingerprint)
        assert r["success"] is True
        assert r["response"]["num-tokens-revoked"] >= 1

        r = provider.audit_tokens(100)
        assert r["success"] is True
        audit_report        = r['response']
        as_provider         = audit_report["as-provider"]

        for a in as_provider:
                if a['certificate-serial-number'] == cert_serial and a['certificate-fingerprint'] == cert_fingerprint:
                        if a['expired'] is False:
                                assert a['revoked'] is True

def test_token_api():
        
        req = {
                "user_email" : email, 
                "user_role":'consumer',
                "item_id":"rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs1/r1",
                "item_type":"resourcegroup",
                "capabilities": ['temporal']
                }
        r = provider.provider_access([req])
        assert r['success']     == True
        assert r['status_code'] == 200

        body = [
                {
                        "id"    : "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs1/r1/*",
                },
                {
                        "id"    : "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs1/r1/r2"
                }
        ]

        expect_failure(True)
        r = restricted_consumer.get_token(body)
        expect_failure(False)

        assert r['success']     is False
        assert r['status_code'] == 400

        # test token request with invalid API

        body = [
                {
                        "id"    : "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs1/r1/*",
                        "apis"  : ["/ngsi-invalid"]
                },
                {
                        "id"    : "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs1/r1/r2",
                        "apis"  : ["/ngsi-invalid"]
                }
        ]

        expect_failure(True)
        r = restricted_consumer.get_token(body)
        expect_failure(False)

        assert r['success']     is False
        assert r['status_code'] == 400

        body = [
                {
                        "id"    : "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs1/r1/*",
                        "apis"  : ["/ngsi-ld/v1/temporal/entities"]
                },
                {
                        "id"    : "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs1/r1/r2",
                        "apis"  : ["/ngsi-ld/v1/temporal/entities"]
                }
        ]

        r = restricted_consumer.get_token(body)
        access_token = r['response']

        assert r['success']     is True
        assert None             != access_token
        assert 60*60*24*7       == access_token['expires-in']

        body = [
                {
                        "id"    : "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs1/r1/*",
                        "apis"  : ["/ngsi-ld/v1/temporal/entities"]
                },
                {
                        "id"    : "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs331/r2",
                        "apis"  : ["/ngsi-ld/v1/temporal/entities"]
                }
        ]

        expect_failure(True)
        r = restricted_consumer.get_token(body)
        expect_failure(False)

        assert r['success']     is False
        assert r['status_code'] == 403

        # new api tests

        body = [
                {
                    "id"    : "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs1/r1/item-0",
                    "apis"  : ["/ngsi-ld/v1/temporal/entities"]
                    },
                {
                    "id" : "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs1/r1/item-1",
                    "apis"  : ["/ngsi-ld/v1/temporal/entities"]
                    }
                ]

        r = consumer.get_token(body)
        assert r['success']                     is True
        assert r['response']['expires-in']      == 60*60*24*7

def test_multiple_provider_audit():

        # test audit for multiple providers
        req = {
                "user_email" : email, 
                "user_role":'consumer',
                "item_id":"rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/abc.com/r1",
                "capabilities": ['complex', 'temporal', 'subscription'],
                "item_type":"resourcegroup"
                }
        r = provider.provider_access([req])
        assert r['success']     == True
        assert r['status_code'] == 200

        req["item_id"] = "iisc.ac.in/2052f450ac2dde345335fb18b82e21da92e3388c/example.com/test-providers"
        r = alt_provider.provider_access([req])
        assert r['success']     == True
        assert r['status_code'] == 200

        body = [
                {
                        "id"    : "iisc.ac.in/2052f450ac2dde345335fb18b82e21da92e3388c/example.com/test-providers/*",
                        "apis"  : ["/ngsi-ld/v1/temporal/entities"]
                },
                {
                        "id"    : "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/abc.com/r1/ABC123",
                        "apis"  : ["/ngsi-ld/v1/temporal/entities"]
                },
                {
                        "id"    : "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/abc.com/r1/abc-xyz",
                        "apis"  : ["/ngsi-ld/v1/temporal/entities"]
                }
        ]

        r = consumer.get_token(body)
        access_token = r['response']

        r = alt_provider.audit_tokens(5)
        assert r["success"] is True
        audit_report = r['response']
        as_provider = audit_report["as-provider"]

        token_hash = hashlib.sha256(access_token['token'].encode('utf-8')).hexdigest()

        token_hash_found = False
        found = None

        for a in as_provider:
                if a['token-hash'] == token_hash:
                        token_hash_found = True
                        found = a
                        break

        assert token_hash_found is True
        assert found['revoked'] is False

        for r in found['request']:
                assert r['id'].startswith('iisc.ac.in') is True

        # same test with rbccps.org provider
        r = provider.audit_tokens(5)
        assert r["success"] is True
        audit_report = r['response']
        as_provider = audit_report["as-provider"]

        found = None

        for a in as_provider:
                if a['token-hash'] == token_hash:
                        found = a
                        break

        assert token_hash_found is True
        assert found['revoked'] is False

        for r in found['request']:
                assert r['id'].startswith('rbccps.org') is True
