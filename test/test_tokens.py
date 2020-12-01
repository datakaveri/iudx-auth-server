# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

import os

from init import consumer
from init import provider
from init import alt_provider
from init import untrusted
from init import resource_server

from init import expect_failure

from init import restricted_consumer

import hashlib

body = ""
RS = "iisc.iudx.org.in"
TUPLE = type(("x",))
num_tokens_before = 0
token_hash = ""

def test_token():

        global body
        global TUPLE
        global RS

        policy = "x can access *" # dummy policy
        provider.set_policy(policy)

        policy = 'all can access * for 2 hours if tokens_per_day < 100'
        provider.set_policy(policy)

        assert policy in provider.get_policy()['response']['policy']

        new_policy  = "*@rbccps.org can access resource-yyz-abc for 1 hour"
        assert provider.append_policy(new_policy)['success'] is True

        x = provider.get_policy()['response']['policy']
        assert new_policy in x
        assert policy in x

        r = provider.audit_tokens(5)
        assert r['success'] is True
        audit_report        = r['response']
        as_provider         = audit_report["as-provider"]


        num_tokens_before = len(as_provider)
        body = [
                {
                        "id"    : "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/" + RS + "/resource-xyz-yzz",
                        "apis"          : ["/ngsi-ld/v1/entities"],
                        "methods"       : ["GET"],
                        "body"          : {"key":"some-key"}
                },
                {
                        "id"    : "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/abc.com/abc-xyz",
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
        assert 60*60*2          == access_token['expires-in']

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
                        "id"    : "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/" + RS + "/resource-xyz-yzz",
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
        r = provider.get_token(body)
        access_token = r['response']

        assert r['success']     is True
        assert None             != access_token
        assert 60*60*2          == access_token['expires-in']

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

def test_revoke_with_token():
        
        global body
        global TUPLE
        
        # test revoke API
        r = provider.get_token(body)
        access_token = r['response']

        assert r['success']     is True
        assert None             != access_token
        assert 60*60*2          == access_token['expires-in']

        token = access_token['token']

        if type(token) == TUPLE:
                token = token[0]

        s = token.split("/")

        assert len(s)   == 3
        assert s[0]     == 'auth.iudx.org.in'

        r = provider.audit_tokens(5)
        assert r["success"] is True
        audit_report        = r['response']
        as_consumer         = audit_report["as-consumer"]
        num_revoked_before  = 0

        for a in as_consumer:
                if a['revoked'] is True:
                        num_revoked_before = num_revoked_before + 1

        r = provider.revoke_tokens(token)
        assert r["success"] is True
        assert r["response"]["num-tokens-revoked"] >= 1

        r = provider.audit_tokens(5)
        assert r["success"] is True
        audit_report        = r['response']
        as_consumer         = audit_report["as-consumer"]
        num_revoked_after   = 0

        for a in as_consumer:
                if a['revoked'] is True:
                        num_revoked_after = num_revoked_after + 1

        assert num_revoked_before < num_revoked_after

        new_policy  = "*@iisc.ac.in can access * for 1 month"
        assert provider.set_policy(new_policy)['success'] is True

        # test token request without APIs
        body = [
                {
                        "id"    : "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs1/r1",
                },
                {
                        "id"    : "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs1/r2"
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
                        "id"    : "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs1/r1",
                        "apis"  : ["/ngsi-invalid"]
                },
                {
                        "id"    : "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs1/r2",
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
                        "id"    : "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs1/r1",
                        "apis"  : ["/ngsi-ld/v1/temporal/entities"]
                },
                {
                        "id"    : "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs1/r2",
                        "apis"  : ["/ngsi-ld/v1/temporal/entities"]
                }
        ]

        r = restricted_consumer.get_token(body)
        access_token = r['response']

        assert r['success']     is True
        assert None             != access_token
        assert 60*60*24*30      == access_token['expires-in']

        body = [
                {
                        "id"    : "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs1/r1",
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

        new_policy  = "*@iisc.ac.in can access * for 5 months"
        assert provider.set_policy(new_policy)['success'] is True

        body = [
                {
                    "id"    : "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs1/r1",
                    "apis"  : ["/ngsi-ld/v1/temporal/entities"]
                    },
                {
                    "id" : "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs2/r2",
                    "apis"  : ["/ngsi-ld/v1/temporal/entities"]
                    }
                ]

        r = consumer.get_token(body)
        assert r['success']                     is True
        assert r['response']['expires-in']      == 60*60*24*30*5

def test_multiple_provider_audit():

        # test audit for multiple providers
        policy = "all can access abc.com/*"
        provider.set_policy(policy)

        policy = 'all can access example.com/test-providers'
        alt_provider.set_policy(policy)

        body = [
                {
                        "id"    : "iisc.ac.in/2052f450ac2dde345335fb18b82e21da92e3388c/example.com/test-providers",
                        "apis"  : ["/ngsi-ld/v1/temporal/entities"]
                },
                {
                        "id"    : "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/abc.com/ABC123",
                        "apis"  : ["/ngsi-ld/v1/temporal/entities"]
                },
                {
                        "id"    : "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/abc.com/abc-xyz",
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
