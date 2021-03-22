# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

import os
import sys
import json
import requests

f = open('../2factor_config.json')
data = json.load(f)

class Auth():
#{
        secured_endpoints = data['secured_endpoints']

        def __init__(self, certificate, key, auth_server="auth.iudx.org.in", version=1):
        #
                # Since we are testing on localhost
                self.ssl_verify = False

                self.url                = "https://" + auth_server
                self.credentials        = (certificate, key)
                self.session_id         = '0'
        #

        def call(self, api, body=None, method = "POST", params=None, header={}):
        #
                ret = True # success

                api_type = "/auth"

                body = json.dumps(body)
                endpoint = api_type + "/v1/" + api
                url = self.url + endpoint

                if endpoint in Auth.secured_endpoints and method in Auth.secured_endpoints[endpoint]:
                        header['session-id'] = self.session_id
                        header['tfa'] = 'true'

                response = requests.request (
                        method      = method,
                        url         = url,
                        verify      = self.ssl_verify,
                        cert        = self.credentials,
                        data        = body,
                        params      = params,
                        headers     = {"content-type":"application/json", **header}
                )

                if response.status_code != 200:
                #
                        if "EXPECT_FAILURE" not in os.environ:
                        #
                                sys.stderr.write (
                                        "WARNING: auth API failure  | " +
                                        url                     + " | " +
                                        response.reason         + " | " +
                                        response.text
                                )
                        #

                        ret = False
                #

                if response.headers['content-type'] == 'application/json':
                #
                        return {
                                "success"       : ret,
                                "response"      : json.loads(response.text),
                                "status_code"   : response.status_code
                        }
                #
                else:
                #
                        if "EXPECT_FAILURE" not in os.environ:
                        #       
                                sys.stderr.write (
                                        "WARNING: auth did not send 'application/json' : " + url  + "\n"
                                )
                        #

                        return {"success":ret, "response":None}
                #
        #

        def set_user_session_id(self, id):
                self.session_id = id

        def certificate_info(self):
                return self.call("certificate-info")

        def get_token(self, body):
        #
                return self.call("token", body)
        #

        def view_tokens(self):
        #
                return self.call("token", None, "GET")
        #

        def update_token(self, body):
        #
                return self.call("token", body, "PUT")
        #

        def delete_token(self, body):
        #
                return self.call("token", body, "DELETE")
        #

        def view_consumer_resources(self):
        #
                return self.call("consumer/resources", None, "GET")
        #

        def introspect_token(self, token):
        #
                body = {'token': token}

                return self.call("token/introspect", body)
        #

        def provider_access(self, request, provider_email=None):
        #
                header = {}

                if provider_email:
                        header['provider-email'] = provider_email

                return self.call("provider/access", request, "POST", {}, header)
        #

        def update_rule(self, request, provider_email=None):
        #
                header = {}

                if provider_email:
                        header['provider-email'] = provider_email

                return self.call("provider/access", request, "PUT", {}, header)
        #

        def delete_rule(self, request, provider_email=None):
        #
                header = {}

                if provider_email:
                        header['provider-email'] = provider_email

                return self.call("provider/access", request, "DELETE", {}, header)
        #

        def get_provider_access(self,provider_email=None):
        #
                header = {}

                if provider_email:
                        header['provider-email'] = provider_email
                
                return self.call("provider/access", {}, "GET", {}, header)
        #

        def organization_reg(self, org):
        #
                body = {'organization' : org}
                return self.call("admin/organizations", body)
        #

        def get_provider_regs(self, filtr=None):
        #
                params = {"filter" : filtr}
                return self.call("admin/provider/registrations", {}, "GET", params)
        #

        def update_provider_status(self, uid, status):
        #
                params = {"user_id" : uid, "status" : status}
                return self.call("admin/provider/registrations/status", {}, "PUT", params)
        #

        def get_delegate_providers(self):
        #
                return self.call("delegate/providers", {}, "GET")
        #

        def get_session_id(self,request):
        #
                return self.call("get-session-id",request,"POST" )
        #
#}
