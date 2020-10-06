import requests
import json
import os
import sys

os.environ["EXPECT_FAILURE"] = "1"
CONSENT_ENDPOINT = "cons.iudx.org.in"
ssl_verify = True

##### Since we are testing on localhost, disable SSL warnings #####

ssl_verify = False
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def call(api, body=None, method = "POST"):
#
        ret = True # success

        api_type = "/consent"

        body = json.dumps(body)

        url = "https://" + CONSENT_ENDPOINT + "/v1/" + api
        response = requests.request (
                method      = method,
                url         = url,
                verify      = ssl_verify,
                data        = body,
                headers     = {"content-type":"application/json"}
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

def provider_reg(email, phone, name, organization, csr):
#
        body = { 
                    "email"         : email,
                    "phone"         : phone,
                    "name"          : name,
                    "organization"  : organization,
                    "csr"           : csr
                }

        return call("provider/registration", body)
#

def role_reg(email, phone, name, roles, org_id = None, csr = None):
#
        body = { 
                    "email"             : email,
                    "phone"             : phone,
                    "name"              : name,
                    "organization"   : org_id,
                    "csr"               : csr,
                    "roles"             : roles
                }

        return call("/registration", body)
#

def get_orgs():
#
        body ={}
        return call("/organizations", body, "GET")
#
