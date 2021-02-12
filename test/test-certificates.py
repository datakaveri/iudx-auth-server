# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

from init import consumer
from init import provider
from init import delegate
from init import untrusted
from init import resource_server
from init import example_dot_com

from init import expect_failure 

r = resource_server.certificate_info()
assert r["success"] is True
assert r["response"]["certificate-class"] == 1
assert r["response"]["id"] == "example@example.com"

r = consumer.certificate_info()
assert r["success"] is True
assert r["response"]["certificate-class"] == 2
assert r["response"]["id"] == "barun@iisc.ac.in"

r = provider.certificate_info()
assert r["success"] is True
assert r["response"]["certificate-class"] == 3
assert r["response"]["id"] == "arun.babu@rbccps.org"

r = example_dot_com.certificate_info()
assert r["success"] is True
assert r["response"]["certificate-class"] == 1
