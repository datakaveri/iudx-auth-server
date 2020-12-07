## Postman Collections

* [Organization_collection.json](Organization_collection.json) contains the Admin Organization Registration APIs
* [Registration_collection.json](Registration_collection.json) contains the Registration APIs for Providers and other roles (Consumers, Data Ingesters, Onboarders, Delegates) and also the GET organizations API 
* [ProviderApproval_collection.json](ProviderApproval_collection.json) contains the Admin Provider Approval APIs
* [Access_collection.json](Access_collection.json) contains the Access APIs (POST, GET and DELETE), with requests for access for different kinds of users (Consumers, Data Ingesters, Onboarders, Delegates). It also contains the `GET /auth/v1/delegate/providers` API for Delegates to determine which Providers have given them delegate access.
* [Token_collection.json](Token_collection.json) contains the Token API, with requests for issuing tokens for different kinds of users (consumers, data ingesters, onboarders)
* [AuditRevoke_collection.json](AuditRevoke_collection.json) contains the Audit, Revoke and Revoke-All APIs

Additionally, all collections that require a client certificate have the Certificate Info API included.

The environment file [AAA-Environment.postman_environment.json](AAA-Environment.postman_environment.json) can be used to configure the Auth and Consent URLs. By default, they are `authorization.iudx.org.in` and `consent.iudx.org.in` respectively.
