![IUDX](./images/iudx.png)
# India Urban Data eXchange (IUDX) Authentication, Authorization, and Accounting (AAA) Server

IUDX-AAA is the Authentication, Authorization, and Accounting server for accessing [IUDX](https://www.iudx.org.in) services.

## 1. Read the API documentation
Please visit [IUDX Auth Documentation](https://authdocs.iudx.org.in) for API specifications and documentation.

The [postman_collections](postman_collections) folder contains Postman collections for the various APIs.

IUDX-AAA consists of 2 endpoints, the Auth endpoint and the Consent endpoint. 
* The Auth endpoint serves all Auth and Admin APIs. These APIs need to be called with a valid client certificate issued by IUDX
* The Consent endpoint serves all Consent APIs. These APIs are used for registering as an IUDX Provider or Consumer

## 2. Installation
### 2.1 Install Ubuntu 20.04

Install [Ubuntu 20.04](https://releases.ubuntu.com/20.04/)

### 2.2 Installation of IUDX Auth server (as root)

1. Clone this repository in the `/home` directory

2. Change directory to `iudx-auth-server`

3. The setup will configure Let's Encrypt SSL certificates for the Auth and Consent endpoints using Certbot automatically. Add your email address and the domain names for the Auth endpoint and Consent endpoint to the [certbot.env](certbot.env) file. The default domains are `auth.iudx.org.in` and `cons.iudx.org.in` respectively. **For a test instance, Certbot will not be executed and [certbot.env](certbot.env) should not be changed.**

4. IUDX-AAA sends certificates via email. In order to send emails, update [mailer_config.json](mailer_config.json) with your SMTP server details

5. IUDX-AAA signs Certificate Signing Requests (CSR) to create certificates. This requires a [root certificate](https://en.wikipedia.org/wiki/Root_certificate) and it's corresponding private key. Rename your root certificate and key files to `cert.pem` and `key.pem` respectively and place them in the directory. **The files will be created automatically if they are not added to the directory**. (For a test instance, it is recommended to use the generated root certificate)


6. Update the `AUTH_SERVER` and `CONSENT_URL` variables in [main.js](main.js) to your respective Auth and Consent domains

7. If PostgreSQL is to be installed in a different server:
	- Run [postgres-remote.sh](postgres-remote.sh) on that machine and follow instructions specified in that file
	- Create an environment variable with the IP address of the PostgreSQL machine on the Auth machine
			
			export POSTGRES_IP=<ip of that machine>
			
	- **If the environment variable is not set, then PostgreSQL will be installed on the same machine**
	- Update the `DB_SERVER` variable in [main.js](main.js)

8. In order to make the 2factor flow work, the file [2factor_config](2factor_config) must be populated with the required details.

9. In order to make sessionIds work in test/development, the header 'tfa' is required. To change the environment in which the instance is running, NODE_ENV must be set to 'development'. This can be changed in [auth-server.service](auth-server.service).  

10. Finally, run `setup`

```
	./setup
``` 

for a test instance of IUDX-AAA, add `test` to the command. Please read Section 5 for more details.

```
	./setup test
``` 

## 3. After install

* IUDX-AAA uses admin APIs to perform administrative tasks. In order to create an admin role, you may add a role to an existing user by performing an insert in the `roles` table. (`INSERT INTO consent.role (user_id,role,status,created_at,updated_at) VALUES (<user id>,'admin','approved',NOW(),NOW()`)

* The Auth server is configured as a Systemd service during setup. Hence, systemctl commands can be used to stop, start, etc. the server.

```
	sudo systemctl status auth-server.service		// check status of Auth server
	sudo systemctl stop auth-server.service		
	sudo systemctl start auth-server.service		
	sudo systemctl restart auth-server.service		
```

* The NGINX configs for the Auth ([nginx.conf](nginx.conf)) and Consent ([consent-nginx.conf](consent-nginx.conf)) endpoints will be placed in `/etc/nginx/sites-available` and renamed to the Auth and Consent domains configured in [certbot.env](certbot.env)

* The passwords for the DB users are present in the `passwords` directory

* To enable Telegram notifications, add your Telegram API key and chat ID to the `telegram.apikey` and `telegram.chatid` files respectively

## 4. Database structure

The tables used in the project are:
* `token` : Token related information
* `policy`: Policies associated with individual providers
* `crl`	  : Information regarding revoked certificates
* `organizations` : Organization related information
* `users`		: Individual user related information
* `role`		: Roles associated with users
* `certificates`	: CSRs and certificates of users
* `access`		: Access and policy related information
* `resourcegroup`	: Resource groups for which policies have been created
* `capability`		: Capabilities associated with individual access rules/policies

For more information, please check the [schema.sql](schema.sql) and [consent_schema.sql](consent_schema.sql) files.

## 5. Testing

* All tests are run on localhost
* The domains `auth.iudx.org.in` and `cons.iudx.org.in` are added to the `/etc/hosts` file as _127.0.0.1_ to facilitate testing on localhost
* The root certificate is used to sign several certificates. These are placed in the `/root` directory and are used when testing the various APIs
* It is recommended to not use a test instance in production

### Running tests

1. All tests are written in Python3. The _requests_ and _psycopg2_ Python packages are required to run tests:

```
apt install python3-pip
pip3 install psycopg2
pip3 install requests
```

2. NGINX is configured to perform rate-limiting on the Auth and Consent endpoints. To avoid this during testing, increase the request limit in `/etc/nginx/sites-available/auth.iudx.org.in` and `/etc/nginx/sites-available/cons.iudx.org.in`. Then, restart NGINX (`systemctl restart nginx`)

3. To execute the tests - in the `tests/` directory, run:

```
./run
```

A collection of tests have been written for _pytest_ (`pip3 install pytest`). In the `tests/` directory, run:

```
pytest
```

## 6. License

[MIT](./LICENSE)
