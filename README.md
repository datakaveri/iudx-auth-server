# India Urban Data eXchange (IUDX) Authentication, Authorization, and Accounting (AAA) Server

IUDX-AAA is the Authentication, Authorization, and Accounting server for accessing [IUDX](https://www.iudx.org.in) services.

## 1. Read the API documentation
Please visit [IUDX Auth server](http://auth.iudx.org.in) for APIs and flows.

## 2. Installation
### 2.1 Install Ubuntu 20.04

Install [Ubuntu 20.04](https://releases.ubuntu.com/20.04/)

### 2.2 Installation of IUDX Auth server (as root)

1. Clone the repository in the `/home` directory
2. Change directory to `iudx-auth-server`
3. The setup will configure SSL certificates for the Auth and Consent endpoints using Certbot automatically. Add your email address and the domain names for the Auth endpoint and Consent endpoint to the `certbot.env` file 
4. In order to send emails, update `mailer_config.json` with your SMTP server details
5. To sign certificates, rename your signing certificate and key files to `cert.pem` and `key.pem` and place them in the directory
6. Update `admins.json` with the email addresses of users who will be admins
7. Update the `AUTH_SERVER` and `CONSENT_URL` variables in `main.js` to the desired domains
8. If PostgreSQL is to be installed in a different server:
	- Run `postgres-setup.sh` on that machine and follow instructions specified in that file
	- Create an environment variable with the IP address of the PostgreSQL machine on the Auth machine before running `setup`

```
	export POSTGRES_IP=<ip of that machine>
```	
	- Update the `DB_SERVER` variable in `main.js`, and the DB connection string in `crl.js`
	- If the environment variable is not set, then PostgreSQL will be installed on the same machine
9. Finally, run `setup`

```
	./setup
``` 

## 3. After install (as root) 

* The Auth server and CRL scripts are configured as Systemd services during setup. Hence, systemctl commands can be used to stop, start, etc. the server and script.

```
	systemctl status auth-server.service		// check status of Auth server
	systemctl stop auth-server.service		
	systemctl start auth-server.service		
	systemctl restart auth-server.service		

	systemctl status crl-script.service		// check status of Auth server
	systemctl stop crl-script.service		
	systemctl start crl-script.service		
	systemctl restart crl-script.service		
```

* The NGINX configs for the Auth and Consent endpoints will be placed in `/etc/nginx/sites-available` and renamed to the Auth and Consent domains configured in `certbot.env`. 

* The passwords for the DB users are present in the `passwords` directory

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

For more information, please check the `schema.sql` and `consent_schema.sql` files
