* Add email and endpoints to `certbot.env` file
* Update `mailer_config.json` with SMTP details
* Update AUTH_SERVER variable in `main.js`
* Update DB_SERVER variable in `main.js`
* Update DB connection string in `crl.js`
* Place `cert.pem` and `key.pem` in directory
* Update `admins.json` with admin emails
* If postgresql is installed on a different machine
    - run `postgres-setup.sh` on that machine. On the API server
    - run `export POSTGRES_IP=<ip of that machine>` before running `setup`
