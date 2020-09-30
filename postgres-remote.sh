# setup postgresql

# AFTER INSTALLATION, BEFORE SETTING UP AUTH SERVER
# -------------------------------------------------
# Update postgres to accept remote connections
# in postgresql.conf, set listen_address = '*'
#
# in pg_hba.conf add
# host      all     postgres        <authIP(in CIDR)> or 0.0.0.0/0        trust
#
# WARNING : REMOVE ABOVE LINE AFTER SETUP. This is required to setup the
# schema and users from the Auth machine by logging into Postgres as the
# admin user. Once setup is done, the line must be removed.
#
# in pg_hba.conf
# host      all     all             <authIP(in CIDR)> or 0.0.0.0/0        md5
# This allows other users to connect to Postgres if they have a password

apt install -y postgresql postgresql-contrib
apt install -y libpq-dev

# TODO : change 12
until pg_isready
do
	pg_ctlcluster 12 main start
	sleep 1
done

