# setup postgresql
apt install -y postgresql postgresql-contrib
apt install -y libpq-dev

# TODO : change 12
until pg_isready
do
	pg_ctlcluster 12 main start
	sleep 1
done

# Update postgres to accept remote connections
# in postgresql.conf, set listen_address = '*'
# in pg_hba.conf add
# host      all     postgres        IP(in CIDR) or 0.0.0.0/0        trust
# TODO : REMOVE ABOVE LINE AFTER SETUP
# host      all     all             IP(in CIDR) or 0.0.0.0/0        md5
# This allows other users to connect if they have a password
