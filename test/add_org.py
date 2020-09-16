import psycopg2

with open("../passwords/auth.db.password", "r") as f:
        pg_password = f.read().strip()

conn_string = "host='localhost' dbname='postgres' user='auth' password='" + pg_password + "'"

try:
        conn = psycopg2.connect(conn_string)

except psycopg2.DatabaseError as error:
        quit()

cursor = conn.cursor()

def add_organization(website):

        try:
                cursor.execute("select id from consent.organizations where website = '" + website + "'")
                conn.commit()

        except psycopg2.DatabaseError as error:
                return {}
 
        if cursor.rowcount == 0:
                try:
                        cursor.execute("insert into consent.organizations (name,website,city,state,country,created_at,updated_at) values ('Testing Org', '" + website + "', 'testing-city', 'TA', 'TS', now(), now()) returning id")
                        conn.commit()

                except psycopg2.DatabaseError as error:
                        return {}

        oid = cursor.fetchone()[0]
        return oid
