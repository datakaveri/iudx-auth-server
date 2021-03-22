import psycopg2

with open("../passwords/auth.db.password", "r") as f:
        pg_password = f.read().strip()

conn_string = "host='localhost' dbname='postgres' user='auth' password='" + pg_password + "'"

try:
        conn = psycopg2.connect(conn_string)

except psycopg2.DatabaseError as error:
        quit()

cursor = conn.cursor()

def expire_token(uuid):

        try:
                cursor.execute("update consent.token set expiry = now() where uuid = '" + uuid + "'")
                conn.commit()
                return True

        except psycopg2.DatabaseError as error:
                return False

