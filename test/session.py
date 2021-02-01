import psycopg2

with open("../passwords/auth.db.password", "r") as f:
        pg_password = f.read().strip()

conn_string = "host='localhost' dbname='postgres' user='auth' password='" + pg_password + "'"

try:
        conn = psycopg2.connect(conn_string)

except psycopg2.DatabaseError as error:
        quit()

cursor = conn.cursor()

def fetch_sessionId(email):

        try:
                cursor.execute("select session_id from consent.session, consent.users where users.email = '"+ email
                         +   "' and users.id = session.user_id ORDER BY session.created_at DESC LIMIT 1")
                
                oid = cursor.fetchone()[0]

                return oid
        except psycopg2.DatabaseError as error:
                return error

        

