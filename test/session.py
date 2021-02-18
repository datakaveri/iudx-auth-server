import psycopg2
import json

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

# ALL_SECURE_ENDPOINTS_BODY is the request for all secure
# endpoints in the format in which the get-session-id API requires

f = open('../2factor_config.json')
data = json.load(f)
ALL_SECURE_ENDPOINTS_BODY = {"apis":[]}

for endpoint in data['secured_endpoints']:
        for method in data['secured_endpoints'][endpoint]:
            ALL_SECURE_ENDPOINTS_BODY['apis'].append({"endpoint":endpoint, "method":method})
