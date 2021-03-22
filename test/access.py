from consent import provider_reg
from add_org import add_organization
import psycopg2
import random, string

name = { "title"        : "Mr.",
         "firstName"    : "Testing",
         "lastName"     : "Testing"
         }

csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIICjDCCAXQCAQAwRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQK\nDAtNeU9yZywgSW5jLjEVMBMGA1UEAwwMbXlkb21haW4uY29tMIIBIjANBgkqhkiG\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyhF2a5PeL72zGdL47/6zVQQQtZJcO01iVbjR\nSSyswUa2jcfYfoQEVKo1JAz25G3nYfSW1Te3OWjuihvPhZeatFSUwTxcZJFxzIWm\n4/gOQIhJKCA/Wry3liW2sjIGLuHxeH2BoQCIEZyYcqVpRWEJ9RusRFcwPgvROigh\nhMXhgE86uaIRs0yPqzhc7sl53T4qx6qvQJ6uTXBWBvUELgSSgeyaT0gwU1mGmPck\n7Svo6tsWfBFfgT5Ecbqsc2nqChAExgocp5tkPJYcy8FB/tU/FW0rFthqecSvMrpS\ncZW9+iyzseyPrcK9ka6XSlVu9EoX82RW7SRyRL2T5VN3JemXfQIDAQABoAAwDQYJ\nKoZIhvcNAQELBQADggEBAJRFEYn6dSzEYpgYLItUm7Sp3LzquJw7QfMyUvsy45rp\n0VTdQdYp/hVR2aCLiD33ht4FxlhbZm/8XcTuYolP6AbF6FldxWmmFFS9LRAj7nTV\ndU1pZftwFPp6JsKUCYHVsuxs7swliXbEcBVtD6QktzZNrRJmUKi38DAFcbFwgLaM\nG/iRIm4DDj2hmanKp+vUWjXfj13naa7bDtIlzW96y24jsu+naabg8MVShfGCStIv\nrX3T2JkkSjpTw7YzIpgI8/Zg9VR1l0udvfh9bn7mjmOYc3EYwJKvuJDn1TzVuIIi\n9NmVasTjhZJ0PyWithWuZplo/LXUwSoid8HVyqe5ZVI=\n-----END CERTIFICATE REQUEST-----\n"

with open("../passwords/auth.db.password", "r") as f:
        pg_password = f.read().strip()

conn_string = "host='localhost' dbname='postgres' user='auth' password='" + pg_password + "'"

try:
        conn = psycopg2.connect(conn_string)

except psycopg2.DatabaseError as error:
        quit()

cursor = conn.cursor()

# create a provider role for the email address
def init_provider(email):
        
        org_domain = email.split('@')[1]

        org_id = add_organization(org_domain)

        try:
                # deletes all rules also
                cursor.execute("delete from consent.users where users.email = '" + email + "'")
                conn.commit()

        except psycopg2.DatabaseError as error:
                return {}

        r = provider_reg(email, '7529547992', name , org_id, csr)

        try:
                cursor.execute("update consent.role as rr set status = 'approved' from consent.users where " + " users.id = rr.user_id and users.email = '" + email + "'")
                conn.commit()

        except psycopg2.DatabaseError as error:
                return {}

def reset_role(email):
# set all roles with this email as rejected
        
        try:
                cursor.execute("delete from  consent.users where  users.email = '" + email + "'")
                conn.commit()

        except psycopg2.DatabaseError as error:
            print(error)
            return False
        
        return True 

def expire_rule(access_id):
        try:
                cursor.execute("update consent.access set expiry = NOW() where id = " + str(access_id))
                conn.commit()

        except psycopg2.DatabaseError as error:
            print(error)
            return False
        
        return True 
