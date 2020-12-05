import psycopg2
import os
#establishing the connection
os.chdir('/app/recon/')

PSQL_HOST  = os.getenv('psql_host', '172.105.5.96')
PSQL_USER =  os.getenv('psql_user', 'postgres')
PSQL_PASSWORD =  os.getenv('psql_password', 'mysecretpassword')

conn = psycopg2.connect(
   database="postgres", user='postgres', password=PSQL_PASSWORD, host=PSQL_HOST, port= '5432'
)
conn.autocommit = True

#Creating a cursor object using the cursor() method
cursor = conn.cursor()

#Preparing query to create a database
sql = '''CREATE database recon3''';

#Creating a database
cursor.execute(sql)
print("Database created successfully........")

#Closing the connection
conn.close()
