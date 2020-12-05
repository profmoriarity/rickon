from flask import Flask, Blueprint
from flask_sqlalchemy import SQLAlchemy
import redis, os
from rq import Queue, Worker, Connection
from flask_rq2 import RQ



db = SQLAlchemy()

rq = RQ()


REDIS_HOST = os.getenv('redis_host', '172.105.5.96')
REDIS_PORT = os.getenv('redis_port', 7001)
REDIS_PASSWORD = os.getenv('redis_password', 'rickon')
PSQL_HOST  = os.getenv('psql_host', '172.105.5.96')
PSQL_USER =  os.getenv('psql_user', 'postgres')
PSQL_PASSWORD =  os.getenv('psql_password', 'mysecretpassword')


PSQL_DBNAME = os.getenv('psql_db', 'recon3')
r = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT, 
    password=REDIS_PASSWORD)


q = Queue('high',connection=r)



app = Flask(__name__)
DB_URL = 'postgresql+psycopg2://{}:{}@{}/{}'.format(PSQL_USER,PSQL_PASSWORD,PSQL_HOST,PSQL_DBNAME)
app.config['SQLALCHEMY_DATABASE_URI'] = DB_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # silence the deprecation warning
app.config['RQ_REDIS_URL'] = 'redis://:{}@{}:{}'.format(REDIS_PASSWORD,REDIS_HOST,REDIS_PORT)
app.config['RQ_QUEUES'] = ['default']



db.init_app(app)



from .main import main
from .helper import helper
app.register_blueprint(main)
app.register_blueprint(helper)


