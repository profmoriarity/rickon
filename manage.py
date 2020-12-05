import redis, os
from rq import Queue, Worker, Connection
import recon

# Returns alsssl workers registered in this connection

os.chdir('/app/recon')

conn = redis.from_url('redis://:rickon@172.105.5.96:7001')

listen = ['high']

with Connection(conn):
	worker = Worker(map(Queue, listen))
	worker.work()
