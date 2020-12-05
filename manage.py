import redis, os
from rq import Queue, Worker, Connection
import recon

# Returns alsssl workers registered in this connection

os.chdir('/app/recon')

conn = redis.from_url('redis://:rickon@139.59.58.6:7001')

listen = ['high']

with Connection(conn):
	worker = Worker(map(Queue, listen))
	worker.work()
