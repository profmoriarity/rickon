from redis import Redis
from rq import Queue, Worker
from os import system

import time

r = Redis(
    host='139.59.58.6',
    port=7001, 
    password='rickon')




# Returns all workers registered in this connection
redis = r



q = Queue('high',connection=r)  # no args implies the default queue
q.empty()
