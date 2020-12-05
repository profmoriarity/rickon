from redis import Redis
from rq import Queue, Worker, Job
from os import system

import time

r = Redis(
    host='172.105.5.96',
    port=7001, 
    password='rickon')




# Returns all workers registered in this connection
redis = r



q = Queue('high',connection=r)  # no args implies the default queue
for x in q.job_ids:
	print(x)
	job = Job.fetch(x,r) #fetch Job from redis
	print(job.return_value)
