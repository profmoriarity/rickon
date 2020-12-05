from queue import Queue
from threading import Thread
import requests



def download(q):
	while not q.empty():
		file,location = q.get()
		r = requests.get(file.strip())
		file = file.split("?")[0]
		file_name = file.strip().replace("://","_").replace("/","_").replace("?","_")
		print("Downloading",file_name)
		print(r.status_code)
		if r.status_code == 200:
			print(location,file_name)
			with open(location+"/"+file_name, 'wb') as f:
				f.write(r.content)
		q.task_done()

def threaded_download(file, opl, threads):
	q = Queue()
	f = open(file,'r').readlines()
	for x in range(len(f)):
		data = f[x], opl
		q.put(data)
	print(q)
	for i in range(threads):
		worker = Thread(target=download, args=(q,))
		worker.setDaemon(True)
		worker.start()