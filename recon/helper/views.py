from recon import db, app
from recon.models import Project, Config, Nuclei, DirScans
import json, os, glob
import datetime
import csv
import uuid
import redis
from rq import Queue, Worker, Connection
import os
from queue import Queue as Que
from threading import Thread
import requests


REDIS_HOST = os.getenv('redis_host', '172.105.5.96')
REDIS_PORT = os.getenv('redis_port', 7001)
REDIS_PASSWORD = os.getenv('redis_password', 'rickon')

r = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT, 
    password=REDIS_PASSWORD)




q = Queue('high',connection=r)


# Returns all workers in this queue (new in version 0.10.0)



def update_timestamp(id, timestamp):
	print("")




def ffuf_scan(output_d, url, output_dir, threads=100, wordlist='./wordlist/quickhits-2000.txt', status_codes='200,401,500',
	op_format='csv',calibration='-ac'):
		outputfile = output_dir + url.split('/')[2].replace(":","_")+".txt"
		command  = 'ffuf -u {}/FUZZ -t {} -w {} -mc {} {} -of {} -o {} -od {}'.format(url, threads, wordlist, status_codes, calibration, op_format, outputfile,output_d)
		executor(command)


def executor(cmd):
	job = q.enqueue(os.system, cmd)

def ts():
	now = datetime.datetime.today() 
	return now.strftime("%d-%m-%Y-%H-%M-%S")
def tsi():
	return datetime.datetime.timestamp(datetime.datetime.now())

def dir_scan_target(id,scanner,wordlist='./wordlists/quickhits-2000.txt'):
	output_d = "data/"+id+"/response-output"
	if not os.path.exists(output_d):
		os.mkdir(output_d)
	f = open("data/{}/alive.txt".format(id), 'r')
	lines = f.readlines()
	now = datetime.datetime.today() 
	nTime = now.strftime("%d-%m-%Y-%H-%M-%S")
	new_scan = DirScans('ffuf_scan_'+nTime, scanner, tsi(), 0, id , False)
	with app.app_context():
		db.session.add(new_scan)
		db.session.commit()
	output_dir = './data/{}/ffuf_scan_{}/'.format(id,nTime)
	for line in lines:
		domain = line.strip()
		if scanner == 'ffuf':
			print(scanner)
			if not os.path.exists(output_dir):
				os.mkdir(output_dir)
			ffuf_scan(output_d,domain,output_dir,100,wordlist,'200,401,400','csv','-ac')


def parse_ffuf(id,dir):
	ffuf_dir = "data/{}/{}/".format(id,dir)
	temp = []
	for file in glob.glob("{}*.txt".format(ffuf_dir)):
		with open(file,'r') as f:
			test = csv.DictReader(f)

			for x in test:
				temp.append(x)
	return temp



def parse_nuclei(id,dir,file,all=False):
	if all is False:
		nuclei_dir = "data/{}/{}/{}".format(id,dir,file)
		temp = []
		with open(nuclei_dir,'r') as f:
				for line in f.readlines():
					try:
						temp.append(json.loads(line.strip()))
					except:
						pass
	else:
		nuclei_dir = "data/{}/{}/*.txt".format(id,dir)
		file_list = glob.glob(nuclei_dir)
		print(nuclei_dir)
		temp = []
		print(file_list)
		for fi in file_list:
			with open(fi,'r') as f:
					for line in f.readlines():
						try:
							temp.append(json.loads(line.strip()))
						except:
							pass
	return temp


def nuclei_scanner(id,templates,threads):
	wordlists = glob.glob("nuclei-templates/*/*.yaml",recursive=True)
	projects = Project.query.limit(100).all()
	if id == 'all':
		for project in projects:
			inp = "data/{}/alive.txt".format(project.id)
			if len(templates) == len(wordlists):
				#scanning all templates
				output = "data/{}/nuclei-output/{}".format(project.id,"nuclei-all-"+ts()+".txt")
				nuclei_command = "nuclei -l {} -t {} -c {} -json -o {}".format(inp,"nuclei-templates",threads,output)
				new_scan = Nuclei(output, 'nuclei', tsi(), 0, id , False)
				with app.app_context():
					db.session.add(new_scan)
					db.session.commit()
				executor(nuclei_command)
			else:
				#scan few templates individually
				for template in templates:
					template_name = template.split('/')[-1].split('.')[0]
					output = "data/{}/nuclei-output/{}".format(project.id,"nuclei-"+template_name+ts()+".txt")
					nuclei_command = "nuclei -l {} -t {} -c {} -json -o {}".format(inp,template,threads,output)
					log = "data/{}/nuclei-output/{}".format(project.id,"nuclei_log.txt")
					fd = open(log,'a')
					fd.write(template+"\n")
					new_scan = Nuclei(output, 'nuclei', tsi(), 0, id , False)
					with app.app_context():
						db.session.add(new_scan)
						db.session.commit()
					executor(nuclei_command)
	else:
		p = Project.query.filter_by(id=id).first()
		inp = "data/{}/alive.txt".format(p.id)
		if len(templates) == len(wordlists):
			#scanning all templates
			output = "data/{}/nuclei-output/{}".format(p.id ,"nuclei-all-"+ts()+".txt")
			nuclei_command = "nuclei -l {} -t {} -c {} -json -o {}".format(inp,"nuclei-templates",threads,output)
			new_scan = Nuclei(output, 'nuclei', tsi(), 0, id , False)
			with app.app_context():
				db.session.add(new_scan)
				db.session.commit()
			executor(nuclei_command)
		else:
			#scan few templates individually
			for template in templates:
				template_name = template.split('/')[-1].split('.')[0]
				output = "data/{}/nuclei-output/{}".format(p.id,"nuclei-"+template_name+"-"+ts()+".txt")
				nuclei_command = "nuclei -l {} -t {} -c {} -json -o {}".format(inp,template,threads,output)
				new_scan = Nuclei(output, 'nuclei', tsi(), 0, id , False)
				with app.app_context():
					db.session.add(new_scan)
					db.session.commit()
				print(nuclei_command)
				log = "data/{}/nuclei-output/{}".format(p.id,"nuclei_log.txt")
				fd = open(log,'a')
				fd.write(template+"\n")
				executor(nuclei_command)

def download(q):
	while not q.empty():
		file,location = q.get()
		r = requests.get(file.strip())
		file = file.split("?")[0]
		file_name = file.strip().replace("://","_").replace("/","_").replace("?","_").replace(".","_")+".js"
		print("Downloading",file_name)
		print(r.status_code)
		if r.status_code == 200:
			print(location,file_name)
			with open(location+"/"+file_name, 'wb') as f:
				f.write(r.content)
		q.task_done()

def threaded_download(file, opl, threads):
	q = Que()
	f = open(file,'r').readlines()
	for x in range(len(f)):
		data = f[x], opl
		q.put(data)
	print(q)
	for i in range(threads):
		worker = Thread(target=download, args=(q,))
		worker.setDaemon(True)
		worker.start()
