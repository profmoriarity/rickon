from flask import Flask, request, render_template, redirect , make_response, url_for
from datetime import datetime
import json
import os
import subprocess
import uuid
from threading import Thread
import random
import glob
from datetime import datetime, timedelta
import timeago, random
from recon.search.views import search_text
from recon.helper.views import dir_scan_target, parse_ffuf, parse_nuclei, executor, nuclei_scanner, threaded_download, ffuf_scan
import redis
from recon import db, app, q
from flask import g
from . import main


		

JS_EXCLUDE = "googletagmanager|jquery|google-analytics|datatables|bootstrap|raven|vannila|lazyload|dojo|angularjs|openui|chart.js|optimizely|heatmap|medium.com|modernizr|slick.min.js|OwlCarousel2"
colors = ['primary','secondary','success','danger','warning','info','light']




from recon.models import Project, DirScans, Nuclei, Config



@main.app_template_filter('date')
def tsTodate(s):
    return datetime.fromtimestamp(s)

@main.app_template_filter('perc')
def perc(s):
	try:
		return ((len(json.loads(s))-2)*5)
	except:
		return 0

@main.app_template_filter('timeago')
def timeagofromnow(s):
	now = datetime.now() + timedelta(seconds = 60 * 3.4)
	return timeago.format(s,now)

@main.app_template_filter('color')
def randomcolor(s):
	return random.choice(s)

def command_scheduler(cmd):
	subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout.read()

def ts():
	return datetime.timestamp(datetime.now())

def update_project(col, val, table, uid):
	with app.app_context():
		if table == 'project':
			obj = Project.query.filter_by(id=uid).first()
			setattr(obj,col,val)
		elif table == 'dirscans':
			obj = DirScans.query.filter_by(id=uid).first()
			setattr(obj,col,val)
		elif table =='nuclei':
			obj = Nuclei.query.filter_by(id=uid).first()
			setattr(obj,col,val)
		elif table == 'config':
			obj = Config.query.filter_by(id=uid).first()
			setattr(obj,col,val)
		else:
			pass
		db.session.commit()

def summary_update(sam, scan, time):
	print(sam)
	jd = json.loads(sam)
	jd[scan] = time
	return json.dumps(jd)

def subdomains(domain,uid,temp_dir):
	print("test")
	sam = json.loads('{}')
	sam['subdomains_start'] = ts()
	sam['status'] = 'in progress'
	cmd = 'subfinder -d '+domain+' -t 100 -o '+temp_dir+'/subdomains_subfinder.txt'
	command_scheduler(cmd)
	cmd = 'shuffledns -d '+domain+' -w ./wordlists/subdomains_commonspeak2.txt -r ./wordlists/resolvers.txt -massdns /root/go/bin/massdns -wt 100 -o '+temp_dir+'/subdomains_shuffledns.txt'
	command_scheduler(cmd)
	cmd = "cat "+temp_dir+"/subdomains_subfinder.txt "+temp_dir+"/subdomains_shuffledns.txt | sort -u | tee "+temp_dir+"/sorted_subdomains.txt"
	command_scheduler(cmd)
	subdomains_count = len(open(temp_dir+'/sorted_subdomains.txt','r').readlines())
	update_project('subdomains',subdomains_count,'project',uid)
	sam['subdomains_end'] = ts()
	update_project('summary_string',json.dumps(sam),'project',uid)
	
def httpinfo(temp_dir,uid):
	with app.app_context():
		p = Project.query.filter_by(id=uid).first()
	summary_string = p.summary_string
	summary_string = summary_update(summary_string, 'httpinfo_start',ts())
	cmd = "httpx -l "+temp_dir+"/subdomains_subfinder.txt -threads 100 -ports 80,443,8080 -vhost -title -content-length -status-code -web-server -timeout 3 -json -o "+temp_dir+"/httpx.json"
	command_scheduler(cmd)
	summary_string = summary_update(summary_string, 'httpinfo_end',ts())
	update_project('summary_string',summary_string,'project',uid)
	a_file = open(temp_dir+'/httpx.json',encoding="utf-8")
	lines = a_file.readlines()
	update_project('subdomains_alive',len(lines),'project',uid)
	newfile = open(temp_dir+'/alive.txt','w')
	for jsonline in lines:
		jdata = json.loads(jsonline.strip())
		url = jdata['url']
		newfile.write(url+"\n")
	newfile.close()

def screenshots(temp_dir, uid):
	with app.app_context():
		p = Project.query.filter_by(id=uid).first()
	summary_string = p.summary_string
	summary_string = summary_update(summary_string, 'screenshot_start',ts())
	screenshots_cmd = "xvfb-run python3 tools/webscreenshot/webscreenshot.py -i "+temp_dir+'/alive.txt --window-size \'1200,800\' -o static/screenshots/'+uid+'/screenshots -w 10 -r chromium --renderer-binary /usr/bin/chromium-browser'
	command_scheduler(screenshots_cmd)
	summary_string = summary_update(summary_string, 'screenshot_end',ts())
	update_project('summary_string',summary_string,'project',uid)

def saveheaderinfo(temp_dir, uid):
	with app.app_context():
		p = Project.query.filter_by(id=uid).first()
	summary_string = p.summary_string
	summary_string = summary_update(summary_string, 'headers_start',ts())
	grab_headers = "parallel -j10 \"echo -n {}\|;curl -Is -m 3 {} | base64 -w 0 ; echo ''\" :::: "+temp_dir+"/alive.txt > "+temp_dir+"/headers_base64.txt"
	command_scheduler(grab_headers)
	summary_string = summary_update(summary_string, 'headers_end',ts())
	update_project('summary_string',summary_string,'project',uid)


def httphistory(domain, uid, temp_dir):
	with app.app_context():
		p = Project.query.filter_by(id=uid).first()
	summary_string = p.summary_string
	summary_string = summary_update(summary_string, 'httphistory_start',ts())
	waybackurls = "hakrawler -plain -url "+domain+" |tee "+temp_dir+"/urls_hakrawler.txt"
	command_scheduler(waybackurls)
	gau = "gau "+domain+" | tee "+temp_dir+"/urls_gau.txt"
	command_scheduler(gau)
	sort = "cat "+temp_dir+"/urls_gau.txt "+temp_dir+"/urls_hakrawler.txt | sort -u | tee "+temp_dir+"/urls_sorted.txt"
	command_scheduler(sort)
	summary_string = summary_update(summary_string, 'httphistory_end',ts())
	update_project('summary_string',summary_string,'project',uid)
	cmd = "httpx -l "+temp_dir+"/urls_sorted.txt -threads 200 -title -content-length -status-code -timeout 3 -json -o "+temp_dir+"/waybackurls.json"
	command_scheduler(cmd)
	

def javascript_scan(temp_dir, uid):
	with app.app_context():
		p = Project.query.filter_by(id=uid).first()
	summary_string = p.summary_string
	summary_string = summary_update(summary_string, 'js_start',ts())
	jsfiles = "subjs -c 100 -t 1 -i "+temp_dir+"/alive.txt | tee "+temp_dir+"/javascript_alive.txt"
	command_scheduler(jsfiles)
	jsfiles = "subjs -c 100 -t 1 -i "+temp_dir+"/urls_sorted.txt | tee "+temp_dir+"/javascript_pages.txt"
	command_scheduler(jsfiles)
	sort = "cat "+temp_dir+"/javascript_pages.txt "+temp_dir+"/javascript_alive.txt | sort -u| grep -Ev '"+JS_EXCLUDE+"' | tee "+temp_dir+"/sorted_js.txt"
	command_scheduler(sort)
	summary_string = summary_update(summary_string, 'js_end',ts())
	update_project('summary_string',summary_string,'project',uid)
	if not os.path.exists(temp_dir+"/js-files"):
		os.mkdir(temp_dir+"/js-files")
	threaded_download(temp_dir+"/sorted_js.txt",temp_dir+"/js-files",20)
	if not os.path.exists(temp_dir+"/js-beautify"):
		os.mkdir(temp_dir+"/js-beautify")
	cmd = 'ls '+temp_dir+'/js-files/ | parallel -j50 "js-beautify -o '+temp_dir+'/js-beautify/{} '+temp_dir+'/js-files/{}"'
	print(command_scheduler)
	command_scheduler(cmd)
	linkfinder_report = "xvfb-run python3 /app/recon/tools/LinkFinder/linkfinder.py -i '"+temp_dir+"/js-beautify/*.js' -o "+temp_dir+"/linkfinder.html"
	print(linkfinder_report)
	command_scheduler(linkfinder_report)

PORT = "80,443"
def portscan(temp_dir, uid):
	with app.app_context():
		p = Project.query.filter_by(id=uid).first()
	summary_string = p.summary_string
	summary_string = summary_update(summary_string, 'portscan_start',ts())
	f = open(temp_dir+"/ips.txt",'r').readlines()
	cmd = "masscan -p"+PORT
	for x in f:
		cmd = cmd + " "+x.strip()
	cmd = cmd + " --rate=10000 | tee "+temp_dir+"/masscan_out.txt"
	command_scheduler(cmd)
	summary_string = summary_update(summary_string, 'portscan_end',ts())
	update_project('summary_string',summary_string,'project',uid)

def stack_analysis(temp_dir, uid):
	with app.app_context():
		p = Project.query.filter_by(id=uid).first()
	summary_string = p.summary_string
	summary_string = summary_update(summary_string, 'sa_start',ts())
	stack_analysis = "LC_ALL=C.UTF-8 wad -u @"+temp_dir+"/alive.txt -f json -o "+temp_dir+"/stack_analysis.txt -v -t 500"
	print(stack_analysis)
	command_scheduler(stack_analysis)
	summary_string = summary_update(summary_string, 'sa_end',ts())
	update_project('summary_string',summary_string,'project',uid)

def basic_scans(temp_dir, uid):
	with app.app_context():
		p = Project.query.filter_by(id=uid).first()
	summary_string = p.summary_string
	summary_string = summary_update(summary_string, 'basic_start',ts())
	cnames = "parallel -j100 \"host -t cname {} | grep 'is an alias'\" :::: "+temp_dir+"/sorted_subdomains.txt | tee "+temp_dir+"/cnames_withalias.txt"
	command_scheduler(cnames)
	summary_string = summary_update(summary_string, 'basic_end',ts())
	update_project('summary_string',summary_string,'project',uid)
	#save ips
	ips = "parallel -j50 'host -t A {}' :::: "+temp_dir+"/sorted_subdomains.txt | grep address | awk '{print $4}' | sort -u | tee "+temp_dir+"/ips.txt"
	command_scheduler(ips)
	dalfox = "#dalfox file "+temp_dir+"/urls_sorted.txt -o "+temp_dir+"/dalfox.txt"
	print(dalfox)
	command_scheduler(dalfox)

def dir_sann(temp_dir, uid):
	with app.app_context():
		p = Project.query.filter_by(id=uid).first()
	summary_string = p.summary_string
	summary_string = summary_update(summary_string, 'dirscan_start',ts())
	dir_scan_target(uid, 'ffuf', './wordlists/ffuf.txt')
	summary_string = summary_update(summary_string, 'dirscan_end',ts())
	update_project('summary_string',summary_string,'project',uid)

def nscan(temp_dir, uid):
	with app.app_context():
		p = Project.query.filter_by(id=uid).first()
	summary_string = p.summary_string
	summary_string = summary_update(summary_string, 'nuclei_start',ts())
	if not os.path.exists(temp_dir+"/nuclei-output"):
		os.mkdir(temp_dir+"/nuclei-output")
	nuclei_scan_dir = "data/{}/nuclei-output/nuclei_log.txt".format(uid)
	if not os.path.exists(nuclei_scan_dir):
		wordlists = glob.glob("nuclei-templates/*/*.yaml",recursive=True)
		stt = "\n".join(wordlists)
		f = open(nuclei_scan_dir,'w')
		f.write(stt)
		f.close()
	output = temp_dir+"/nuclei-output/nuclei-output.txt"
	new_scan = Nuclei(output, 'nuclei', ts(), 0, uid , False)
	with app.app_context():
		db.session.add(new_scan)
		db.session.commit()
	nuclei_command = "nuclei -l {} -t {} -c 100 -json -o {}".format(temp_dir+"/alive.txt", "nuclei-templates",output)
	command_scheduler(nuclei_command)
	summary_string = summary_update(summary_string, 'nuclei_end',ts())
	update_project('summary_string',summary_string,'project',uid)



def final_step(uid):
	with app.app_context():
		p = Project.query.filter_by(id=uid).first()
	summary_string = p.summary_string
	summary_string = summary_update(summary_string, 'status','completed')
	update_project('summary_string',summary_string,'project',uid)
	update_project('status',True,'project',uid)
	update_project('scan_complete',ts(),'project',uid)


def start_scan(domain, description):
	uid = str(uuid.uuid4())
	temp_dir = 'data/{}'.format(uid)
	print(os.getcwd())
	print(temp_dir)
	if not os.path.exists(temp_dir):
		os.mkdir(temp_dir)
	new_project = Project(uid, domain, description, 0, 0, ts(), 0, 0, False,'{"status":"Not started"}')
	with app.app_context():
		db.session.add(new_project)
		db.session.commit()
	job = q.enqueue(subdomains, domain, uid, temp_dir, job_timeout=600)
	print(job)
	job = q.enqueue(httpinfo, temp_dir, uid, job_timeout=600)
	print(job)
	job = q.enqueue(screenshots, temp_dir, uid, job_timeout=600)
	job = q.enqueue(saveheaderinfo, temp_dir, uid, job_timeout=600)
	job = q.enqueue(httphistory, domain, uid, temp_dir, job_timeout=600)
	job = q.enqueue(javascript_scan, temp_dir, uid, job_timeout=600)
	job = q.enqueue(stack_analysis, temp_dir, uid, job_timeout=600)
	job = q.enqueue(basic_scans, temp_dir, uid, job_timeout=600)
	job = q.enqueue(dir_sann, temp_dir, uid, job_timeout=600)
	job = q.enqueue(nscan, temp_dir, uid, job_timeout=600)
	job = q.enqueue(final_step, uid, job_timeout=600)
	job = q.enqueue(portscan, temp_dir, id, job_timeout=600)


@main.route('/basic_scan/<id>', methods=['GET', 'POST'])
def bscan(id):
	if request.method == 'GET':
		temp_dir = "data/"+id
		f = open(temp_dir+"/dalfox.txt",'r').readlines()
		cnames = open(temp_dir+"/cnames_withalias.txt",'r').readlines()
		jd = [x.strip().split(' is an alias for ') for x in cnames]
		xd = [x.strip() for x in f]
		x = { 'cnames': jd ,'dalfox': xd }
		return json.dumps(x)



@main.route('/create', methods=['GET', 'POST'])
def create_project():
	if request.method  == 'GET':
			return render_template("create.html")
	if request.method  == 'POST':
			domain = request.form.get("domain")
			description = request.form.get("description")
			thread = Thread(target=start_scan, args=(domain, description,))
			thread.daemon = True
			thread.start()
			now = datetime.now()
			timestamp = datetime.timestamp(now)
			resp = make_response(redirect(url_for('main.create_project')))
			resp.set_cookie('message', domain+' scanning initiated')
			resp.set_cookie('message_status', 'unread')
			return resp

@main.route('/dir_scan/<id>/<tool>')
def ffuf_scan_results(id,tool='ffuf'):
	if tool == 'ffuf':
		li = glob.glob("data/{}/ffuf_scan_*".format(id))
		scan_results = []
		for l in li:
			scan_results.append(l.split('/')[-1])
		print(scan_results)
		response = app.response_class(
		response=json.dumps(scan_results),
		status=200,
		mimetype='application/json'
	)
	return response


@main.route('/dir_scanner/all/',methods=['GET','POST'])
def dir_scanner(tool='ffuf'):
	wordlists = glob.glob("wordlists/*.txt",recursive=True)
	if request.method == 'GET':
		return render_template("dir_scanner.html",wordlists=wordlists)
	if request.method == 'POST':
		print(request.form.get('wordlist'))
		target = request.form.get('target')
		threads = request.form.get('threads')
		wl = request.form.get('wordlist')
		extensions = request.form.get('extensions')
		tool = request.form.get('tool')
		if tool == 'ffuf':
			job = q.enqueue(ffuf_scan, 'data/raw_data', target, 'data/ffuf_scans/',threads, wl, job_timeout=600)
		return render_template("dir_scanner.html",wordlists=wordlists)


@main.route('/get_scan/<id>/<scan_name>')
def get_scan_results(id,scan_name):
	ffuf_data = parse_ffuf(id,scan_name)
	print(ffuf_data)
	response = app.response_class(
		response=json.dumps(ffuf_data),
		status=200,
		mimetype='application/json'
	)
	return response

@main.route('/linkfinder/<id>/', methods=['GET'])
def showlinkfinder(id):
	return open("data/"+id+"/linkfinder.html").read()



@main.route('/config', methods=['GET', 'POST'])
def config():
	print(request.files)
	if request.method == 'GET':
		return render_template("configuration.html")
	if request.method == 'POST':
		action = request.form.get('action')
		if action == 'template_upload':
			if 'yaml_file' not in request.files:
					return "nope"
			file = request.files['yaml_file']
			if file.filename == '':
					return redirect(request.url)
			file.save(os.path.join('nuclei-templates', request.form.get('file_name')))
			resp = make_response(redirect(url_for('config')))
			resp.set_cookie('Template uploaded')
			resp.set_cookie('message_status', 'unread')
			return resp
		elif action == 'wordlist_upload':
			if 'txt_file' not in request.files:
					pass
			file = request.files['txt_file']
			if file.filename == '':
					return redirect(request.url)
			file.save(os.path.join('wordlists', request.form.get('file_name')))
			resp = make_response(redirect(url_for('config')))
			resp.set_cookie('wordlist uploaded')
			resp.set_cookie('message_status', 'unread')
			return resp
		elif action == 'update':
			executor("nuclei -update-templates -update-directory nuclei-templates")
			resp = make_response(redirect(url_for('config')))
			resp.set_cookie('Updating templates in background')
			resp.set_cookie('message_status', 'unread')
			return resp
		else:
			pass
		return action



@main.route('/nuclei_scan/<id>/', methods=['GET','POST'])
def nuclei_scanner2(id=None):
	if request.method  == 'GET':
		wordlists = glob.glob("nuclei-templates/*/*.yaml",recursive=True)
		stt = "\n".join(wordlists)
		all_projects =  Project.query.limit(100).all()
		if id is not None:
			if id == 'all':
				all = True
				scannable = []
				nuclei_out = []
			else:
				all = False
				nuclei_scan_dir = "data/{}/nuclei-output/nuclei_log.txt".format(id)
				if os.path.exists(nuclei_scan_dir):
					with open(nuclei_scan_dir,'r') as f:
						checklist = f.readlines()
						checklist = [ x.strip("\n") for x in checklist]
					if len(wordlists) == len(checklist):
						scannable = []
					else:
						scannable = list(set(wordlists) - set(checklist))
					print(scannable)
				else:
					f = open(nuclei_scan_dir,'w')
					f.write(stt)
					f.close()
				p = Project.query.filter_by(id=id).first()
				all_projects  = []
				nuclei_out = parse_nuclei(id, 'nuclei-output','nuclei-output.txt',True)
		return render_template("nuclei_scan.html",wordlists=wordlists,scannable=scannable,all=all,all_projects=all_projects,nuclei_out=nuclei_out)
	if request.method  == 'POST':
		wordlists = glob.glob("nuclei-templates/*/*.yaml",recursive=True)
		stt = "\n".join(wordlists)
		template = request.form.get('template')
		if id == 'all':
			project = request.form.get('project')
			print(project)
			if project == 'All Projects':
				#scan all projects
				if template == 'All Templates':
					nuclei_scanner('all',wordlists, 200)
				elif template == 'Unscanned templates Only':
					all_projects =  Project.query.limit(100).all()
					for proj in all_projects:
						nuclei_scan_dir = "data/{}/nuclei-output/nuclei_log.txt".format(proj.id)
						if os.path.exists(nuclei_scan_dir):
							with open(nuclei_scan_dir,'r') as f:
								checklist = f.readlines()
								checklist = [ x.strip("\n") for x in checklist]
							if len(wordlists) == len(checklist):
								scannable = []
							else:
								scannable = list(set(wordlists) - set(checklist))
						nuclei_scanner('all',scannable, 200)
				else:
					word = []
					print("here")
					word.append(template)
					nuclei_scanner('all',word, 200)
			else:
				#scan selected project
				scannable = []
				id = project.split(':')[-1]
				nuclei_scan_dir = "data/{}/nuclei-output/nuclei_log.txt".format(id)
				if os.path.exists(nuclei_scan_dir):
					with open(nuclei_scan_dir,'r') as f:
						checklist = f.readlines()
						checklist = [ x.strip("\n") for x in checklist]
					if len(wordlists) == len(checklist):
						scannable = []
					else:
						scannable = list(set(wordlists) - set(checklist))
				else:
					f = open(nuclei_scan_dir,'w')
					f.write(stt)
					f.close()
				if template == 'All Templates':
					nuclei_scanner(id,wordlists, 200)
				elif template == 'Unscanned templates Only':
					nuclei_scanner(id,scannable, 200)
				else:
					word = []
					word.append(template)
					nuclei_scanner(id,word, 200)
			resp = make_response(redirect(url_for('main.index')))
			resp.set_cookie('message','Nuclei scan initated')
			resp.set_cookie('message_status', 'unread')
			return resp
		else:
			#scan based on id
			wordlists = glob.glob("nuclei-templates/*/*.yaml",recursive=True)
			nuclei_scan_dir = "data/{}/nuclei-output/nuclei_log.txt".format(id)
			if os.path.exists(nuclei_scan_dir):
				with open(nuclei_scan_dir,'r') as f:
					checklist = f.readlines()
					if len(checklist) < 1:
						fr = open(nuclei_scan_dir,'w')
						fr.write(stt)
						fr.close()
					checklist = [ x.strip("\n") for x in checklist]
				if len(wordlists) == len(checklist):
					scannable = []
				else:
					scannable = list(set(wordlists) - set(checklist))
			else:
				f = open(nuclei_scan_dir,'w')
				f.write(stt)
				f.close()
			if template == 'All Templates':
				nuclei_scanner(id,wordlists, 200)
			elif template == 'Unscanned templates Only':
				nuclei_scanner(id,scannable, 200)
			else:
				word = []
				word.append(template)
				nuclei_scanner(id,word, 200)
			resp = make_response(redirect(url_for('main.index')))
			resp.set_cookie('message','Nuclei scan initated')
			resp.set_cookie('message_status', 'unread')
			return resp


@main.route('/content_scan/<id>',methods = ['GET','POST'])
def content_scanner(id):
	if request.method  == 'GET':
		wordlists = glob.glob("wordlists/*.txt",recursive=True)
		p = Project.query.filter_by(id=id).first()
		return render_template("dir_scan.html",id=id,wordlists=wordlists,p=p)
	if request.method  == 'POST':
		tool = request.form.get("tool")
		wl = request.form.get("wl")
		uid = request.form.get("id")
		print(id+wl+tool)
		dir_scan_target(uid, tool, wl)
		resp = make_response(redirect(url_for('main.create_project')))
		resp.set_cookie('message', tool+' scanning initiated')
		resp.set_cookie('message_status', 'unread')
		return resp


@main.route('/getrecent')
def getrecent():
	projects = Project.query.order_by(Project.scan_complete.desc()).limit(4).all()
	print(projects)
	js = []
	for project in projects:
		temp = {'id': project.id, 'domain': project.domain }
		js.append(temp)
	print(js)
	response = app.response_class(
		response=json.dumps(js),
		status=200,
		mimetype='application/json'
	)
	return response


@main.route('/')
def index():
	projects = Project.query.limit(100).all()
	print(projects)
	total_domains = 0
	subs_alive = 0 
	for pro in projects:
		total_domains = total_domains + pro.subdomains
		subs_alive = subs_alive + pro.subdomains_alive
		print(pro.status)
	p_completed = Project.query.filter_by(status=True).count()
	p_inprogress = len(projects) - p_completed
	p_failed = 0
	proj_dict = {
	'p_completed': p_completed,
	'p_inprogress': p_inprogress,
	'p_failed': p_failed,
	'total_domains': total_domains,
	'subs_alive': subs_alive
	}
	print(total_domains)
	return render_template("index.html", jsondata=projects,proj_dict=proj_dict)


@main.route('/debugger/<id>',methods=['GET', 'POST'])
def debug_ep(id):
	temp_dir = "data/"+id+"/"
	job = q.enqueue(basic_scans, temp_dir, id,  job_timeout=600)
	return ""


@main.route('/grep',methods=['GET', 'POST'])
def grep_response():
	print(request.form.get)
	stri = request.form.get("search_str")
	above = request.form.get("above")
	below = request.form.get("below")
	id = request.form.get("id")
	type = request.form.get("type")
	out = search_text(id+"/"+type, stri, above, below)
	return json.dumps(out)

@main.route('/waybackurls/<id>',methods=['GET', 'POST'])
def urlwb(id):
	temp_dir = "data/"+id
	offset = int(request.args.get('offset'))
	page = int(request.args.get('page'))
	f = open(temp_dir+"/waybackurls.json", 'r')
	httpx = [json.loads(x) for x in f.readlines()]
	out = [httpx[x] for x in range(page,page+offset)]
	return json.dumps(out)


@main.route('/details/')
@main.route('/details/<id>')
@main.route('/details/<id>/<item>')
def getProject(id=None,item=None):
	result = Project.query.filter_by(id=id).first()
	id =  result.id
	if result.status == True:
		screenshot_dir = "static/screenshots/"+id+"/screenshots/*.png"
		mylist = [f for f in glob.glob(screenshot_dir)]
		f = open("data/"+id+"/httpx.json", "r",encoding="utf-8")
		httpx = [json.loads(x) for x in f.readlines()]
		x = open("data/"+id+"/stack_analysis.txt","r")
		di =  json.loads(x.read())
		newlist = []
		for y in httpx:
			try:
				url = y['url']+"/"
				y['stack'] = di[url]
				newlist.append(y)
			except:
				newlist.append(y)
		print(json.dumps(newlist,sort_keys=True, indent=4))	
		nuclei_out = parse_nuclei(id, 'nuclei-output','nuclei-output.txt')
		print(nuclei_out)
		templates = [x['template'] for x in nuclei_out]
		print(templates)
	else:
		newlist = []
		nuclei_out= []
		mylist = []
	sam_str = json.loads(result.summary_string)
	print(sam_str)
	return render_template("content.html", result=result,summary=sam_str,screenshots=mylist,httpdata=newlist,colors=colors,nuclei_out=nuclei_out)


"""


@main.route('/details/')
@main.route('/details/<id>')
@main.route('/details/<id>/<item>')
def getProject(id=None,item=None):
	result = Project.query.filter_by(id=id).first()
	id =  result.id
	if result.status == True:
		screenshot_dir = "static/screenshots/"+id+"/screenshots/*.png"
		mylist = [f for f in glob.glob(screenshot_dir)]
		f = open("data/"+id+"/httpx.json", "r",encoding="utf-8")
		httpx = [json.loads(x) for x in f.readlines()]
		x = open("data/"+id+"/stack_analysis.txt","r")
		di =  json.loads(x.read())
		newlist = []
		for y in httpx:
			try:
				url = y['url']+"/"
				y['stack'] = di[url]
				newlist.append(y)
			except:
				newlist.append(y)
		print(json.dumps(newlist,sort_keys=True, indent=4))	
		nuclei_out = parse_nuclei(id, 'nuclei-output','nuclei-output.txt')
		print(nuclei_out)
		templates = [x['template'] for x in nuclei_out]
		print(templates)
	else:
		newlist = []
		nuclei_out= []
		mylist = []
	sam_str = json.loads(result.summary_string)
	print(sam_str)
	return render_template("content.html", result=result,summary=sam_str,screenshots=mylist,httpdata=newlist,colors=colors,nuclei_out=nuclei_out)

@main.route('/details/ajax/')
@main.route('/details/ajax/<id>')
@main.route('/details/ajax/<id>')
def getProject(id=None,item=None):
	result = Project.query.filter_by(id=id).first()
	id =  result.id
	sam_str = json.loads(result.summary_string)
	print(sam_str)
	return render_template("content2.html", id=id,summary=sam_str)
"""
