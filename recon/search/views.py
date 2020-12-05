import glob
import os, re




#simple file search
def search_text(dir, stri, above, below):
	print("data/"+dir+"/**/*")
	files = glob.glob("data/"+dir+"/*", recursive=True)
	result = []
	print(files)
	print(dir, stri, above, below)
	for file in files:
		if not os.path.isdir(file):
			print(file)
			f = open(file,'r',encoding="latin-1")
			li =  f.readlines()
			for idx,l in enumerate(li):
				temp = [] 
				if re.search(stri, l):
					print(l)
					for x in range(idx-int(above), idx+int(below)):
							space = " "* (4 - len(str(x)))
							try:
								if x > -1:
									if stri in li[x]:
										z = li[x].replace(stri, '<mark>'+stri+'</mark>')
									else:
										z = li[x]
									y = str(x)+space+z.replace('\n', '')
									temp.append(y)
							except:
								pass
				if len(temp) > 0:
					dum = { file: temp }
					result.append(dum)			
		else:
			print("failure")
	return result


