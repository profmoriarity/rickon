import os
from recon import app

os.chdir('/app/recon/')
os.system('python3 /app/recon/createdb.py')
os.system('python3 /app/recon/migrate.py db init')
os.system('python3 /app/recon/migrate.py db migrate')
os.system('python3 /app/recon/migrate.py db upgrade')
