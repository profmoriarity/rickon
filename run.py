import os
from recon import app

os.chdir('/app/recon/')
# Returns all workers registered in this connection

if __name__ == '__main__':
    app.run(host="0.0.0.0",port=5000)

