#!/bin/sh

python3 createdb.py
python3 migrate.py db init
python3 migrate.py db migrate
python3 migrate.py db upgrade
python3 manage.py &
python3 run.py
