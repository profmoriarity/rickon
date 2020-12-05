from flask import Blueprint

helper = Blueprint('helper',__name__,template_folder='templates')

from . import views