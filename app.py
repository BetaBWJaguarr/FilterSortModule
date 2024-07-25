from flask import Flask
from rest_api.restapi import app as restapi_app
from authentication.auth import auth as auth_app, limiter
from databasebackupmanager.rest.api import api as databasebackupmanager_app
from flask_limiter import Limiter
import configparser



app = Flask(__name__)


limiter.init_app(app)


app.register_blueprint(restapi_app)
app.register_blueprint(databasebackupmanager_app)
app.register_blueprint(auth_app)

config = configparser.ConfigParser()
config.read('config.ini')

app.config['SECRET_KEY'] = config.get('security', 'secret_key')

if __name__ == '__main__':
    app.run()
