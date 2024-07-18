from flask import Flask
from rest_api.restapi import app as restapi_app
from authentication.auth import auth as auth_app
from databasebackupmanager.rest.api import api as databasebackupmanager_app


app = Flask(__name__)


app.register_blueprint(restapi_app)
app.register_blueprint(databasebackupmanager_app)
app.register_blueprint(auth_app)

if __name__ == '__main__':
    app.run()
