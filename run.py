from flask import Flask
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
import os

file_path = os.path.abspath(os.getcwd())+"\Store.db"
app = Flask(__name__)
api = Api(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+file_path 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'sha256$jYcWLXKs$e923f0a707216ba5b86b65f1c817d7e508d597fc777a5c6d2ca299fdd99efaf0'
# print(app.config['SQLALCHEMY_DATABASE_URI'])
db = SQLAlchemy(app)

@app.before_first_request
def create_tables():
    db.create_all()

app.config['JWT_SECRET_KEY'] = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwdWJsaWNfaWQiOiIzZjZ'
jwt = JWTManager(app)

app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return models.RevokedTokenModel.is_jti_blacklisted(jti)

import views, models, resources

api.add_resource(resources.UserRegistration, '/registration')
api.add_resource(resources.UserLogin, '/login')
api.add_resource(resources.UserLogoutAccess, '/logout/access')
api.add_resource(resources.UserLogoutRefresh, '/logout/refresh')
api.add_resource(resources.TokenRefresh, '/token/refresh')
api.add_resource(resources.AllUsers, '/users')
api.add_resource(resources.SecretResource, '/secret')
api.add_resource(resources.GenerateTIcketResource,'/genticket')
 #http://192.168.29.82:5000/branch/HDFC0003676
api.add_resource(resources.BankBranch,'/branch/<ifsc>')
# api.add_resource(resources.BankBranch,'/branch/<ifsc>')
api.add_resource(resources.BranchList,'/allbranches')
api.add_resource(resources.BankServices,'/services')
api.add_resource(resources.GetBranchDetails,'/getbranchesbyifsc/<ifsc>')
#http://127.0.0.1:5000/getbranchesbyifsc/UK-B-20057405 


