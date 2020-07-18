from flask import Flask, request, jsonify, make_response   
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid 
import jwt
import datetime
from functools import wraps
import os
import random
import string


file_path = os.path.abspath(os.getcwd())+"\Bank.db"
app = Flask(__name__) 
app.config['SECRET_KEY']='sha256$jYcWLXKs$e923f0a707216ba5b86b65f1c817d7e508d597fc777a5c6d2ca299fdd99efaf0'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///'+file_path 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True 

db = SQLAlchemy(app)   

class Users(db.Model):
  __tablename__ = 'users' 
  id = db.Column(db.Integer, primary_key=True)
  public_id = db.Column(db.Integer)  
  name = db.Column(db.String(50))
  password = db.Column(db.String(50))
  phone_no = db.Column(db.String(12))
  email = db.Column(db.String(50))

class User_Tickets(db.Model):
  __tablename__ = 'user_tickets'
  id = db.Column(db.Integer, primary_key=True)
  ticket = db.Column(db.String(50), unique=True, nullable=False)
  # Services = db.Column(db.String(50), unique=True, nullable=False)
  branch_id = db.Column(db.String(50), unique=True, nullable=False)
  user_id = db.Column(db.Integer)

  def __init__(self, name):
    self.ticket = ticket
  def serialize(self):
    return {"id": self.id,"ticket": self.ticket ,"branch_id":self.branch_id , "user_id":self.user_id}

def token_required(f):  
    @wraps(f)  
    def decorator(*args, **kwargs):
       token = None 
       if 'x-access-tokens' in request.headers:  
          token = request.headers['x-access-tokens'] 
       if not token:  
          return jsonify({'message': 'a valid token is missing'})   
       try:  
          data = jwt.decode(token, app.config['SECRET_KEY']) 
          current_user = Users.query.filter_by(public_id=data['public_id']).first()  
       except:  
          return jsonify({'message': 'token is invalid'})  
          return f(current_user, *args,  **kwargs)  
    return decorator 


        

@app.route('/register', methods=['GET', 'POST'])
def signup_user():  
 data = request.get_json()  
 print("New User post data....",data)
 hashed_password = generate_password_hash(data['password'], method='sha256')
 
 new_user = Users(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, phone_no =data['phone_no'],email=data['email']) 
 print("New User Created....",new_user)
 db.session.add(new_user)  
 db.session.commit()    

 return jsonify({'message': 'registered successfully'})   


@app.route('/login', methods=['GET', 'POST'])  
def login_user(): 
 
  auth = request.authorization   

  if not auth or not auth.username or not auth.password:  
     return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})    

  user = Users.query.filter_by(name=auth.username).first()   
     
  if check_password_hash(user.password, auth.password):  
     token = jwt.encode({'public_id': user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])  
     return jsonify({'token' : token.decode('UTF-8')}) 

  return make_response('could not verify',  401, {'WWW.Authentication': 'Basic realm: "login required"'})


@app.route('/user', methods=['GET'])
def get_all_users():  
   
   users = Users.query.all() 

   result = []   

   for user in users:   
       user_data = {} 
       user_data['public_id'] = user.public_id    
       user_data['name'] = user.name 
       user_data['password'] = user.password
       user_data['phone_no'] = user.phone_no 
       user_data['email'] = user.email 


       result.append(user_data)   

   return jsonify({'users': result})  


def get_random_string(stringLength=8):
    lettersAndDigits = string.ascii_uppercase + string.digits
    return ''.join((random.choice(lettersAndDigits) for i in range(stringLength)))

@app.route('/gentik', methods=['GET', 'POST'])
@token_required
def add_ticket():
  print(dir(request))
  return None
  # gen_ticket = str(get_random_string(4))
  # branch_id = request.json['branch_id']
  # user_id = "abc"
  # print(gen_ticket, branch_id,user_id)
  # new_ticket = User_Tickets(gen_ticket, branch_id,user_id)
  # print(new_ticket)
  # db.session.add(new_ticket)
  # db.session.commit()
  # return jsonify(new_ticket)


# def add_ticket(current_user):
#   print(request.json)
#   gen_ticket = get_random_string(4)
#   branch_id = request.json['branch_id']
#   user_id = current_user.id
#   print("Helllllllooooooooooooo--2")
#   print(gen_ticket, branch_id,user_id)
#   new_ticket = User_Tickets(gen_ticket, branch_id,user_id)
#   print(new_ticket)
#   db.session.add(new_ticket)
#   db.session.commit()
#   return jsonify(new_ticket)

@app.route('/', methods=['GET', 'POST'])
@token_required
def signal(current_user):
    if request.method == 'POST':
        content = request.get_json()
        return jsonify(current_user.id)
    else:
        return 'Hello, world!'
    return jsonify(current_user.id)

if __name__ == '__main__':
    if not os.path.exists('Bank.db'):
        db.create_all()
    app.run(debug=True)


