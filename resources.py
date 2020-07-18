from flask_restful import Resource, reqparse
from models import UserModel, RevokedTokenModel,BranchModel ,ServicesModel
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)
import random
import string
import json

parser = reqparse.RequestParser()
parser.add_argument('username', help = 'This field cannot be blank', required = True)
parser.add_argument('password', help = 'This field cannot be blank', required = True)
parser.add_argument('phone_no')
parser.add_argument('email')

class UserRegistration(Resource):
    def post(self):
        data = parser.parse_args()
        
        if UserModel.find_by_username(data['username']):
            return {'message': 'User {} already exists'.format(data['username'])}
        
        new_user = UserModel(
            username = data['username'],
            password = UserModel.generate_hash(data['password']),
            phone_no = data['phone_no'],
            email = data['email']
        )
        
        try:
            new_user.save_to_db()
            access_token = create_access_token(identity = data['username'])
            refresh_token = create_refresh_token(identity = data['username'])
            return {
                'message': 'User {} was created'.format(data['username']),
                'access_token': access_token,
                'refresh_token': refresh_token
                }
        except:
            return {'message': 'Something went wrong'}, 500


class UserLogin(Resource):
    def post(self):
        data = parser.parse_args()
        current_user = UserModel.find_by_username(data['username'])
        if not current_user:
            return {'message': 'User {} doesn\'t exist'.format(data['username'])}
        
        if UserModel.verify_hash(data['password'], current_user.password):
            access_token = create_access_token(identity = data['username'])
            refresh_token = create_refresh_token(identity = data['username'])
            return {
                'message': 'Logged in as {}'.format(current_user.username),
                'access_token': access_token,
                'refresh_token': refresh_token
                }
        else:
            return {'message': 'Wrong credentials'}


class UserLogoutAccess(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti = jti)
            revoked_token.add()
            return {'message': 'Access token has been revoked'}
        except:
            return {'message': 'Something went wrong'}, 500


class UserLogoutRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti = jti)
            revoked_token.add()
            return {'message': 'Refresh token has been revoked'}
        except:
            return {'message': 'Something went wrong'}, 500


class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity = current_user)
        return {'access_token': access_token}


class AllUsers(Resource):
    def get(self):
        return UserModel.return_all()
    
    def delete(self):
        return UserModel.delete_all()


class SecretResource(Resource):
    @jwt_required
    def get(self):
        return {
            'answer': 42
        }

def get_random_string(stringLength=8):
    lettersAndDigits = string.ascii_uppercase + string.digits
    return ''.join((random.choice(lettersAndDigits) for i in range(stringLength)))

class GenerateTIcketResource(Resource):
    @jwt_required
    def get(self):
        gen_ticket = get_random_string(4)
        return {'Ticket': gen_ticket}

class GetAllBranchs(Resource):
    def get(self):
        pass 

class BankBranch(Resource):
    parser = reqparse.RequestParser()  # only allow price changes, no branch_name changes allowed
    parser.add_argument('ifsc', type=str, required=True, help='This field cannot be left blank')
    parser.add_argument('branch_name', type=str, required=True, help='Must enter the branch name')
    parser.add_argument('address', type=str, required=True, help='This field cannot be left blank')
    parser.add_argument('city', type=str, required=True, help='Must enter city name')
    parser.add_argument('district', type=str, required=True, help='This field cannot be left blank')
    parser.add_argument('state', type=str, required=True, help='Must enter the state name')

    # @jwt_required()  # Requires dat token
    # def get(self):
    #     branch = BranchModel.find_by_ifsc()
    #     if branch:
    #         return branch.json()
    #     return {'message': 'Branch not found'}, 404

    # # @jwt_required()  # Requires dat token
    def get(self, ifsc):
        branch = BranchModel.find_by_ifsc(ifsc)
        if branch:
            return branch.json()
        return {'message': 'Branch not found'}, 404

    # @jwt_required()
    def post(self):
        data = BankBranch.parser.parse_args()
        if BranchModel.find_by_ifsc(data["ifsc"]):
            return {'message': "An branch with ifsc '{}' already exists.".format(data["ifsc"])}, 400

        # data = BankBranch.parser.parse_args()
        branch = BranchModel(data["ifsc"],data['branch_name'],data['address'], data['city'],data['district'], data['state'])

        try:
            branch.save_to_db()
        except:
            return {"message": "An error occurred inserting the branch."}, 500
        return branch.json(), 201

    # @jwt_required()
    def delete(self, ifsc):

        branch = BranchModel.find_by_ifsc(ifsc)
        if branch:
            branch.delete_from_db()

            return {'message': 'branch has been deleted'}



class BranchList(Resource):
    def get(self):
        with open('branches.json') as f:
            data = json.load(f)
        print("*************************************RESULT***************************")
        print(len(data['data']))
        return data
        # return {'Branches': [branch.json() for branch in BranchModel.query.all()]} #More pythonic
        ##return {'items': list(map(lambda x: x.json(), BranchModel.query.all()))} #Alternate Lambda way

class GetBranchDetails(Resource):
    @jwt_required
    def get(self,ifsc):
        with open('branches.json') as f:
            data = json.load(f)
        record = (data['data'][0]['Brand'][0]['Branch'])
        for item in range(len(record)):
            if record[item]['Identification'] == ifsc:
                return record[item]

class BankServices(Resource):
    parser = reqparse.RequestParser()  # only allow price changes, no branch_name changes allowed
    parser.add_argument('name', type=str, required=True, help='This field cannot be left blank')

    # @jwt_required()
    def post(self):
        data = BankServices.parser.parse_args()
        service = ServicesModel(data['name'])

        try:
            service.save_to_db()
        except:
            return {"message": "An error occurred inserting the branch."}, 500
        return service.json(), 201
        
    def get(self):
        return {'ResponseData': [service.json() for service in ServicesModel.query.all()]},200