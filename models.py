from run import db
from passlib.hash import pbkdf2_sha256 as sha256

class UserModel(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(120), unique = True, nullable = False)
    password = db.Column(db.String(120), nullable = False)
    phone_no = db.Column(db.String(12),unique = True, nullable = False)
    email = db.Column(db.String(50),unique = True, nullable = False)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()
    
    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username = username).first()
    
    @classmethod
    def return_all(cls):
        def to_json(x):
            return {
                'username': x.username,
                'password': x.password,
                'phone_no':x.phone_no,
                'email':x.email
            }
        return {'users': list(map(lambda x: to_json(x), UserModel.query.all()))}

    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete()
            db.session.commit()
            return {'message': '{} row(s) deleted'.format(num_rows_deleted)}
        except:
            return {'message': 'Something went wrong'}

    @staticmethod
    def generate_hash(password):
        return sha256.hash(password)
    
    @staticmethod
    def verify_hash(password, hash):
        return sha256.verify(password, hash)

class RevokedTokenModel(db.Model):
    __tablename__ = 'revoked_tokens'
    id = db.Column(db.Integer, primary_key = True)
    jti = db.Column(db.String(120))
    
    def add(self):
        db.session.add(self)
        db.session.commit()
    
    @classmethod
    def is_jti_blacklisted(cls, jti):
        query = cls.query.filter_by(jti = jti).first()
        return bool(query)

class BranchModel(db.Model):
    """
    Contains branch information of the Bank.
    A Bank has many branches : ManyToOne Rel to Bank
    """
    __tablename__ = 'branch'
    id = db.Column(db.Integer, primary_key = True)
    ifsc = db.Column(db.String(20))
    branch_name =  db.Column(db.String(120))
    address =  db.Column(db.String(120))
    city =  db.Column(db.String(120))
    district =  db.Column(db.String(120))
    state =  db.Column(db.String(120))


    def __init__(self, ifsc, branch_name, address,city,district,state):
        self.ifsc = ifsc
        self.branch_name = branch_name
        self.address = address
        self.city = city
        self.district = district
        self.state = state

    def json(self):
        return {'BranchId':self.id,'ifsc': self.ifsc, 'branch_name': self.branch_name, 'address': self.address,'city': self.city,'district': self.district,'state': self.district}

    # @classmethod
    # def find_by_ifsc(cls):
    #     return cls.query.first()  # simple TOP 1 select

    @classmethod
    def find_by_ifsc(cls, ifsc):
        return cls.query.filter_by(ifsc=ifsc).first()  # simple TOP 1 select

    def save_to_db(self):  # Upserting data
        db.session.add(self)
        db.session.commit()  # Balla

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()


class ServicesModel(db.Model):
    """
    Contains Services information of the Bank.
    A Bank has many branches : ManyToOne Rel to Bank
    """
    __tablename__ = 'services'
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(20))


    def __init__(self, name):
        self.name = name

    def json(self):
        return {'ServiceId':self.id,'ServiceName': self.name}

    def save_to_db(self):  # Upserting data
        db.session.add(self)
        db.session.commit() 
