from flask import Flask
from flask_cors import CORS
from flask_restful import Resource, Api, reqparse, marshal, fields

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc, insert, ForeignKey, DateTime, distinct, func
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager
from flask_jwt_extended import JWTManager, create_access_token, verify_jwt_in_request, get_jwt_claims, jwt_required, get_jwt_identity, get_raw_jwt

from functools import wraps
import sys, json, datetime, math

Base = declarative_base()

app = Flask(__name__)
CORS(app, resources={r"*": {"origin" : "*"}})
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://4QM30GS0bR:35wYFCKxFX@remotemysql.com:3306/4QM30GS0bR'
app.config['JWT_SECRET_KEY'] = 'manixmanik-secret-key'


db = SQLAlchemy(app)
migrate = Migrate(app, db)
manager = Manager(app)
manager.add_command('db', MigrateCommand)
jwt = JWTManager(app)

api = Api(app)

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        claims = get_jwt_claims()
        if claims['type'] != 'admin':
            return {'status':'FORBIDDEN'}, 403, {'Content-Type': 'application/json'}
        else:
            return fn(*args, **kwargs)
    return wrapper

def seller_token_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        claims = get_jwt_claims()
        if claims['type'] != 'seller':
            return {'status':'FORBIDDEN'}, 403, {'Content-Type': 'application/json'}
        else:
            return fn(*args, **kwargs)
    return wrapper

class Users(db.Model):
    id = db.Column(db.Integer, primary_key= True)
    username = db.Column(db.String(255), nullable= False)
    email = db.Column(db.String(255), unique= True, nullable= False)
    password = db.Column(db.String(255), nullable= False)
    address = db.Column(db.String(255))
    type = db.Column(db.String(30), nullable = False)
    createdAt = db.Column(db.DateTime, default= db.func.current_timestamp())
    updatedAt = db.Column(db.DateTime, default= db.func.current_timestamp())
    item =  db.relationship('Item', backref='users')

    def __repr__(self):
        return '<Users %r>' % self.id


class Category(db.Model):
    id = db.Column(db.Integer, primary_key= True)
    category = db.Column(db.String(255), nullable = False)
    createdAt = db.Column(db.DateTime, default= db.func.current_timestamp())
    updatedAt = db.Column(db.DateTime, default= db.func.current_timestamp())
    item = db.relationship("Item", backref='category_item')

    def __repr__(self):
        return '<Category %r>' % self.id


class Item(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    itemname = db.Column(db.String(255), nullable= False)
    desc = db.Column(db.String(255))
    category = db.Column(db.Integer, db.ForeignKey("category.id"), nullable= False)
    price = db.Column(db.Integer, nullable = False)
    qty = db.Column(db.Integer)
    url_picture= db.Column(db.String(255))
    createdAt = db.Column(db.DateTime, default= db.func.current_timestamp())
    updatedAt = db.Column(db.DateTime, default= db.func.current_timestamp())
    seller_id= db.Column(db.Integer, db.ForeignKey("users.id"), nullable= False)

    def __repr__(self):
        return '<Item %r>' % self.id


class LoginResource(Resource):

    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', location= 'json', required= True)
        parser.add_argument('password', location= 'json', required= True)

        args = parser.parse_args()

        qry = Users.query.filter_by( username= args['username'], password= args['password']).first()
        
        if qry == None:
            return {"status": "UNAUTHORIZED"}, 401
        
        token = create_access_token(identity= qry.id, expires_delta = datetime.timedelta(days=1))

        return {"token": token}, 200


    @seller_token_required
    def get(self):
        current_user = get_jwt_identity()

        qty= Users.query.get(current_user)
        data = {
            "username": qty.username,
            "email": qty.email,
            "password": qty.password,
            "address": qty.address
        }
        return data, 200


class RegisterResource(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type= str, location='json', required= True, help= 'username must be string and exist')
        parser.add_argument('email', type= str, location='json', required= True, help= 'email must be string and exist')
        parser.add_argument('password', type= str, location='json', required=True, help= 'password must be string and exist')
        parser.add_argument('address', type= str, location='json', required=True, help= 'address must be string and exist')
        parser.add_argument('secret', type= str, location='json', required=False, help= 'secret must be string')

        mySecret = "ADMIN"
        args = parser.parse_args()

        qry= Users.query.filter_by(username= args['username']).first()
        if qry != None:
            return {"status": "Username telah digunakan"}, 406

        qry= Users.query.filter_by(email= args['email']).first()
        if qry != None:
            return {"status": "Email telah digunakan"}, 406

        if(args["secret"] != None and args["secret"] == mySecret):
            auth = 'admin'
        else:
            auth = 'seller'

        data = Users(
                username= args['username'], 
                email= args['email'], 
                password= args['password'], 
                address= args['address'], 
                type= auth
            )

        db.session.add(data)
        db.session.commit()

        token = create_access_token(identity= data.id, expires_delta = datetime.timedelta(days=1))
        return {"status": "SUCCESS" , "token": token}, 200

@jwt.user_claims_loader
def add_claim_to_access_token_uhuyy(identity):
    data = Users.query.get(identity)
    return { "type": data.type }

class SellerResource(Resource):
    item_field= {
        "id": fields.Integer,
        "itemname": fields.String,
        "desc": fields.String,
        "category_item.category": fields.String,
        "price": fields.Integer,
        "qty": fields.Integer,
        "url_picture": fields.String,
        "createdAt": fields.String,
        "updatedAt": fields.String,
        "users.username": fields.String
    }
    
    @seller_token_required
    def get(self, id= None):
        current_user = get_jwt_identity()

        ans = {}
        ans["status"] = "SUCCESS"
        rows = []

        if(id != None):
            qry = Item.query.filter_by(seller_id = current_user, id = id).first()
            if(qry == None):
                return {'status': 'Data not found !!!'}, 404
            rows = marshal(qry, self.item_field)
            ans["data"] = rows
            return ans, 200

        qry = Item.query.filter_by(seller_id = current_user)
        
        for row in qry.all():
            rows.append(marshal(row, self.item_field))
        
        ans["data"] = rows

        return ans, 200

    @seller_token_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("itemname", type= str, help= 'itemname key must be an string and exist', location= 'json', required= True)
        parser.add_argument("desc", type= str, location= 'json')
        parser.add_argument("category", type= str, help= 'category must be an string and exist', location= 'json', required= True)
        parser.add_argument("price", type= int, help= 'price must be an integer and exist', location= 'json', required= True)
        parser.add_argument("qty", type= int, help= 'qty must be an integer and exist', location= 'json', required= True)
        parser.add_argument("url_picture", type= str, help= 'url picture must be an string and exist', location= 'json', required= False, default= 'default pict')
        
        args = parser.parse_args()

        current_user = get_jwt_identity()
        

        data = Item(
                itemname= args["itemname"],
                desc= args["desc"],
                category= args["category"],
                price= args["price"],
                qty= args["qty"],
                url_picture= args["url_picture"],
                seller_id= current_user
            )
        db.session.add(data)
        db.session.commit()

        return {"status": "SUCCESS"}, 200

    @seller_token_required
    def patch(self, id):
        current_user = get_jwt_identity()
        data = Item.query.filter_by(seller_id = current_user, id = id).first()

        if(data == None): 
            return {'status': 'Data not found !!!'}, 404

        parser = reqparse.RequestParser()
        parser.add_argument("itemname", type= str, help= 'itemname key must be an string and exist', location= 'json', required= False)
        parser.add_argument("desc", type= str, location= 'json', required= False)
        parser.add_argument("category", type= str, help= 'category must be an string and exist', location= 'json', required= False)
        parser.add_argument("price", type= int, help= 'price must be an integer and exist', location= 'json', required= False)
        parser.add_argument("qty", type= int, help= 'qty must be an integer and exist', location= 'json', required= False)
        parser.add_argument("url_picture", type= str, help= 'url picture must be an string and exist', location= 'json', required= False)
        
        args = parser.parse_args()

        if args["itemname"] != None:
            data.itemname= args["itemname"]
        if args["desc"] != None:
            data.desc= args["desc"]
        if args["category"] != None:
            data.category= args["category"]
        if args["price"] != None:
            data.price= args["price"]
        if args["qty"] != None:
            data.qty= args["qty"]
        if args["url_picture"] != None:
            data.url_picture= args["url_picture"]
        
        data.updatedAt = db.func.current_timestamp()
        
        db.session.add(data)
        db.session.commit()

        return {"status": "SUCCESS"}, 200

    @seller_token_required
    def delete(self, id):
        current_user = get_jwt_identity()
        data = Item.query.filter_by(seller_id = current_user, id = id).first()

        if data == None:
            return {'status': "Data not found!"}, 404

        db.session.delete(data)
        db.session.commit()
        return {'status': "SUCCESS"}, 200

class PublicResource(Resource):
    item_field= {
        "id": fields.Integer,
        "itemname": fields.String, 
        "desc": fields.String,
        "category": fields.String,
        "price": fields.Integer,
        "qty": fields.Integer,
        "url_picture": fields.String,
        "createdAt": fields.String,
        "updatedAt": fields.String,
        "seller_id": fields.String
    }
    
    def get(self, id = None):

        if(id != None):
            qry = Item.query.get(id)
            if(qry == None):
                return {'status': 'Data not found !!!'}, 404
            ans = {
                "page": 1,
                "total_page": 1,
                "per_page": 25,
                "data": []
            }

            rows = marshal(qry, self.item_field)
            ans["data"] = rows
            return ans, 200

        parser = reqparse.RequestParser()
        parser.add_argument("p", type= int, location= 'args', default= 1)
        parser.add_argument("rp", type= int, location= 'args', default= 25)
        parser.add_argument("id",type= int, help= 'id must be an integer', location= 'args')
        parser.add_argument("itemname",type= str, help= 'itemname must be an string', location= 'args')
        parser.add_argument("desc",type= str, location= 'args')
        parser.add_argument("price",type= int, help= 'price must be an integer', location= 'args')
        parser.add_argument("qty",type= int, help= 'qty must be an integer', location= 'args')
        parser.add_argument("category",type= str, help= 'category must be an string', location= 'args')
        parser.add_argument("orderBy", help= 'invalid orderBy', location= 'args', choices=('id', 'itemname', 'price', 'qty', 'category', 'createdAt', 'updatedAt'))
        parser.add_argument("sort", help= 'invalid sort value', location= 'args', choices=('asc', 'desc'), default = 'asc')

        args = parser.parse_args()

        qry = Item.query

        if args['p'] == 1:
            offset = 0
        else:
            offset = (args['p'] * args['rp']) - args['rp']

        if args['id'] != None:
            qry = qry.filter_by(id = args['id'])
        if args["itemname"] != None:
            qry = qry.filter_by(itemname = args["itemname"]) 
        if args["desc"] != None:
            qry = qry.filter_by(desc = args["desc"]) 
        if args["category"] != None:
            qry = qry.filter_by(category = args["category"]) 
        if args["price"] != None:
            qry = qry.filter_by(price = args["price"]) 
        if args["qty"] != None:
            qry = qry.filter_by(qty = args["qty"]) 

           
        if args['orderBy'] != None:

            if args["orderBy"] == "id":
                field_sort = Item.id
            elif args["orderBy"] == "itemname":
                field_sort = Item.itemname
            elif args["orderBy"] == "price":
                field_sort = Item.price
            elif args["orderBy"] == "qty":
                field_sort = Item.qty
            elif args["orderBy"] == "category":
                field_sort = Item.category
            elif args["orderBy"] == "createdAt":
                field_sort = Item.createdAt
            elif args["orderBy"] == "updatedAt":
                field_sort = Item.updatedAt

            if args['sort'] == 'desc':
                qry = qry.order_by(desc(field_sort))
               
            else:
                qry = qry.order_by(field_sort)

        
        rows= qry.count()
        qry =  qry.limit(args['rp']).offset(offset)
        tp = math.ceil(rows / args['rp'])
        
        ans = {
            "page": args['p'],
            "total_page": tp,
            "per_page": args['rp'],
            "data": []
        }

        rows = []
        for row in qry.all():
            rows.append(marshal(row, self.item_field))

        ans["data"] = rows

        return ans, 200

class CategoryResource(Resource):
    category_field = {
        "category" : fields.String,
        "createdAt" : fields.String,
        "updatedAt" : fields.String
    }

    def get(self):
        data = Category.query
        ans = {
            "status": "SUCCESS",
            "data": []
        }

        rows = []
        for row in data.all():
            rows.append(marshal(row, self.category_field))
        ans["data"] = rows
        return ans, 200
        
    @admin_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("category", type= str, help= 'itemname key must be an string and exist', location= 'json', required= True)
        
        args = parser.parse_args()

        data = Category.query.filter_by(category = args["category"]).first()
        if (data != None):
            return {"status": "Cannot duplicate category"}, 406

        data = Category(
                category= args["category"],
            )
        db.session.add(data)
        db.session.commit()

        return {"status": "SUCCESS"}, 200
    
    @admin_required
    def patch(self, id):
        data = Category.query.get(id)

        if(data == None):
            return {"status": "Data Not Found!"}, 404

        parser = reqparse.RequestParser()
        parser.add_argument("category", type= str, help= 'itemname key must be an string and exist', location= 'json', required= True)
        
        args = parser.parse_args()
        data.category = args['category']
        db.session.add(data)
        db.session.commit()

        return {"status": "SUCCESS"}, 200

    @admin_required
    def delete(self, id):
        data = Category.query.get(id)

        if data == None:
            return {'status': "Data not found!"}, 404

        db.session.delete(data)
        db.session.commit()
        return {'status': "SUCCESS"}, 200


# Endpoints for Users
api.add_resource(LoginResource, '/api/users/login', '/api/users/me')
api.add_resource(RegisterResource, '/api/users/register')

# Endpoints for Sellers
api.add_resource(SellerResource, '/api/users/items', '/api/users/items/<int:id>')

# Endpoints for Public
api.add_resource(PublicResource, '/api/public/items', '/api/public/items/<int:id>' )

# Endpoints Category
api.add_resource(CategoryResource, '/api/public/category', '/api/public/category/<int:id>' )

@jwt.expired_token_loader
def exipred_token_message():
    return json.dumps({"status": "The token has expired"}), 401, {'Content-Type': 'application/json'}

@jwt.unauthorized_loader
def unathorized_message(error_string):
    return json.dumps({'status': error_string}), 401, {'Content-Type': 'application/json'}


if __name__ == "__main__":
    try:
        if sys.argv[1] == 'db':
            manager.run()
    except IndexError as identifier:
        app.run(debug=True, host='0.0.0.0', port=5000)