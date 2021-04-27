from flask import Flask, request
from flask_mail import Mail, Message
from flask_restful import Api, Resource, reqparse, abort, fields, marshal_with
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required,  get_jwt_identity)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import NoResultFound
from sqlalchemy.sql.expression import func
from flask_jwt_extended import JWTManager, get_jwt
import pandas as pd
from google_trans_new import google_translator
from smtplib import SMTPException
from private import *
from models import *

app = Flask(__name__)
api = Api(app)

app.config['SECRET_KEY'] = secret_key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)

app.config['MAIL_SERVER'] = server_name
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = email_username
app.config['MAIL_PASSWORD'] = password
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)


app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
jwt = JWTManager(app)

translator = google_translator()

ANIMAL = ["cat", "cats"]


# parser to put facts
cats_put_args = reqparse.RequestParser()
cats_put_args.add_argument("fact", type=str, help="Please insert fun fact about cats", required=True)
# parser to register user
parser = reqparse.RequestParser()
parser.add_argument('username', help='This field cannot be blank', required=True)
parser.add_argument('password', help='This field cannot be blank', required=True)
parser.add_argument('email_address', help='This field cannot be blank', required=True)
# parser to delete user
user_delete = reqparse.RequestParser()
user_delete.add_argument('username', help='This field cannot be blank', required=True)
user_delete.add_argument('password', help='This field cannot be blank', required=True)
# parser to login
user_login = reqparse.RequestParser()
user_login.add_argument('username', help='This field cannot be blank', required=True)
user_login.add_argument('password', help='This field cannot be blank', required=True)
# parser to download csv
download_parser = reqparse.RequestParser()
download_parser.add_argument('email_address', help='This field cannot be blank', required=True)

"""
to serialize fields from Model, with marshal_with
"""
resource_fields = {
    'fact': fields.String
}
resource_fields_2 = {
    'username': fields.String,
    'password_hash': fields.String,
    'email_address': fields.String
}


@jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    return RevokedTokenModel.is_jti_blocklisted(jti)


class UserRegistration(Resource):
    @jwt_required()
    @marshal_with(resource_fields_2)
    def get(self):
        user_list = UserModel.query.all()
        return user_list

    def post(self):
        data = parser.parse_args()
        if UserModel.query.filter_by(username=data['username']).first():
            abort(404, message="User already exists.")

        new_user = UserModel(
            username=data['username'],
            password=UserModel.generate_hash(data['password']),
            email_address=data['email_address']
        )
        try:
            new_user.save_to_db()
            access_token = create_access_token(identity=data['username'])
            refresh_token = create_refresh_token(identity=data['username'])
            return {
                'message': 'User {} was created'.format(data['username']),
                'access_token': access_token,
                'refresh_token': refresh_token
                }
        except:
            return {'message': 'Something went wrong'}, 500

    def delete(self):
        data = user_delete.parse_args()
        try:
            result = UserModel.query.filter_by(username=data['username']).first()
        except NoResultFound:
            abort(404, message="User does not exists.")
        db.session.delete(result)
        db.session.commit()
        data = {'message': 'deleted'}
        return data, 204


class UserLogin(Resource):
    def post(self):
        data = user_login.parse_args()
        current_user = UserModel.find_by_username(data['username'])

        if not current_user:
            return {'message': 'User {} doesn\'t exist'.format(data['username'])}

        if UserModel.verify_hash(data['password'], current_user.password):
            access_token = create_access_token(identity=data['username'])
            refresh_token = create_refresh_token(identity=data['username'])
            return {
                'message': 'Logged in as {}'.format(current_user.username),
                'access_token': access_token,
                'refresh_token': refresh_token
            }
        else:
            return {'message': 'Wrong credentials'}


# because we have access token and refresh token 2 endpoints necessary
class UserLogoutAccess(Resource):
    @jwt_required()
    def post(self):
        jti = get_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti=jti)
            revoked_token.add()
            return {'message': 'Access token has been revoked'}
        except:
            return {'message': 'Something went wrong'}, 500


class UserLogoutRefresh(Resource):
    @jwt_required(refresh=True)
    def post(self):
        jti = get_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti=jti)
            revoked_token.add()
            return {'message': 'Refresh token has been revoked'}
        except:
            return {'message': 'Something went wrong'}, 500


# access only with refresh token
class TokenRefresh(Resource):
    @jwt_required(refresh=True)
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity=current_user)
        return {'access_token': access_token}


class Cats(Resource):
    @marshal_with(resource_fields)
    def get(self):
        animal = request.args.get("animal")
        facts_number = request.args.get("facts_number")
        if (str(animal)).lower() in ANIMAL:
            try:
                int(facts_number)
            except ValueError:
                abort(404, message="You need to give number of facts.")
            results = FactModel.query.order_by(func.random()).limit(facts_number).all()
            return results
        else:
            abort(404, message="There is only one correct animal... CATS. Remember. Always. Forever.")

    @jwt_required()
    def put(self):
        args = cats_put_args.parse_args()
        user = UserModel.query.filter_by(username=get_jwt_identity()).first()
        cat = FactModel(fact=args['fact'], user_id=user.id)
        db.session.add(cat)
        db.session.commit()
        data = {'message': 'fact added'}
        return data

    @jwt_required()
    @marshal_with(resource_fields)
    def delete(self):
        cat_id = request.args.get("cat_id")
        try:
            result = FactModel.query.filter_by(id=cat_id).one()
        except NoResultFound:
            abort(404, message="This cat facts does not exist.")
        db.session.delete(result)
        db.session.commit()
        message = {"message": "fact deleted."}
        return message


class Download(Resource):
    @jwt_required()
    def post(self):
        data = download_parser.parse_args()
        result = FactModel.query.order_by(func.random())
        to_be_sent = pd.read_sql(result.statement, result.session.bind).head(10)
        to_be_sent.drop('user_id', axis=1, inplace=True)
        to_be_sent.to_csv("data.csv", index=False)
        msg = Message("Hello",
                      sender=email_username,
                      recipients=[data['email_address']])
        with app.open_resource("data.csv") as fp:
            msg.attach("data.csv", 'cats/data.csv', fp.read())
        try:
            mail.send(msg)
        except SMTPException:
            abort(500, message="Incorrect email.")
        message = {'message': 'message sent'}
        return message, 200


class Translate(Resource):
    @marshal_with(resource_fields)
    def get(self):
        animal = request.args.get("animal")
        facts_number = request.args.get("facts_number")
        if (str(animal)).lower() in ANIMAL:
            try:
                int(facts_number)
            except ValueError:
                abort(404, message="You need to give number of facts.")
            result = FactModel.query.order_by(func.random()).limit(facts_number).all()
            new_list = []
            for elem in result:
                value = elem.fact
                final = translator.translate(value, lang_tgt='pl')
                dict = {}
                dict['fact'] = final
                new_list.append(dict)
            return new_list
        else:
            abort(404, message="There is only one correct animal... CATS. Remember. Always. Forever.")


api.add_resource(Cats, "/")
api.add_resource(UserRegistration, "/registration")
api.add_resource(UserLogin, '/login')
api.add_resource(UserLogoutAccess, '/logout/access')
api.add_resource(UserLogoutRefresh, '/logout/refresh')
# by default token expired after 15 minutes, refresh token 30 days.
api.add_resource(TokenRefresh, '/token/refresh')
api.add_resource(Download, "/download")
api.add_resource(Translate, "/translate")


if __name__ == "__main__":
    app.run(debug=True)