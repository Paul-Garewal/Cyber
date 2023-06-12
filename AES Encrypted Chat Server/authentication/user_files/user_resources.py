import bcrypt
from flask_restful import Resource, reqparse
from flask_jwt_extended import create_access_token, create_refresh_token
from user_files.user_model import UserModel

parser = reqparse.RequestParser()
parser.add_argument(
    'username',
    type=str,
    required=True,
    help="A username is required"
)
parser.add_argument(
    'password',
    type=str,
    required=True,
    help="A password is required"
)

# These classes outline the HTTP interactions possible with the User database


class User(Resource):

    def get(self, name):
        user = UserModel.find_by_username(name)

        if user:
            return user.json(), 200
        return {'message': f'User  {name} not found.'}, 404

    def delete(self, name):
        user = UserModel.find_by_username(name)
        if not user:
            return {'message': 'User Not Found'}, 404
        user.delete_from_db()
        return {'message': f"User {name} deleted."}, 200


class UserList(Resource):
    def get(self):
        return {'users': [user.json() for user in UserModel.query.all()]}


class UserRegister(Resource):

    def post(self):
        data = parser.parse_args()

        if UserModel.find_by_username(data['username']):
            return {"message": f"User {data['username']} already exists"}, 400

        # store password as hash
        p = str.encode(data['password'])
        salt = bcrypt.gensalt()
        hashed_p = bcrypt.hashpw(p, salt)

        user = UserModel(username=data['username'], password_hash=hashed_p)
        user.save_to_db()

        return {"message": f"User {data['username']} was registered"}, 201


class UserLogin(Resource):

    def post(self):
        data = parser.parse_args()

        user = UserModel.find_by_username(data['username'])

        # check against hashed pw
        credentials = bcrypt.checkpw(str.encode(data['password']), user.password_hash)

        if user and credentials:
            access_token = create_access_token(identity=user.id, fresh=True)
            refresh_token = create_refresh_token(user.id)
            return {
                'access_token': access_token,
                'refresh_token': refresh_token
            }, 200

        return {"message": "Invalid Credentials!"}, 401
