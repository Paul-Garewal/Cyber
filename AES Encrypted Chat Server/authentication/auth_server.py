from flask import Flask
from flask_restful import Api
from flask_jwt_extended import JWTManager

from user_files.user_resources import User, UserList, UserRegister, UserLogin
from message_history.message_resources import Message, MessageList
from database import db

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# In a non-prototype app this would be hidden
app.secret_key = 'key'
api = Api(app)


@app.before_first_request
def create_tables():
    db.create_all()


jwt = JWTManager(app)

# Resources for interacting with users via http
api.add_resource(User, '/user/<string:name>')
api.add_resource(UserRegister, '/register')
api.add_resource(UserLogin, '/login')
api.add_resource(UserList, '/users')

# Resources for interacting with messages via http
api.add_resource(Message, '/save-message')
api.add_resource(MessageList, '/message-history')


if __name__ == '__main__':
    db.init_app(app)
    app.run(port=5000, debug=True)
