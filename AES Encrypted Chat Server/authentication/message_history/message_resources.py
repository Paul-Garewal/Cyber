from flask_restful import Resource, reqparse
from message_history.message_model import MessageModel

parser = reqparse.RequestParser()
parser.add_argument(
    'message',
    type=str,
    required=True,
    help="A message body is required"
)
parser.add_argument(
    'timestamp',
    type=str,
    required=True,
    help="A timestamp is required"
)
parser.add_argument(
    'sender',
    type=str,
    required=True,
    help="A sender name is required"
)

# The following classes outline the HTTP interactions possible with the message database


class Message(Resource):

    def post(self):
        data = parser.parse_args()

        message = MessageModel(message=data['message'], timestamp=data['timestamp'], sender=data['sender'])
        message.save_to_db()

        return {"message": f"Message from {data['sender']} saved."}, 201


class MessageList(Resource):

    def get(self):
        return {'messages': [message.json() for message in MessageModel.query.all()]}
