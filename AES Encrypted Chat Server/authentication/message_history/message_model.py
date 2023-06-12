from database import db

# The following model represents a message in the db


class MessageModel(db.Model):
    __tablename__ = 'messages'

    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(255))
    timestamp = db.Column(db.String(80))
    sender = db.Column(db.String(80))

    def __init__(self, message, timestamp, sender):
        self.message = message
        self.timestamp = timestamp
        self.sender = sender

    def json(self):
        return {
            'id': self.id,
            'message': self.message,
            'timestamp': self.timestamp,
            'sender': self.sender
        }

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()
