from database import db

# The following model represents a user stored in the db


class UserModel(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    password_hash = db.Column(db.String(255))

    def __init__(self, username, password_hash):
        self.username = username
        self.password_hash = password_hash

    def json(self):
        return {
            'id': self.id,
            'username': self.username
        }

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()

    @classmethod
    def find_by_username(cls, username):
        # SELECT * FROM users WHERE name=name LIMIT 1
        return cls.query.filter_by(username=username).first()

    @classmethod
    def find_by_id(cls, _id):
        # SELECT * FROM users WHERE name=name LIMIT 1
        return cls.query.filter_by(id=_id).first()
