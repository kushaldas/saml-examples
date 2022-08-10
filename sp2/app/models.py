from flask_login import UserMixin
from app import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), index=True, unique=True)

    def __repr__(self):
        return '<User {}>'.format(self.email)
