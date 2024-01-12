from app import db
from datetime import datetime

class User(db.Model):
        __tablename__ = 'users'
        __table_args__ = {'extend_existing': True}

        user_id = db.Column(db.Integer, primary_key=True)
        name_first = db.Column(db.String(50))
        name_last = db.Column(db.String(50))
        birthdate = db.Column(db.Date)
        gender = db.Column(db.String(20))
        user_email = db.Column(db.String(320), unique=True, nullable=False)
        username = db.Column(db.String(50), nullable=False)
        pw_hashed = db.Column(db.String(80), nullable=False)
        confirmed = db.Column(db.Integer, nullable=False, default=0)
        created = db.Column(db.DateTime, default=datetime.utcnow)

        def as_dict(self):
            return {c.name: getattr(self, c.name) for c in self.__table__.columns}