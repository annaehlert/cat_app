from main import db
from passlib.hash import pbkdf2_sha256 as sha256


class FactModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fact = db.Column(db.String(150), nullable=False)
    user_id = db.Column(db.String(32), db.ForeignKey('users.id'), nullable=False)


class UserModel(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index= True)
    password = db.Column(db.String(128))
    email_address = db.Column(db.String(100), nullable=False)
    facts = db.relationship('FactModel', backref='user')

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def generate_hash(password):
        return sha256.hash(password)


    @staticmethod
    def verify_hash(password, hash):
        return sha256.verify(password, hash)

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()


class RevokedTokenModel(db.Model):
    __tablename__ = 'revoked_tokens'
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(120))

    def add(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def is_jti_blocklisted(cls, jti):
        query = cls.query.filter_by(jti=jti).first()
        return bool(query)

db.create_all()