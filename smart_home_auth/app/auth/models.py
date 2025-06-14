from datetime import datetime
from app import db
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), default='user')  # user/admin/superadmin
    failed_attempts = db.Column(db.Integer, default=0)
    locked = db.Column(db.Boolean, default=False)
    locked_until = db.Column(db.DateTime)
    last_login = db.Column(db.DateTime)
    login_history = db.relationship('LoginHistory', backref='user', lazy='dynamic')
    
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')
    
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_locked(self):
        if self.locked and self.locked_until:
            return datetime.utcnow() < self.locked_until
        return self.locked

class LoginHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(200))
    login_time = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20))  # success/failed
    location = db.Column(db.String(100))