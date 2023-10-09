# Python imports
import uuid

# Flask imports
from flask_login import UserMixin

# Local imports
from app import cryptoutil, db


class Base(db.Model):
    __abstract__ = True

    id = db.Column(
        db.String(36), unique=True, primary_key=True, default=lambda: str(uuid.uuid4())
    )
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(
        db.DateTime,
        default=db.func.current_timestamp(),
        onupdate=db.func.current_timestamp(),
    )


class User(Base, UserMixin):
    __tablename__ = "users"

    username = db.Column(db.String, nullable=False, unique=True)
    email = db.Column(db.String, nullable=True, unique=False)
    pw_hash = db.Column(db.String(150), nullable=False)
    directory = db.Column(db.String(36), default="local", nullable=False)

    # Used to store Azure user's Object ID
    azure_oid = db.Column(db.String(36), default=None, nullable=True)

    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    encrypted_api_key = db.Column(db.String(), unique=True, nullable=True)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # When a User is created, if no API key is given
        # Generate and encrypt a new API Key
        if not self.encrypted_api_key:
            api_key = str(uuid.uuid4())
            self.encrypted_api_key = cryptoutil.encrypt(api_key)

    def gen_api_key(self) -> str:
        api_key = str(uuid.uuid4())
        self.encrypted_api_key = cryptoutil.encrypt(api_key)
        return api_key

    def set_api_key(self, api_key) -> None:
        self.encrypted_api_key = cryptoutil.encrypt(api_key)
        return api_key

    def get_api_key(self) -> str:
        return cryptoutil.decrypt(self.encrypted_api_key)
