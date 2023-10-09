# Python imports
import logging
import logging.handlers
import os
import sys

# Third-party imports
import toml

# Flask imports
from flask import Flask, jsonify, request
from flask_login import LoginManager
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash

# Local imports
from app.libs.cryptlib import CryptLib

# Load the settings TOML file dynamically regardless
# from where this code is being executed.
file_path = os.path.abspath(__file__)
install_path = os.path.dirname(os.path.dirname(file_path))
with open(f"{install_path}/settings.toml", "r", encoding="utf8") as file:
    settings = toml.load(file)


# Setup logging
DEBUG_MODE = settings["general"]["debug"]
log = logging.getLogger()

if DEBUG_MODE:
    log.setLevel(logging.DEBUG)
    formatter = logging.Formatter("App: %(levelname)s: [%(funcName)s] %(message)s")
else:
    log.setLevel(logging.INFO)
    formatter = logging.Formatter("App: %(levelname)s: %(message)s")

if os.path.exists("/dev/log"):
    handler = logging.handlers.SysLogHandler(address="/dev/log")
    handler.setFormatter(formatter)
    log.addHandler(handler)

# This checks if the code is running interactively from
# the terminal then prints the logs to standard out as well.
# Otherwise the logs are written to the syslog only.
if sys.stdout.isatty():
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    log.addHandler(handler)

# Init database lib
db = SQLAlchemy()


cryptoutil = CryptLib(settings["general"]["secret_key"])


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = settings["general"]["secret_key"]
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = settings["general"]["sqlite_database_uri"]
    app.config["SESSION_TYPE"] = "sqlalchemy"
    app.config["SESSION_SQLALCHEMY"] = db
    db.init_app(app)
    Session(app)

    from app.api import api
    from app.auth import auth
    from app.user import user

    app.register_blueprint(user, url_prefix="/")
    app.register_blueprint(api, url_prefix="/api/v1")
    app.register_blueprint(auth, url_prefix="/auth")

    with app.app_context():
        db.create_all()
        from app.models import User

        if User.query.count() == 0:
            log.info("No users found, creating the initial superuser")
            superuser_username = settings["general"]["superuser_username"]
            superuser_password = settings["general"]["superuser_password"]
            superuser_api_key = settings["general"]["superuser_api_key"]

            admin_user = User(
                username=superuser_username,
                pw_hash=generate_password_hash(superuser_password),
                email="superuser@localhost",
                is_admin=True,
                directory="local",
            )

            if superuser_api_key:
                admin_user.set_api_key(superuser_api_key)

            try:
                db.session.add(admin_user)
                db.session.commit()
                log.info(f'Superuser account "{superuser_username}" has been created')
            except SQLAlchemyError as err:
                log.info("Failed creating the initial superuser, database err: %s", err)

        # We try to decrypt the superuser API key on startup
        # So if any decryption issue found we throw an error.
        superuser = User.query.first()
        superuser.get_api_key()

    login_manager = LoginManager()
    login_manager.login_view = "auth.login"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.filter_by(id=user_id).first()

    @app.errorhandler(HTTPException)
    def handle_http_exception(err):
        if request.path.startswith("/api"):
            return jsonify({"error": err.description}), err.code
        else:
            return err.description, err.code

    return app
