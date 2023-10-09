# Python imports
import re
from functools import wraps
from typing import Callable, Optional, Tuple

# Flask imports
from flask import abort, jsonify, redirect, request, url_for
from flask_login import UserMixin, current_user

# Local imports
from app import cryptoutil, log
from app.models import User

"""
Here are several functions intended for quick project prototyping.

It's important to note that these functions may not be considered production ready!
Please review them carefully or substitute them with more robust solutions when
transitioning to a production environment.

You can find examples illustrating how to use these functions in
the API routes "api/routes.py".
"""


def validate_email(email: str) -> bool:
    """
    This is as good as it gets.
    More information: https://emailregex.com/index.html
    """
    email_pattern = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")
    return bool(email_pattern.match(email))


def get_api_user() -> Optional[User]:
    """
    A wrapper around _get_api_user() for cleaner usability.
    This will either return a user or None.
    """
    return _get_api_user()[0]


def api_key_required(f: Callable) -> Callable:
    """
    Simple API login required decorator
    Use this to enforce using a valid API key when accessing an endpoint.
    """

    @wraps(f)
    def decorator(*args, **kwargs):
        _, error_message, error_code = _get_api_user()
        if error_message:
            return jsonify({"error": error_message}), error_code

        return f(*args, **kwargs)

    return decorator


def get_source_addr() -> str:
    """
    The default flask "request.remote_addr" does not work when using a proxy or
    localhost.

    This function provides the source IP of the request, regardless of its origin.
    It should function properly with direct requests, local requests, and requests
    that have been proxied.

    If you are proxying traffic from another server, such as Nginx, be sure to enable
    the forwarded header, More information on that:
    https://www.nginx.com/resources/wiki/start/topics/examples/forwarded/
    """
    if "X-Forwarded-For" in request.headers:
        return request.headers["X-Forwarded-For"].split(",")[0].strip()
    else:
        return request.remote_addr or "127.0.0.1"


def is_api_authenticated_user() -> bool:
    """
    Returns a boolean value indicating whether a user is considered an API user or not.
    """
    user, _, _ = _get_api_user()
    if user:
        return True
    return False


def is_ui_authenticated_user() -> bool:
    """
    Returns a boolean value indicating whether a user is considered a UI user or not.
    """
    return current_user.is_authenticated


def get_current_user() -> Optional[UserMixin]:
    """
    Returns a database object representing the user who initiated the request.

    This function is particularly useful when dealing with API users, since
    When using a custom API authentiaction code, API users do not get registered in
    the "current_user" variable.
    """

    # If the user is authenticated via the Web UI.
    if current_user.is_authenticated:
        return current_user

    # If the user is authenticated via the API.
    user, _, _ = _get_api_user()
    if user:
        return user

    return None


def login_required(f: Callable) -> Callable:
    """
    Custom login required decorator.

    Use this decorator to enforce the usage of either API or Web portal user
    authentication before accessing an endpoint.
    """

    @wraps(f)
    def decorator(*args, **kwargs):
        user = get_current_user()
        if user:
            return f(*args, **kwargs)
        else:
            abort(403)

    return decorator


def admin_required(f: Callable) -> Callable:
    """
    Custom admin login required decorator.

    Use this decorator to ensure that an endpoint can only be accessed by an admin.
    Note: This decorator should be placed at the bottom of the decorator stack on
    an endpoint.
    """

    @wraps(f)
    def decorator(*args, **kwargs):
        user = get_current_user()
        if user and user.is_admin:
            return f(*args, **kwargs)
        else:
            abort(403)

    return decorator


def ui_login_required(f: Callable) -> Callable:
    """
    Custom UI login required.

    Use this decorator to ensure that an endpoint can only be accessed by an
    authenticated user via the web portal.
    """

    @wraps(f)
    def decorator(*args, **kwargs):
        if current_user.is_authenticated:
            return f(*args, **kwargs)
        else:
            return redirect(url_for("auth.login"))

    return decorator


def _get_api_user() -> Tuple[Optional[User], Optional[str], Optional[int]]:
    """
    This function validates the authorization token then returns
    the user database object if valid.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None, "Missing or invalid Authorization header", 401

    api_key = auth_header.split("Bearer ")[1].strip()
    if not api_key:
        return None, "A valid authorization token is required", 400

    try:
        encrypted_api_key = cryptoutil.encrypt(api_key)
        user = User.query.filter_by(encrypted_api_key=encrypted_api_key).first()
        if not user:
            return None, "A valid authorization token is required", 403

        if not user.is_active:
            return None, "Inactive account", 403

    except Exception as err:
        log.error("API auth error: %s", err)
        return None, "Internal server error", 500

    return user, None, None
