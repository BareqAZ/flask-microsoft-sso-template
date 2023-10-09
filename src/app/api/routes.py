# local imports
from app.api import api
from app.libs.utils import (
    admin_required,
    api_key_required,
    get_current_user,
    get_source_addr,
    login_required,
    ui_login_required,
)


@api.route("/public")
def public_route():
    return {"message": "Everyone should be able to access this endpoint"}, 200


@api.route("/check")
@login_required
def user_auth_check():
    return {
        "message": "This is accessible by all authenticated users, both API and Web UI."
    }, 200


@api.route("/api-user-check")
@api_key_required
def user_api_auth_check():
    return {"message": "This is only accessible by API authenticated users."}, 200


@api.route("/admin-check")
@admin_required
def admin_auth_check():
    return {
        "message": "This is accessible by all authenticated Admins, both API and Web UI."
    }, 200


@api.route("/api-admin-check")
@api_key_required
@admin_required
def admin_api_auth_check():
    return {"message": "This is only accessible by API authenticated Admins."}, 200


@api.route("/ui-only-check")
@login_required
@ui_login_required
def ui_auth_check():
    return {"message": "This is only accessible by UI authenticated users"}, 200


@api.route("/profile")
@login_required
def get_user_info():
    """
    This is accessible by all authenticated users, both API and Web UI.
    """
    user = get_current_user()
    source_addr = get_source_addr()
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "directory": user.directory,
        "is_admin": user.is_admin,
        "request_origin": source_addr,
    }, 200
