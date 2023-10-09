# Flask imports
# Python imports
import http.client
import json

# Third-party imports
import msal
from flask import flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_user, logout_user
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.security import check_password_hash, generate_password_hash

# Local imports
from app import cryptoutil, db, log, settings
from app.auth import auth
from app.auth.utils import get_source_addr, ui_login_required
from app.models import User


@auth.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("user.default"))

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username is None or password is None:
            flash("Incorrect credentials", "err")
            return redirect(url_for("auth.login"))

        user = User.query.filter(User.username == username).first()
        if user and check_password_hash(user.pw_hash, password):
            if not user.is_active:
                flash("Inactive account", "err")
                log.warning(f'Inactive user "{username}" attempted login')
                return redirect(url_for("auth.login"))

            login_user(user, remember=True)
            log.info(f'User "{user.username}" logged in')
            return redirect(url_for("user.default"))

        elif not user:
            flash("Incorrect credentials", "err")
            log.warning("Incorrect login attempt from: %s", get_source_addr())
            return redirect(url_for("auth.login"))

        else:
            flash("Incorrect credentials", "err")
            log.warning(f'User "{username}" provided incorrect password')
            return redirect(url_for("auth.login"))

    # Here we build the Microsoft SSO button
    auth_uri = None
    if settings["azure"]["enabled"]:
        try:
            session["flow"] = _build_auth_code_flow(scopes=settings["azure"]["scopes"])
            auth_uri = session["flow"]["auth_uri"]
        except ValueError as err:
            log.error(
                "Failed to build Microsoft SSO URI, \
                 most likely missing or incorrect credentials, err: %s",
                err,
            )

    return render_template("login.html", sso_uri=auth_uri)


@auth.route("/sign-up", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        password_confirm = request.form.get("password-confirm")

        user = User.query.filter(User.username == username).first()

        if user:
            flash("Username already exists", "err")
            return render_template("sign_up.html"), 400

        if not username or not password:
            flash("Missing fields", "err")
            return render_template("sign_up.html"), 400

        if password != password_confirm:
            flash("Passwords do not match", "err")
            return render_template("sign_up.html"), 400

        try:
            user = User(
                pw_hash=generate_password_hash(password),
                username=username,
                directory="local",
            )

            db.session.add(user)
            db.session.commit()
            flash("Account created successfully", category="info")
            log.info(f'Account "{username}" has been created')
            return redirect(url_for("user.default"))

        except SQLAlchemyError as err:
            flash("Account creation failed, internal error occurred")
            log.error("Failed inserting user to the databasen err: %s", err)
            return render_template("sign_up.html"), 500

    return render_template("sign_up.html")


# After a user clicks the SSO button and Microsoft does their proprietary magic
# they will be redirected to here, the redirect path must match the Azure app's
# redirect_uri.
# More info:
# https://learn.microsoft.com/en-us/azure/active-directory/develop/reply-url
@auth.route(settings["azure"]["redirect_path"])
def authorized():
    cache = _load_cache()
    result = _build_msal_app(cache=cache).acquire_token_by_auth_code_flow(
        session.get("flow", {}), request.args
    )

    user_info = result.get("id_token_claims")
    if user_info:
        username = user_info.get("preferred_username")
        email = user_info.get("email")
        oid = user_info.get("oid")
    else:
        flash("Authentication failed, Failed retrieving user info", "fail")
        log.error("Microsoft SSO Authentication failed, err: %s", result)
        return redirect(url_for("auth.login"))

    # We store the users locally as well
    # to simplify managing rights, access, association... etc
    user = User.query.filter_by(azure_oid=oid).first()

    # If the user is found, then we check for updates
    # To ensure our local db is always in sync.
    if user:
        if user.username != username or user.email != email:
            user.username = username
            user.email = email
            db.session.commit()
            log.info(f'Azure AD User "{username}" updated')

    # Else if the user does not exist then
    # create a new user.
    else:
        try:
            user = User(
                username=username,
                email=email,
                azure_oid=oid,
                pw_hash="",
                directory="azure",
            )
            db.session.add(user)
            db.session.commit()

        # In the unlikely event that 2 requests are submitted at the same exact time
        # from the same exact user.  the first request will create a new user and the
        # 2nd one will raise IntegrityError due to the unique constraint violation.
        except IntegrityError:
            db.session.rollback()  # Rollback the session to a clean state
            user = User.query.filter_by(username=username).first()  # Re-query the user

    login_user(user, remember=True)
    session["user"] = user_info
    _save_cache(cache)
    log.info(f'Azure AD User "{username}" logged in')

    return redirect(url_for("user.default"))


@auth.route("/logout")
@ui_login_required
def logout():
    if current_user.directory == "azure":
        log.info(f'Azure AD user "{current_user.username}" logging out')
        logout_user()
        return redirect(
            "https://login.microsoftonline.com/"
            + settings["azure"]["tenant_id"]
            + "/oauth2/v2.0/logout?post_logout_redirect_uri="
            + url_for("auth.login", _external=True)
        )

    log.info(f'User "{current_user.username}" logging out')
    logout_user()
    return redirect(url_for("auth.login"))


@auth.route("/account")
@ui_login_required
def account():
    encrypted_api_key = current_user.encrypted_api_key
    user_api_key = cryptoutil.decrypt(encrypted_api_key)
    if current_user.directory == "azure":
        token = _get_token_from_cache(settings["azure"]["scopes"])
        if not token:
            return redirect(url_for("auth.login"))

        access_token = token["access_token"]
        headers = {"Authorization": "Bearer " + str(access_token)}
        conn = http.client.HTTPSConnection("graph.microsoft.com")
        try:
            conn.request("GET", "/v1.0/me/", body={}, headers=headers)
            resp = conn.getresponse().read().decode("utf-8")
            azure_user_info = json.loads(resp)
        finally:
            conn.close()

        return render_template(
            "account.html",
            user_api_key=user_api_key,
            azure_token_info=token,
            azure_user_info=azure_user_info,
        )
    else:
        return render_template("account.html", user_api_key=user_api_key)


@auth.route("/account/reset", methods=["GET", "POST"])
@ui_login_required
def account_reset():
    if request.method == "POST":
        password_old = request.form.get("password")
        password_new = request.form.get("password-new")
        password_new_confirm = request.form.get("password-new-confirm")

        if not password_old or not password_new:
            flash("Empty password fields", "err")
            return render_template("reset_password.html"), 400

        if password_new != password_new_confirm:
            flash("New passwords do not match!", "err")
            return render_template("reset_password.html"), 400

        if check_password_hash(current_user.pw_hash, password_old):
            current_user.pw_hash = generate_password_hash(password_new)
            db.session.commit()
            log.info(f'User "{current_user.username}" changed their password')
            flash("Password changed successfully", category="info")
            return redirect(url_for("user.default"))
        else:
            flash("Incorrect user password", category="err")
            return render_template("reset_password.html"), 400

    return render_template("reset_password.html")


def _load_cache():
    cache = msal.SerializableTokenCache()
    if session.get("token_cache"):
        cache.deserialize(session["token_cache"])
    return cache


def _save_cache(cache):
    if cache.has_state_changed:
        session["token_cache"] = cache.serialize()


def _build_msal_app(cache=None, authority=None):
    return msal.ConfidentialClientApplication(
        settings["azure"]["client_id"],
        authority=authority
        or "https://login.microsoftonline.com/" + settings["azure"]["tenant_id"],
        client_credential=settings["azure"]["client_secret"],
        token_cache=cache,
    )


def _build_auth_code_flow(authority=None, scopes=None):
    return _build_msal_app(authority=authority).initiate_auth_code_flow(
        scopes or [], redirect_uri=url_for("auth.authorized", _external=True)
    )


def _get_token_from_cache(scope=None):
    # This web app maintains one cache per session
    cache = _load_cache()
    cca = _build_msal_app(cache=cache)
    accounts = cca.get_accounts()

    # All account(s) belong to the current signed-in user
    if accounts:
        result = cca.acquire_token_silent(scope, account=accounts[0])
        _save_cache(cache)
        return result
