# Flask imports
from flask import redirect, url_for
from flask_login import login_required

# Local imports
from app.user import user


@user.route("/")
@user.route("/home")
@user.route("/index")
@login_required
def default():
    return redirect(url_for("auth.account"))
