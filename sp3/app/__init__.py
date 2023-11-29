from flask_login.utils import login_required, logout_user
from saml2.config import SPConfig
from saml2.client import Saml2Client
from saml2.metadata import create_metadata_string
from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from satosa.internal import AuthenticationInformation, InternalData
from flask import Flask, redirect, request, render_template, url_for
from flask.wrappers import Response
import json
import yaml
from yaml.loader import SafeLoader
from pprint import pprint
import random
import string
import ipdb

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, login_user, login_required, logout_user

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
app.config[
    "SECRET_KEY"
] = "192b9bdd22ab9ed4d12e236c78afcb9a393ec15f71bbf5dc987d54727823bcbf"

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

from .models import User


@login_manager.user_loader
def load_user(user_id):
    # since the user_id is just the primary key of our user table, use it in the query for the user
    return User.query.get(int(user_id))


with open("./saml2_backend.yaml") as fobj:
    sp_config = SPConfig().load(yaml.load(fobj, SafeLoader)["config"]["sp_config"])


sp = Saml2Client(sp_config)


def rndstr(size=16, alphabet=""):
    """
    Returns a string of random ascii characters or digits
    :type size: int
    :type alphabet: str
    :param size: The length of the string
    :param alphabet: A string with characters.
    :return: string
    """
    rng = random.SystemRandom()
    if not alphabet:
        alphabet = string.ascii_letters[0:52] + string.digits
    return type(alphabet)().join(rng.choice(alphabet) for _ in range(size))


def get_idp_entity_id():
    """
    Finds the entity_id for the IDP
    :return: the entity_id of the idp or None
    """

    idps = sp.metadata.identity_providers()
    only_idp = idps[0]
    entity_id = only_idp

    return entity_id


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/metadata/")
def metadata():
    metadata_string = create_metadata_string(
        None, sp.config, 4, None, None, None, None, None
    ).decode("utf-8")
    return Response(metadata_string, mimetype="text/xml")


@app.route("/login/")
def login():
    try:
        acs_endp, response_binding = sp.config.getattr("endpoints", "sp")[
            "assertion_consumer_service"
        ][0]
        relay_state = rndstr()
        entity_id = get_idp_entity_id()
        req_id, binding, http_args = sp.prepare_for_negotiated_authenticate(
            entityid=entity_id,
            response_binding=response_binding,
            relay_state=relay_state,
        )
        if binding == BINDING_HTTP_REDIRECT:
            headers = dict(http_args["headers"])
            return redirect(str(headers["Location"]), code=303)

        return Response(http_args["data"], headers=http_args["headers"])
    except Exception as e:
        print(e)


@app.route("/profile/", methods=["GET"])
@login_required
def profile():
    return render_template("profile.html")

@app.route("/logout/", methods=["GET"])
def logout():
    logout_user()
    return redirect(url_for("index"))

@app.route("/acs/post", methods=["POST"])
def acs_post():
    outstanding_queries = {}
    binding = BINDING_HTTP_POST
    try:
        authn_response = sp.parse_authn_request_response(
            request.form["SAMLResponse"], binding, outstanding=outstanding_queries
        )
    except:
        return render_template("error.html"), 500
    # ipdb.set_trace()
    email = authn_response.ava["email"][0]
    # Now check if an user exists, or add one
    user = User.query.filter_by(email=email).first()

    if not user:
        user = User(email=email)
        db.session.add(user)
        db.session.commit()
    login_user(user, remember=True)
    return redirect(url_for("profile"))


@app.route("/acs/redirect", methods=["GET"])
def acs_redirect():
    outstanding_queries = {}
    binding = BINDING_HTTP_REDIRECT
    authn_response = sp.parse_authn_request_response(
        request.form["SAMLResponse"], binding, outstanding=outstanding_queries
    )
    return str(authn_response.ava)
