from saml2.config import SPConfig
from saml2.client import Saml2Client
from saml2.metadata import create_metadata_string
from saml2 import BINDING_HTTP_REDIRECT
from satosa.internal import AuthenticationInformation, InternalData
from flask import Flask, redirect, request
from flask.wrappers import Response
import json
import yaml
from yaml.loader import SafeLoader
from pprint import pprint
import random
import string
import ipdb

app = Flask(__name__)

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
def hello_world():
    return '<p><a href="/login/">Login</a></p>'


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


@app.route("/acs/post", methods=["POST"])
def acs_post():
    outstanding_queries = {}
    binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    authn_response = sp.parse_authn_request_response(
        request.form["SAMLResponse"], binding, outstanding=outstanding_queries
    )
    #ipdb.set_trace()
    return str(authn_response.ava)

@app.route("/acs/redirect", methods=["GET"])
def acs_redirect():
    outstanding_queries = {}
    binding = BINDING_HTTP_REDIRECT
    authn_response = sp.parse_authn_request_response(
        request.form["SAMLResponse"], binding, outstanding=outstanding_queries
    )
    return str(authn_response.ava)
