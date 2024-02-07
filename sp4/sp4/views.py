import base64
import logging
import saml2

from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.contrib.auth.models import User
from django.dispatch import receiver
from django.http import HttpResponse
from django.shortcuts import render
from django.template import TemplateDoesNotExist
from djangosaml2.conf import get_config
from djangosaml2.cache import IdentityCache, OutstandingQueriesCache
from djangosaml2.cache import StateCache
from djangosaml2.conf import get_config
from djangosaml2.overrides import Saml2Client
from djangosaml2.signals import post_authenticated, pre_user_save
from djangosaml2.utils import (
    available_idps, get_custom_setting,
    get_idp_sso_supported_bindings, get_location
)
from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from saml2.authn_context import requested_authn_context
from saml2.metadata import entity_descriptor



logger = logging.getLogger('djangosaml2')


def index(request):
    """ Barebone 'diagnostics' view, print user attributes if logged in + login/logout links.
    """
    if request.user.is_authenticated:
        out = "LOGGED IN: <a href={0}>LOGOUT</a><br>".format(settings.LOGOUT_URL)
        out += "".join(['%s: %s</br>' % (field.name, getattr(request.user, field.name))
                    for field in request.user._meta.get_fields()
                    if field.concrete])
        return HttpResponse(out)
    else:
        return HttpResponse("LOGGED OUT: <a href={0}>LOGIN</a>".format(settings.LOGIN_URL))


@login_required(redirect_field_name='next')
def information(request):
    """ Barebone 'diagnostics' view, print user attributes if logged in + login/logout links.
    """
    if request.user.is_authenticated:
        out = "LOGGED IN: <a href={0}>LOGOUT</a><br>".format(settings.LOGOUT_URL)
        out += "".join(['%s: %s</br>' % (field.name, getattr(request.user, field.name))
                    for field in request.user._meta.get_fields()
                    if field.concrete])
        return HttpResponse(out)
    else:
        return HttpResponse("LOGGED OUT: <a href={0}>LOGIN</a>".format(settings.LOGIN_URL))