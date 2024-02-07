"""
Django settings for sp4 project.

Generated by 'django-admin startproject' using Django 5.0.2.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.0/ref/settings/
"""

from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = "django-insecure-w5!nwi=rg-riha9&a$t4v0k@)ye0u-pxp3-h9zaf0-a39b%x1="

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ["*",]


# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    'djangosaml2',
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "djangosaml2.middleware.SamlSessionMiddleware",
]

ROOT_URLCONF = "sp4.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "sp4.wsgi.application"


# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}


# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.0/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

STATIC_URL = "static/"

# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


# SAML settings for SP

SAML_SESSION_COOKIE_NAME = 'saml_session'
AUTHENTICATION_BACKENDS = (
        'django.contrib.auth.backends.ModelBackend',
        'djangosaml2.backends.Saml2Backend',
        )


import os
import saml2
from saml2.saml import (NAMEID_FORMAT_PERSISTENT,
                        NAMEID_FORMAT_TRANSIENT,
                        NAMEID_FORMAT_UNSPECIFIED,
                        NAMEID_FORMAT_EMAILADDRESS)
from saml2.sigver import get_xmlsec_binary

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BASE = 'http://localhost:8000'
BASE_URL = '{}/saml2'.format(BASE)

LOGIN_URL = '/saml2/login/'
LOGOUT_URL = '/saml2/logout/'
LOGIN_REDIRECT_URL = '/'

SAML2_DEFAULT_BINDING = saml2.BINDING_HTTP_POST
SAML_CONFIG = {
    'debug' : True,
    'xmlsec_binary': get_xmlsec_binary(
        ['/opt/local/bin', '/usr/bin/xmlsec1']
    ),
    'entityid': f'{BASE_URL}/metadata/',
    'attribute_map_dir': os.path.join(BASE_DIR, "attributemaps"),
    'service': {


        'sp': {
            'name': '%s/metadata/' % BASE_URL,

            # that's for metadata
            'name_id_format': [
                               #  NAMEID_FORMAT_EMAILADDRESS,
                               NAMEID_FORMAT_PERSISTENT,
                               NAMEID_FORMAT_TRANSIENT
                               ],
            # that's for authn request
            'name_id_policy_format': NAMEID_FORMAT_TRANSIENT,

            'endpoints': {
                'assertion_consumer_service': [
                    (f'{BASE_URL}/acs/', saml2.BINDING_HTTP_POST, 1),
                    ],
                "single_logout_service": [
                    (f"{BASE_URL}/ls/post/", saml2.BINDING_HTTP_POST),
                    (f"{BASE_URL}/ls/", saml2.BINDING_HTTP_REDIRECT),
                ],
                }, # end endpoints

            # these only works using pySAML2 patched with this
            # https://github.com/IdentityPython/pysaml2/pull/744
            'signing_algorithm':  saml2.xmldsig.SIG_RSA_SHA256,
            'digest_algorithm':  saml2.xmldsig.DIGEST_SHA256,

            # Mandates that the identity provider MUST authenticate the
            # presenter directly rather than rely on a previous security context.
            "force_authn": False,
            #'name_id_format_allow_create': False,

            # attributes that this project need to identify a user
            'required_attributes': [
                'givenName', 'sn', 'mail', 'email',
            ],

            # attributes that may be useful to have but not required
            'optional_attributes': ['eduPersonAffiliation', "displayName"],

            'want_response_signed': False,
            'authn_requests_signed': False,
            "want_assertions_or_response_signed": True,
            'logout_requests_signed': True,
            # Indicates that Authentication Responses to this SP must
            # be signed. If set to True, the SP will not consume
            # any SAML Responses that are not signed.
            'want_assertions_signed': True,

            'only_use_keys_in_metadata': True,

            # When set to true, the SP will consume unsolicited SAML
            # Responses, i.e. SAML Responses for which it has not sent
            # a respective SAML Authentication Request.
            'allow_unsolicited': True,

            # Permits to have attributes not configured in attribute-mappings
            # otherwise...without OID will be rejected
            'allow_unknown_attributes': True,

            }, # end sp

    },

    # many metadata, many idp...
    'metadata': {
         'local': [

                   os.path.join(BASE_DIR, 'idp.xml'),

                  # os.path.join(os.path.join(os.path.join(BASE_DIR, 'saml2_sp'),
                  # 'saml2_config'), 'satosa_metadata.xml'),
                   ],
        #  #

        "remote": [
            # {
            # "url": "https://proxy.auth.unical.it/Saml2IDP/metadata",
            #"cert": "/opt/satosa-saml2/pki/frontend.cert",
            #"disable_ssl_certificate_validation": True,
            # },
            # {
            # "url": "http://localhost:9000/idp/metadata/",
            #   "disable_ssl_certificate_validation": True,
            #   "check_validity": False,
            # },
            #  {
             #  "url": "https://idp.testunical.it/idp/shibboleth",
             #  "disable_ssl_certificate_validation": True,
             #  },
             #  {
              #  "url": "http://idp1.testunical.it:9000/idp/metadata/",
              #  },
             #  {
              #  "url": "http://idp1.testunical.it:9000/idp/aa/metadata/",
              #  },
            # {
             # 'url': 'https://localhost:10000/Saml2IDP/metadata',
             # only for test purpose !
             # "disable_ssl_certificate_validation": True,
             # }
            ],

        # "mdq": [{
            # "url": "https://ds.testunical.it",
            # "cert": "certificates/others/ds.testunical.it.cert",
            # "disable_ssl_certificate_validation": True,
            # }]

    },
    # avoids exception: HTTPSConnectionPool(host='satosa.testunical.it', port=443):
    # Max retries exceeded with url: /idp/shibboleth (Caused by SSLError(SSLError("bad handshake: Error([('SSL routines', 'tls_process_server_certificate', 'certificate verify failed')],)",),))
    #'ca_certs' : "/opt/satosa-saml2/pki/http_certificates/ca.crt",

    # Signing
    'key_file': BASE_DIR + '/certificates/backend.key',
    'cert_file': BASE_DIR + '/certificates/backend.crt',

    # Encryption
    'encryption_keypairs': [{
        'key_file': BASE_DIR + '/certificates/backend.key',
        'cert_file': BASE_DIR + '/certificates/backend.crt',
    }],

    # own metadata settings
    'contact_person': [
      {'given_name': 'Kushal',
       'sur_name': 'Das',
       'company': 'SUNET',
       'email_address': 'kushal+example@sunet.se',
       'contact_type': 'administrative'},
      {'given_name': 'Kushal',
       'sur_name': 'Das',
       'company': 'SUNET',
       'email_address': 'kushal+example@sunet.se',
       'contact_type': 'technical'},
      ],
    # you can set multilanguage information here
    'organization': {
      'name': [('SUNET', 'se'), ('SUNET', 'en')],
      'display_name': [('SUNET', 'se'), ('SUNET', 'en')],
      'url': [('https://sunet.se', 'se'), ('https://sunet.se', 'en')],
      },

    #'valid_for': 24 * 10,
}

CONFIG = SAML_CONFIG

# OR NAME_ID or MAIN_ATTRIBUTE (not together!)
# SAML_USE_NAME_ID_AS_USERNAME = True
SAML_DJANGO_USER_MAIN_ATTRIBUTE = 'email'
SAML_DJANGO_USER_MAIN_ATTRIBUTE_LOOKUP = '__iexact'

SAML_CREATE_UNKNOWN_USER = True

# logout
SAML_LOGOUT_REQUEST_PREFERRED_BINDING = saml2.BINDING_HTTP_POST

SAML_ATTRIBUTE_MAPPING = {

    # django related
    'uid': ('username', ),
    'displayName': ('displayName',),

    # pure oid standard
    'mail': ('email',),
    'email': ('email', ),

    # oid pure
    'cn': ('first_name', ),
    'sn': ('last_name', ),

    # spid related
    'name': ('first_name', ),
    'familyName': ('last_name', ),
}