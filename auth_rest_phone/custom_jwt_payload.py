__author__ = 'erfan'
import jwt
import uuid
import warnings

from django.contrib.auth import get_user_model

from calendar import timegm
from datetime import datetime

from rest_framework_jwt.compat import get_username
from rest_framework_jwt.compat import get_username_field
from rest_framework_jwt.settings import api_settings


def get_groups(user):
    groups = user.groups.all()
    groups_name = [i.name for i in groups]
    return groups_name


def jwt_payload_handler(user):
    username_field = get_username_field()
    username = get_username(user)
    groups = get_groups(user)
    warnings.warn(
        'The following fields will be removed in the future: '
        '`email` and `user_id`. ',
        DeprecationWarning
    )

    payload = {
        'user_id': user.pk,
        'username': username,
        'exp': datetime.utcnow() + api_settings.JWT_EXPIRATION_DELTA,
        'groups': groups,
        'is_superuser': user.is_superuser,
    }
    if hasattr(user, 'phonenumber'):
        payload['email'] = user.email
    if isinstance(user.pk, uuid.UUID):
        payload['user_id'] = str(user.pk)

    payload[username_field] = username

    # Include original issued at time for a brand new token,
    # to allow token refresh
    if api_settings.JWT_ALLOW_REFRESH:
        payload['orig_iat'] = timegm(
            datetime.utcnow().utctimetuple()
        )

    if api_settings.JWT_AUDIENCE is not None:
        payload['aud'] = api_settings.JWT_AUDIENCE

    if api_settings.JWT_ISSUER is not None:
        payload['iss'] = api_settings.JWT_ISSUER

    return payload
