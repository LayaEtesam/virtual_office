from django.views.generic import detail
from rest_framework.views import exception_handler
from django.http import Http404
# from rest_framework.serializers import ValidationError
# from rest_framework import status
from rest_framework.exceptions import (
    ValidationError, AuthenticationFailed, NotAuthenticated, PermissionDenied)
from rest_framework_simplejwt.exceptions import InvalidToken
from django.conf import settings


def custom_exception_handler(exc, context):
    # Call REST framework's default exception handler first,
    # to get the standard error response.
    response = exception_handler(exc, context)
    if settings.DEBUG:
        # print(exc.detail)
        # print(exc.get_codes())
        # print(exc.get_full_details())

        print("type(exc) : ", type(exc))
        print("exc : ", exc)
    if isinstance(exc, Http404):
        custom_response_data = {
            'detail': 'This object does not exist.',
            'code': 'does_not_exist'  # custom exception message
        }  # gjgjggjgjg
        # set the custom response data on response object
        response.data = custom_response_data
    if isinstance(exc, ValidationError):

        # print("response.data : ", response.data)
        for id, key in enumerate(response.data):
            if key == "usercontacts":
                break
            for i in response.data[key]:
                response.data[key] = {
                    "detail": str(i), "code": i.code}
    elif isinstance(exc, InvalidToken):
        return response
    elif (isinstance(exc, AuthenticationFailed) or
          isinstance(exc, NotAuthenticated) or
          isinstance(exc, PermissionDenied)):
        for id, key in enumerate(response.data):
            i = response.data[key]
            response.data[key] = {
                "detail": str(i), "code": i.code
            }
        # set the custom response data on response object
        # response.data = custom_response_data

    return response
