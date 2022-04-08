from django.apps import apps
from django.conf import settings as django_settings
from django.test.signals import setting_changed
from django.utils.functional import LazyObject
from django.utils.module_loading import import_string
AUTH_REST_SETTINGS_NAMESPACE = "AUTH_REST_PHONE"

auth_module, user_model = django_settings.AUTH_USER_MODEL.rsplit(".", 1)

User = apps.get_model(auth_module, user_model)


class ObjDict(dict):
    def __getattribute__(self, item):
        try:
            val = self[item]
            if isinstance(val, str):
                val = import_string(val)
            elif isinstance(val, (list, tuple)):
                val = [import_string(v) if isinstance(
                    v, str) else v for v in val]
            self[item] = val
        except KeyError:
            val = super(ObjDict, self).__getattribute__(item)

        return val


default_settings = {
    "GHASEDAK_APIKEY": "f1878283f9bfb295997316552a0081fc19eab2c84c0a5101c8bd89431297aa96",
    "LINE_NUMBER": "10008566",
    "USER_ID_FIELD": User._meta.pk.name,
    "AUTH_VALID_USER_GROUPS":[],
    "LOGIN_FIELD": User.USERNAME_FIELD,
    "SEND_SMS_COUNT": 5,
    "VALIDATE_OTP_INTERVAL": 900,
    "SEND_ACTIVATION_EMAIL": False,
    "SEND_CONFIRMATION_SMS": True,
    "SEND_CONFIRMATION_EMAIL": False,
    "USER_CREATE_PASSWORD_RETYPE": False,
    "SET_PASSWORD_RETYPE": False,
    "PASSWORD_RESET_CONFIRM_RETYPE": False,
    "SET_USERNAME_RETYPE": False,
    "USERNAME_RESET_CONFIRM_RETYPE": False,
    "PASSWORD_RESET_SHOW_EMAIL_NOT_FOUND": False,
    "USERNAME_RESET_SHOW_EMAIL_NOT_FOUND": False,
    "PASSWORD_CHANGED_EMAIL_CONFIRMATION": False,
    "USERNAME_CHANGED_EMAIL_CONFIRMATION": False,
    "TOKEN_MODEL": "rest_framework.authtoken.models.Token",
    "AUTH_VALID_USER_GROUPS" :  ['company','person'],

    "SERIALIZERS": ObjDict(
        {
            "register_user": "auth_rest_phone.serializers.RegisterUserSerializer",
            "send_register_sms": "auth_rest_phone.serializers.SendOTPSerializer",
            "send_add_to_group_sms": "auth_rest_phone.serializers.SendSMSAddTOGroupSerializer",
            "add_to_group": "auth_rest_phone.serializers.phoneAndOTPSerializer",
            "activation": "auth_rest_phone.serializers.ActivationSerializer",
            "activation_with_sms": "auth_rest_phone.serializers.ActivationWithSMSSerializer",
            "password_reset_with_sms": "auth_rest_phone.serializers.SendSMSResetSerializer",
            "reset_password_confirm_with_sms": "auth_rest_phone.serializers.PasswordResetConfirmWithSMSSerializer",
            "password_reset": "auth_rest_phone.serializers.SendEmailResetSerializer",
            "password_reset_confirm": "auth_rest_phone.serializers.PasswordResetConfirmSerializer",
            "password_reset_confirm_retype": "auth_rest_phone.serializers.PasswordResetConfirmRetypeSerializer",
            "set_password": "auth_rest_phone.serializers.SetPasswordSerializer",
            "set_password_retype": "auth_rest_phone.serializers.SetPasswordRetypeSerializer",
            "set_username": "auth_rest_phone.serializers.SetUsernameSerializer",
            "set_username_retype": "auth_rest_phone.serializers.SetUsernameRetypeSerializer",
            "username_reset_with_sms": "auth_rest_phone.serializers.SendSMSResetSerializer",
            "username_reset": "auth_rest_phone.serializers.SendEmailResetSerializer",
            "username_reset_confirm": "auth_rest_phone.serializers.UsernameResetConfirmSerializer",
            "username_reset_confirm_with_sms": "auth_rest_phone.serializers.UsernameResetConfirmWithSMSSerializer",
            "username_reset_confirm_retype": "auth_rest_phone.serializers.UsernameResetConfirmRetypeSerializer",
            "user_create": "auth_rest_phone.serializers.UserCreateSerializer",
            "user_create_password_retype": "auth_rest_phone.serializers.UserCreatePasswordRetypeSerializer",
            "user_delete": "auth_rest_phone.serializers.UserDeleteSerializer",
            "user": "auth_rest_phone.serializers.UserSerializer",
            "current_user": "auth_rest_phone.serializers.UserSerializer",
            "token": "auth_rest_phone.serializers.TokenSerializer",
            "token_create": "auth_rest_phone.serializers.TokenCreateSerializer",
        }
    ),
    "EMAIL": ObjDict(
        {
            "activation": "auth_rest_phone.email.ActivationEmail",
            "confirmation": "auth_rest_phone.email.ConfirmationEmail",
            "password_reset": "auth_rest_phone.email.PasswordResetEmail",
            "password_changed_confirmation": "auth_rest_phone.email.PasswordChangedConfirmationEmail",
            "username_changed_confirmation": "auth_rest_phone.email.UsernameChangedConfirmationEmail",
            "username_reset": "auth_rest_phone.email.UsernameResetEmail",
        }
    ),
    "SMS": ObjDict(
        {
            "password_reset": "auth_rest_phone.sms.PasswordResetSMS",
        }
    ),
    "CONSTANTS": ObjDict({"messages": "auth_rest_phone.constants.Messages"}),
    "LOGOUT_ON_PASSWORD_CHANGE": False,
    "CREATE_SESSION_ON_LOGIN": False,
    "SOCIAL_AUTH_TOKEN_STRATEGY": "auth_rest_phone.social.token.jwt.TokenStrategy",
    "SOCIAL_AUTH_ALLOWED_REDIRECT_URIS": [],
    "HIDE_USERS": True,
    "PERMISSIONS": ObjDict(
        {
            "activation": ["rest_framework.permissions.AllowAny"],
            "register_user": ["rest_framework.permissions.AllowAny"],
            "guest_to_supplier":["rest_framework.permissions.AllowAny"],
            "add_to_group":["auth_rest_phone.permissions.CurrentUserOrAdmin"],
            "send_register_sms": ["rest_framework.permissions.AllowAny"],
            "send_guest_to_supplier_sms":["rest_framework.permissions.AllowAny"],
            "activation_with_sms": ["rest_framework.permissions.AllowAny"],
            "password_reset": ["rest_framework.permissions.AllowAny"],
            "password_reset_with_sms": ["rest_framework.permissions.AllowAny"],
            "password_reset_confirm": ["rest_framework.permissions.AllowAny"],
            "reset_password_confirm_with_sms": ["rest_framework.permissions.AllowAny"],
            "set_password": ["auth_rest_phone.permissions.CurrentUserOrAdmin"],
            "username_reset": ["rest_framework.permissions.AllowAny"],
            "username_reset_with_sms": ["rest_framework.permissions.AllowAny"],
            "username_reset_confirm": ["rest_framework.permissions.AllowAny"],
            "username_reset_confirm_with_sms": ["rest_framework.permissions.AllowAny"],
            "set_username": ["auth_rest_phone.permissions.CurrentUserOrAdmin"],
            "user_create": ["auth_rest_phone.permissions.CurrentUserOrAdmin"],
            "user_delete": ["auth_rest_phone.permissions.CurrentUserOrAdmin"],
            "user": ["auth_rest_phone.permissions.CurrentUserOrAdmin"],
            "user_list": ["auth_rest_phone.permissions.CurrentUserOrAdmin"],
            "token_create": ["rest_framework.permissions.AllowAny"],
            "token_destroy": ["rest_framework.permissions.IsAuthenticated"],
        }
    ),
}

SETTINGS_TO_IMPORT = ["TOKEN_MODEL", "SOCIAL_AUTH_TOKEN_STRATEGY"]


class Settings:
    def __init__(self, default_settings, explicit_overriden_settings: dict = None):
        if explicit_overriden_settings is None:
            explicit_overriden_settings = {}

        overriden_settings = (
            getattr(django_settings, AUTH_REST_SETTINGS_NAMESPACE, {})
            or explicit_overriden_settings
        )

        self._load_default_settings()
        self._override_settings(overriden_settings)
        self._init_settings_to_import()

    def _load_default_settings(self):
        for setting_name, setting_value in default_settings.items():
            if setting_name.isupper():
                setattr(self, setting_name, setting_value)

    def _override_settings(self, overriden_settings: dict):
        for setting_name, setting_value in overriden_settings.items():
            value = setting_value
            if isinstance(setting_value, dict):
                value = getattr(self, setting_name, {})
                value.update(ObjDict(setting_value))
            setattr(self, setting_name, value)

    def _init_settings_to_import(self):
        for setting_name in SETTINGS_TO_IMPORT:
            value = getattr(self, setting_name)
            if isinstance(value, str):
                setattr(self, setting_name, import_string(value))


class LazySettings(LazyObject):
    def _setup(self, explicit_overriden_settings=None):
        self._wrapped = Settings(default_settings, explicit_overriden_settings)


settings = LazySettings()


def reload_auth_rest_settings(*args, **kwargs):
    global settings
    setting, value = kwargs["setting"], kwargs["value"]
    if setting == AUTH_REST_SETTINGS_NAMESPACE:
        settings._setup(explicit_overriden_settings=value)


setting_changed.connect(reload_auth_rest_settings)
