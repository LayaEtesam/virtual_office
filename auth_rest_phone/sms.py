from services.sms_send import  send_sms_pattern
import pyotp
# from django.contrib.auth.tokens import default_token_generator
# from templated_mail.mail import BaseEmailMessage

from auth_rest_phone import utils
from auth_rest_phone.conf import settings
from django.conf import settings as django_settings


# class ActivationEmail(BaseEmailMessage):
# template_name = "email/activation.html"

# def get_context_data(self):
#     # ActivationEmail can be deleted
#     context = super().get_context_data()

#     user = context.get("user")
#     context["uid"] = utils.encode_uid(user.pk)
#     context["token"] = default_token_generator.make_token(user)
#     context["url"] = settings.ACTIVATION_URL.format(**context)
#     return context


# class ConfirmationEmail(BaseEmailMessage):
# template_name = "email/confirmation.html"


# class PasswordResetEmail(BaseEmailMessage):
# template_name = "email/password_reset.html"

# def get_context_data(self):
# PasswordResetEmail can be deleted
# context = super().get_context_data()

# user = context.get("user")
# context["uid"] = utils.encode_uid(user.pk)
# context["token"] = default_token_generator.make_token(user)
# context["url"] = settings.PASSWORD_RESET_CONFIRM_URL.format(**context)
# return context


# class PasswordChangedConfirmationEmail(BaseEmailMessage):
# template_name = "email/password_changed_confirmation.html"


# class UsernameChangedConfirmationEmail(BaseEmailMessage):
# template_name = "email/username_changed_confirmation.html"


# class UsernameResetEmail(BaseEmailMessage):
# template_name = "email/username_reset.html"

# def get_context_data(self):
#     context = super().get_context_data()

#     user = context.get("user")
#     context["uid"] = utils.encode_uid(user.pk)
#     context["token"] = default_token_generator.make_token(user)
#     context["url"] = settings.USERNAME_RESET_CONFIRM_URL.format(**context)
#     return context


def PasswordResetSMS(key, phone):
    print(settings.LINE_NUMBER)
    # Time based otp
    # Here we are using Time Based OTP. The interval is 60 seconds.
    # otp must be provided within this interval or it's invalid
    time_otp = pyotp.TOTP(key, interval=settings.VALIDATE_OTP_INTERVAL)
    time_otp = time_otp.now()
    opts = {
        'patternName': "register",
        'mobileNumber': phone,
        "token":time_otp
    }
    if not django_settings.AUTH_SEND_SMS:
        print(time_otp)
        return True
    # elif sms.send(**opts):
    #     return True
    elif send_sms_pattern(**opts):
        return True
    else:
        return False
