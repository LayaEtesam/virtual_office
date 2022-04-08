from rest_framework_simplejwt.tokens import RefreshToken
# from phonenumber_field.serializerfields import PhoneNumberField
from drf_extra_fields.fields import Base64ImageField
from .models import PhoneOTP
from django.core.validators import RegexValidator
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core import exceptions as django_exceptions
from django.conf import settings as django_settings
from django.db import IntegrityError, transaction
from rest_framework import exceptions, serializers
from rest_framework.exceptions import ValidationError
from auth_rest_phone import utils
from auth_rest_phone.compat import get_user_email, get_user_email_field_name
from auth_rest_phone.conf import settings
from django.contrib.auth.models import  Group

import pyotp
User = get_user_model()
# ^(\+98|0)?9\d{9}$
phone_regex = RegexValidator(
    regex=r'^09[0-9]{9}$', message="Phone number must be entered in the format: '09999999999'. Up to 11 digits allowed.")


def generate_key():
    """ PhoneNumber otp key generator """
    key = pyotp.random_base32()
    # key = 100
    if is_unique(key):
        return key
    generate_key()


def is_unique(key):
    old_key = PhoneOTP.objects.filter(key__iexact=key)
    if old_key.exists():
        return False
    return True

def get_groups(user):
    groups = user.groups.all()
    groups_name = [i.name for i in groups]
    return groups_name

def authenticateOTP(key, otp):
    """ This method authenticates the given otp"""
    # provided_otp = 0
    # try:
    #     provided_otp = int(otp)
    # except:
    #     return False

    # Here we are using Time Based OTP. The interval is 60 seconds.
    # otp must be provided within this interval or it's invalid
    t = pyotp.TOTP(key, interval=settings.VALIDATE_OTP_INTERVAL)
    return t.verify(otp)


class UserSerializer(serializers.ModelSerializer):
    avatar = Base64ImageField(required=False)

    class Meta:
        model = User
        fields = tuple(User.REQUIRED_FIELDS) + (
            settings.USER_ID_FIELD,
            settings.LOGIN_FIELD, "email", "first_name", "last_name", "avatar","id"
        )
        read_only_fields = (settings.LOGIN_FIELD,)

    def update(self, instance, validated_data):
        email_field = get_user_email_field_name(User)
        if settings.SEND_ACTIVATION_EMAIL and email_field in validated_data:
            instance_email = get_user_email(instance)
            if instance_email != validated_data[email_field]:
                instance.is_active = False
                instance.save(update_fields=["is_active"])
        return super().update(instance, validated_data)

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user


class UserCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        style={"input_type": "password"}, write_only=True)

    default_error_messages = {
        "cannot_create_user": settings.CONSTANTS.messages.CANNOT_CREATE_USER_ERROR
    }
    avatar = Base64ImageField(required=False)

    class Meta:
        model = User
        fields = tuple(User.REQUIRED_FIELDS) + (
            settings.LOGIN_FIELD,
            settings.USER_ID_FIELD,
            "password", "email", "first_name", "last_name", "avatar"
        )
       
    def validate(self, attrs):
        user = User(**attrs)
        password = attrs.get("password")

        try:
            validate_password(password, user)
        except django_exceptions.ValidationError as e:
            serializer_error = serializers.as_serializer_error(e)
            raise serializers.ValidationError(
                {"password": serializer_error["non_field_errors"]}
            )

        return attrs

    def create(self, validated_data):
        try:
            print(self.context,validated_data)
            user = self.perform_create(validated_data)
        except IntegrityError:
            self.fail("cannot_create_user")

        return user

    def perform_create(self, validated_data):
        with transaction.atomic():
            user = User.objects.create_user(**validated_data)
            try:
                gr, cr = Group.objects.get_or_create(name=self.context["groups"])
                gr.user_set.add(user)
            except Exception as e:
                pass #group does not exist in context
            if settings.SEND_ACTIVATION_EMAIL:
                user.is_active = False
                user.save(update_fields=["is_active"])
            else :
                user.is_active = True
                user.save(update_fields=["is_active"])
        return user



class UserCreatePasswordRetypeSerializer(UserCreateSerializer):     
    class Meta:
        model = User
        fields = tuple(User.REQUIRED_FIELDS) + (
            settings.LOGIN_FIELD,
            settings.USER_ID_FIELD,
            "password", "email", "first_name", "last_name", "avatar"
        ) 
        extra_kwargs = {
            're_password': {'write_only': True},
        }  
    default_error_messages = {
        "password_mismatch": settings.CONSTANTS.messages.PASSWORD_MISMATCH_ERROR
    }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["re_password"] = serializers.CharField(
            style={"input_type": "password"}
        )

    def to_representation(self, instance):
        self.fields.pop('re_password',None)
        return super().to_representation(instance)

    def validate(self, attrs):
        self.fields.pop("re_password", None)
        re_password = attrs.pop("re_password")
        attrs = super().validate(attrs)
        if attrs["password"] == re_password:
            return attrs
        else:
            self.fail("password_mismatch")

class AdminUserCreateSerializer(UserCreatePasswordRetypeSerializer):
    def perform_create(self, validated_data):
        with transaction.atomic():
            user = User.objects.create_user(**validated_data)
            user.is_active =True
        return user


class TokenCreateSerializer(serializers.Serializer):
    password = serializers.CharField(
        required=False, style={"input_type": "password"})

    default_error_messages = {
        "invalid_credentials": settings.CONSTANTS.messages.INVALID_CREDENTIALS_ERROR,
        "inactive_account": settings.CONSTANTS.messages.INACTIVE_ACCOUNT_ERROR,
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = None
        self.fields[settings.LOGIN_FIELD] = serializers.CharField(
            required=False)

    def validate(self, attrs):
        password = attrs.get("password")
        params = {settings.LOGIN_FIELD: attrs.get(settings.LOGIN_FIELD)}
        self.user = authenticate(request=self.context.get(
            "request"), **params, password=password)
        if not self.user:
            self.user = User.objects.filter(**params).first()
            if self.user and not self.user.check_password(password):
                self.fail("invalid_credentials")
        if self.user and self.user.is_active:
            return attrs
        self.fail("invalid_credentials")


class UserFunctionsMixin:
    def get_user(self, is_active=True):
        try:
            user = User._default_manager.get(
                is_active=is_active,
                **{self.email_field: self.data.get(self.email_field, "")},
            )
            if user.has_usable_password():
                return user
        except User.DoesNotExist:
            pass
        if (
                settings.PASSWORD_RESET_SHOW_EMAIL_NOT_FOUND
                or settings.USERNAME_RESET_SHOW_EMAIL_NOT_FOUND
        ):
            self.fail("email_not_found")


class SendEmailResetSerializer(serializers.Serializer, UserFunctionsMixin):
    default_error_messages = {
        "email_not_found": settings.CONSTANTS.messages.EMAIL_NOT_FOUND
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.email_field = get_user_email_field_name(User)
        self.fields[self.email_field] = serializers.EmailField()


class UidAndTokenSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()

    default_error_messages = {
        "invalid_token": settings.CONSTANTS.messages.INVALID_TOKEN_ERROR,
        "invalid_uid": settings.CONSTANTS.messages.INVALID_UID_ERROR,
    }

    def validate(self, attrs):
        validated_data = super().validate(attrs)

        # uid validation have to be here, because validate_<field_name>
        # doesn't work with modelserializer
        try:
            uid = utils.decode_uid(self.initial_data.get("uid", ""))
            self.user = User.objects.get(pk=uid)
        except (User.DoesNotExist, ValueError, TypeError, OverflowError):
            key_error = "invalid_uid"
            raise ValidationError(
                {"uid": [self.error_messages[key_error]]}, code=key_error
            )

        is_token_valid = self.context["view"].token_generator.check_token(
            self.user, self.initial_data.get("token", "")
        )
        if is_token_valid:
            return validated_data
        else:
            key_error = "invalid_token"
            raise ValidationError(
                {"token": [self.error_messages[key_error]]}, code=key_error
            )


class ActivationSerializer(UidAndTokenSerializer):
    default_error_messages = {
        "stale_token": settings.CONSTANTS.messages.STALE_TOKEN_ERROR
    }

    def validate(self, attrs):
        attrs = super().validate(attrs)
        if not self.user.is_active:
            return attrs
        raise exceptions.PermissionDenied(self.error_messages["stale_token"])


class PasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(style={"input_type": "password"})

    def validate(self, attrs):
        user = self.context["request"].user or self.user
        # why assert? There are ValidationError / fail everywhere
        assert user is not None

        try:
            validate_password(attrs["new_password"], user)
        except django_exceptions.ValidationError as e:
            raise serializers.ValidationError(
                {"new_password": list(e.messages)})
        return super().validate(attrs)


class PasswordRetypeSerializer(PasswordSerializer):
    re_new_password = serializers.CharField(style={"input_type": "password"})

    default_error_messages = {
        "password_mismatch": settings.CONSTANTS.messages.PASSWORD_MISMATCH_ERROR
    }

    def validate(self, attrs):
        attrs = super().validate(attrs)
        if attrs["new_password"] == attrs["re_new_password"]:
            return attrs
        else:
            self.fail("password_mismatch")


class CurrentPasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(style={"input_type": "password"})

    default_error_messages = {
        "invalid_password": settings.CONSTANTS.messages.INVALID_PASSWORD_ERROR
    }

    def validate_current_password(self, value):
        is_password_valid = self.context["request"].user.check_password(value)
        if is_password_valid:
            return value
        else:
            self.fail("invalid_password")


class UsernameSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (settings.LOGIN_FIELD,)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.username_field = settings.LOGIN_FIELD
        self._default_username_field = User.USERNAME_FIELD
        self.fields["new_{}".format(self.username_field)] = self.fields.pop(
            self.username_field
        )

    def save(self, **kwargs):
        if self.username_field != self._default_username_field:
            kwargs[User.USERNAME_FIELD] = self.validated_data.get(
                "new_{}".format(self.username_field)
            )
        return super().save(**kwargs)


class PhoneSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("phone",)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.username_field = "phone"
        self._default_username_field = "phone"
        self.fields["new_{}".format(self.username_field)] = self.fields.pop(
            self.username_field
        )

    def save(self, **kwargs):
        if self.username_field != self._default_username_field:
            kwargs["phone"] = self.validated_data.get(
                "new_{}".format(self.username_field)
            )
        return super().save(**kwargs)


class SendOTPSerializer(PhoneSerializer):
    def validate(self, attrs):
        
        phone_number = attrs['phone']
        phone = PhoneOTP.objects.filter(phone=phone_number)
        if not phone.exists():
            key = generate_key()
            PhoneOTP.objects.create(
                phone=phone_number,
                key=key,
                # register=True,
                count=1
            )
            attrs['key'] = key
            return super().validate(attrs)
        else:
            phone = phone.first()
            count = phone.count
            key = phone.key
            if count >= settings.SEND_SMS_COUNT:  # and not django_settings.DEBUG:
                raise ValidationError(
                    {"OTP-PHONE": "Sending otp error. Limit exceeded. Please contact customer support."},
                    code="limit_exceed")
            phone.count = count + 1
            phone.save()
            # key = phone.values_list('key', flat=True).last()
            attrs['key'] = key
        return super().validate(attrs)


class SendSMSResetSerializer(serializers.Serializer):
    phone = serializers.CharField(validators=[phone_regex])

    default_error_messages = {
        "phone_not_found": settings.CONSTANTS.messages.PHONE_NOT_FOUND
    }

    def validate(self, attrs):
        phone_number = attrs.get("phone")
        user = User.objects.filter(phone=phone_number)
        if user.exists():
            phone = PhoneOTP.objects.filter(phone=phone_number)
            if not phone.exists():
                key = generate_key()
                PhoneOTP.objects.create(
                    phone=phone_number,
                    key=key,
                    # register=True,
                    count=1
                )
                attrs['key'] = key
                return super().validate(attrs)
            else:
                phone = phone.first()
                count = phone.count
                key = phone.key
                # if count >= settings.SEND_SMS_COUNT:  # and not django_settings.DEBUG:
                #     raise ValidationError(
                #         detail='Sending otp error. Limit exceeded. Please contact customer support.',
                #         code="limit_exceed")
                phone.count = count + 1
                phone.save()
                # key = phone.values_list('key', flat=True).last()
                attrs['key'] = key
            return super().validate(attrs)
        else:
            self.fail("phone_not_found")

class SendSMSAddTOGroupSerializer(serializers.Serializer):
    phone = serializers.CharField(validators=[phone_regex])
    default_error_messages = {
        "phone_not_found": settings.CONSTANTS.messages.PHONE_NOT_FOUND
    }
    def validate(self, attrs):
        phone_number = attrs.get("phone")
        user = User.objects.filter(phone=phone_number)
        if user.exists():
            phone = PhoneOTP.objects.filter(phone=phone_number)
            if not phone.exists():
                key = generate_key()
                PhoneOTP.objects.create(
                    phone=phone_number,
                    key=key,
                    # register=True,
                    count=1
                )
                attrs['key'] = key
                return super().validate(attrs)
            else:
                phone = phone.first()
                count = phone.count
                key = phone.key
                # if count >= settings.SEND_SMS_COUNT:  # and not django_settings.DEBUG:
                #     raise ValidationError(
                #         detail='Sending otp error. Limit exceeded. Please contact customer support.',
                #         code="limit_exceed")
                phone.count = count + 1
                phone.save()
                # key = phone.values_list('key', flat=True).last()
                attrs['key'] = key
            return super().validate(attrs)
        else:
            self.fail("phone_not_found")


class phoneAndOTPSerializer(serializers.Serializer):
    phone = serializers.CharField(validators=[phone_regex])
    # phone = PhoneNumberField()
    otp_sent = serializers.CharField()

    def validate(self, attrs):
        phone_number = attrs["phone"]
        otp_sent = attrs["otp_sent"]
        phone = PhoneOTP.objects.filter(phone=phone_number)
        if not phone.exists():
            raise ValidationError(
                detail='No OTP message has been sent for this number. First enter the number to send the message',
                code='invalid_API_access')
        key = phone.values_list('key', flat=True).last()
        if authenticateOTP(key, otp_sent):
            attrs = super().validate(attrs)
            self.otp = phone.first()
            return attrs
        raise ValidationError(
            detail='OTP INCOORECT.',
            code='otp_invalid')


class RegisterUserSerializer(UserCreateSerializer, phoneAndOTPSerializer):
    avatar = Base64ImageField(required=False)

    class Meta:
        model = User
        fields = (settings.LOGIN_FIELD,"phone", "password", "otp_sent",
                  "email", "first_name", "last_name", "avatar")

    def validate(self, attrs):
        attrs = phoneAndOTPSerializer.validate(self, attrs)
        attrs.pop('otp_sent')
        attrs = UserCreateSerializer.validate(self, attrs)
        return attrs

    def create(self, validated_data):
        user = super().create(validated_data)
        refresh = RefreshToken.for_user(user)
        token = {}
        token['refresh'] = str(refresh)
        token['access'] = str(refresh.access_token)
        self.token = token
        return user


class ActivationWithSMSSerializer(phoneAndOTPSerializer):
    default_error_messages = {
        "stale_sms_token": settings.CONSTANTS.messages.STALE_SMS_TOKEN_ERROR
    }

    def validate(self, attrs):
        phone_number = attrs["phone"]
        user = User.objects.filter(phone=phone_number)
        if not user.exists():
            raise ValidationError(
                detail='User profile with this phone number does not exists. First register phone number.',
                code='invalid_API_access')
        user = user.first()
        if not user.is_active:
            attrs = super().validate(attrs)
            self.user = user
            # self.otp = PhoneOTP.objects.get(phone=phone_number)
            return attrs
        raise exceptions.PermissionDenied(
            self.error_messages["stale_sms_token"])


class PasswordResetConfirmWithSMSSerializer(phoneAndOTPSerializer, PasswordSerializer):
    def validate(self, attrs):
        phone_number = attrs["phone"]
        user = User.objects.filter(phone=phone_number)
        if not user.exists():
            raise ValidationError(
                detail='User profile for this phone number does not exist. First register phone number.',
                code='invalid_API_access')
        attrs = super().validate(attrs)
        self.user = User.objects.get(phone=phone_number)
        # self.otp = PhoneOTP.objects.get(phone=phone_number)
        return attrs


class UsernameRetypeSerializer(UsernameSerializer):
    default_error_messages = {
        "username_mismatch": settings.CONSTANTS.messages.USERNAME_MISMATCH_ERROR.format(
            settings.LOGIN_FIELD
        )
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["re_new_" + settings.LOGIN_FIELD] = serializers.CharField()

    def validate(self, attrs):
        attrs = super().validate(attrs)
        new_username = attrs[settings.LOGIN_FIELD]
        if new_username != attrs["re_new_{}".format(settings.LOGIN_FIELD)]:
            self.fail("username_mismatch")
        else:
            return attrs


class TokenSerializer(serializers.ModelSerializer):
    auth_token = serializers.CharField(source="key")

    class Meta:
        model = settings.TOKEN_MODEL
        fields = ("auth_token",)


class UsernameResetConfirmWithSMSSerializer(phoneAndOTPSerializer):
    new_phone = serializers.CharField(validators=[phone_regex])

    def validate(self, attrs):
        phone_number = attrs["phone"]
        user = User.objects.filter(phone=phone_number)
        if not user.exists():
            raise ValidationError(
                detail='User profile for this phone number does not exist.',
                code='phone_dont_exist')
        attrs = super().validate(attrs)
        new_phone = attrs['new_phone']
        new_user = User.objects.filter(phone=new_phone)
        if new_user.exists():
            u = new_user.first()
            groups = get_groups(u)
            raise ValidationError(
                detail='Yuor new phone number already exist. Try with another number.',
                groups=groups,
                code='new_phone_exist')
        self.user = User.objects.get(phone=phone_number)
        # self.otp = PhoneOTP.objects.get(phone=phone_number)
        return attrs


class SetPasswordSerializer(PasswordSerializer, CurrentPasswordSerializer):
    pass


class SetPasswordRetypeSerializer(PasswordRetypeSerializer, CurrentPasswordSerializer):
    pass


class PasswordResetConfirmSerializer(UidAndTokenSerializer, PasswordSerializer):
    pass


class PasswordResetConfirmRetypeSerializer(
    UidAndTokenSerializer, PasswordRetypeSerializer
):
    pass


class UsernameResetConfirmSerializer(UidAndTokenSerializer, UsernameSerializer):
    pass


class UsernameResetConfirmRetypeSerializer(
    UidAndTokenSerializer, UsernameRetypeSerializer
):
    pass


class UserDeleteSerializer(CurrentPasswordSerializer):
    pass


class SetUsernameSerializer(UsernameSerializer, CurrentPasswordSerializer):
    class Meta:
        model = User
        fields = (settings.LOGIN_FIELD, 'current_password')


class SetUsernameRetypeSerializer(SetUsernameSerializer, UsernameRetypeSerializer):
    pass
