from django.http import Http404

from django.contrib.auth import get_user_model, update_session_auth_hash
from django.contrib.auth.tokens import default_token_generator

from django.utils.timezone import now
from rest_framework import generics, status, views, viewsets
from rest_framework.decorators import action, authentication_classes
from rest_framework.exceptions import NotFound
from rest_framework.response import Response

from . import signals, utils
from .compat import get_user_email
from .conf import settings
from django.conf import settings as django_settings
from django.shortcuts import get_object_or_404
import random
from .models import PhoneOTP
import pyotp
from .services.sms import sms, linenumber
from .jwt.serializers import CustomTokenObtainPairSerializer
from .authentication import CsrfExemptSessionAuthentication
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth.models import AnonymousUser
from django.contrib.auth.models import  Group

User = get_user_model()

def get_groups(user):
    groups = user.groups.all()
    groups_name = [i.name for i in groups]
    return groups_name

class TokenCreateView(utils.ActionViewMixin, generics.GenericAPIView):
    """
    Use this endpoint to obtain user authentication token.
    """

    serializer_class = settings.SERIALIZERS.token_create
    permission_classes = settings.PERMISSIONS.token_create
    # authentication_classes = [
    #     CsrfExemptSessionAuthentication, JWTAuthentication]

    def _action(self, serializer):
        token = utils.login_user(self.request, serializer.user)
        token_serializer_class = settings.SERIALIZERS.token
        return Response(
            data=token_serializer_class(token).data, status=status.HTTP_200_OK
        )


class TokenDestroyView(views.APIView):
    """
    Use this endpoint to logout user (remove user authentication token).
    """

    permission_classes = settings.PERMISSIONS.token_destroy

    def post(self, request):
        utils.logout_user(request)
        return Response(status=status.HTTP_204_NO_CONTENT)


class UserViewSet(viewsets.ModelViewSet):
    authentication_classes = [JWTAuthentication, ]
    serializer_class = settings.SERIALIZERS.user
    queryset = User.objects.all()
    permission_classes = settings.PERMISSIONS.user
    token_generator = default_token_generator
    lookup_field = settings.USER_ID_FIELD

    def permission_denied(self, request,  **kwargs):
        if (
            settings.HIDE_USERS
            and request.user.is_authenticated
            and self.action in ["update", "partial_update", "list", "retrieve"]
        ):
            raise NotFound()
        super().permission_denied(request,  **kwargs)

    def get_queryset(self):
        user = self.request.user
        queryset = super().get_queryset()
        if settings.HIDE_USERS and self.action == "list" and not user.is_staff:
            queryset = queryset.filter(pk=user.pk)
        return queryset

    def get_authenticators(self):
        """
        Instantiates and returns the list of authenticators that this view can use.
        """
        if django_settings.DEBUG:
            print("action is :", self.action_map.get(
                self.request.method.lower()))

        if self.action_map.get(self.request.method.lower()) == "create":
            return [auth() for auth in self.authentication_classes]
        elif self.action_map.get(self.request.method.lower()) == "list":
            return [auth() for auth in self.authentication_classes]
        elif self.action_map.get(self.request.method.lower()) == "retrieve":
            return [auth() for auth in self.authentication_classes]
        elif self.action_map.get(self.request.method.lower()) == "destroy":
            return [auth() for auth in self.authentication_classes]
        elif self.action_map.get(self.request.method.lower()) == "partial_update":
            return [auth() for auth in self.authentication_classes]
        elif self.action_map.get(self.request.method.lower()) == "update":
            return [auth() for auth in self.authentication_classes]
        elif self.action_map.get(self.request.method.lower()) == "me":
            return [auth() for auth in self.authentication_classes]
        elif self.action_map.get(self.request.method.lower()) == "set_password":
            return [auth() for auth in self.authentication_classes]
        elif self.action_map.get(self.request.method.lower()) == "token_destroy":
            return [auth() for auth in self.authentication_classes]
        elif self.action_map.get(self.request.method.lower()) == "set_username":
            return [auth() for auth in self.authentication_classes]
        elif self.action_map.get(self.request.method.lower()) == "user_create":
            return [auth() for auth in self.authentication_classes]
        elif self.action_map.get(self.request.method.lower()) == "user_delete":
            return [auth() for auth in self.authentication_classes]
        elif self.action_map.get(self.request.method.lower()) == "user":
            return [auth() for auth in self.authentication_classes]
        elif self.action_map.get(self.request.method.lower()) == "user_list":
            return [auth() for auth in self.authentication_classes]
        elif self.action_map.get(self.request.method.lower()) == "register_user":
            return []
        elif self.action_map.get(self.request.method.lower()) == "register_person":
            return []
        elif self.action_map.get(self.request.method.lower()) == "send_add_to_group_sms":
            return []
        else:
            return [auth() for auth in [CsrfExemptSessionAuthentication]]

        # return [auth() for aut h in self.authentication_classes]

    def get_permissions(self):
        if self.action == "create":
            self.permission_classes = settings.PERMISSIONS.user_create
        elif self.action == "send_register_sms":
            self.permission_classes = settings.PERMISSIONS.send_register_sms
        elif self.action == "register_user":
            self.permission_classes = settings.PERMISSIONS.register_user
        elif self.action == "register_person":
            self.permission_classes = settings.PERMISSIONS.register_user
        elif self.action == "activation":
            self.permission_classes = settings.PERMISSIONS.activation
        elif self.action == "activation_with_sms":
            self.permission_classes = settings.PERMISSIONS.activation
        elif self.action == "resend_activation":
            self.permission_classes = settings.PERMISSIONS.password_reset
        elif self.action == "resend_activation_with_sms":
            self.permission_classes = settings.PERMISSIONS.password_reset_with_sms
        elif self.action == "list":
            self.permission_classes = settings.PERMISSIONS.user_list
        elif self.action == "reset_password":
            self.permission_classes = settings.PERMISSIONS.password_reset
        elif self.action == "reset_password_confirm":
            self.permission_classes = settings.PERMISSIONS.password_reset_confirm
        elif self.action == "reset_password_with_sms":
            self.permission_classes = settings.PERMISSIONS.password_reset_with_sms
        elif self.action == "reset_password_confirm_with_sms":
            self.permission_classes = settings.PERMISSIONS.reset_password_confirm_with_sms
        elif self.action == "set_password":
            self.permission_classes = settings.PERMISSIONS.set_password
        elif self.action == "set_username":
            self.permission_classes = settings.PERMISSIONS.set_username
        elif self.action == "reset_username":
            self.permission_classes = settings.PERMISSIONS.username_reset
        elif self.action == "reset_username_with_sms":
            self.permission_classes = settings.PERMISSIONS.username_reset_with_sms
        elif self.action == "reset_username_confirm":
            self.permission_classes = settings.PERMISSIONS.username_reset_confirm
        elif self.action == "reset_username_confirm_with_sms":
            self.permission_classes = settings.PERMISSIONS.username_reset_confirm_with_sms
        elif self.action == "add_to_group":
            self.permission_classes = []
        elif self.action == "destroy" or (
            self.action == "me" and self.request and self.request.method == "DELETE"
        ):
            self.permission_classes = settings.PERMISSIONS.user_delete
        elif  self.action =="send_add_to_group_sms":
            return []
        return super().get_permissions()

    def get_serializer_class(self):
        if self.action == "create":
            if settings.USER_CREATE_PASSWORD_RETYPE:
                return settings.SERIALIZERS.user_create_password_retype
            return settings.SERIALIZERS.user_create
        elif self.action == "destroy" or (
            self.action == "me" and self.request and self.request.method == "DELETE"
        ):
            return settings.SERIALIZERS.user_delete
        elif self.action == "send_register_sms":
            return settings.SERIALIZERS.send_register_sms
        elif self.action == "send_add_to_group_sms":
            return settings.SERIALIZERS.send_add_to_group_sms
        elif self.action == "add_to_group":
            return settings.SERIALIZERS.add_to_group
        elif self.action == "register_user":
            return settings.SERIALIZERS.register_user
        elif self.action == "register_person":
            return settings.SERIALIZERS.register_user
        elif self.action == "reset_password_confirm_with_sms":
            return settings.SERIALIZERS.reset_password_confirm_with_sms
        elif self.action == "activation":
            return settings.SERIALIZERS.activation
        elif self.action == "activation_with_sms":
            return settings.SERIALIZERS.activation_with_sms
        elif self.action == "resend_activation":
            return settings.SERIALIZERS.password_reset
        elif self.action == "reset_password":
            return settings.SERIALIZERS.password_reset
        elif self.action == "resend_activation_with_sms":
            return settings.SERIALIZERS.password_reset_with_sms
        elif self.action == "reset_password_with_sms":
            return settings.SERIALIZERS.password_reset_with_sms
        elif self.action == "reset_password_confirm":
            if settings.PASSWORD_RESET_CONFIRM_RETYPE:
                return settings.SERIALIZERS.password_reset_confirm_retype
            return settings.SERIALIZERS.password_reset_confirm
        elif self.action == "set_password":
            if settings.SET_PASSWORD_RETYPE:
                return settings.SERIALIZERS.set_password_retype
            return settings.SERIALIZERS.set_password
        elif self.action == "set_username":
            if settings.SET_USERNAME_RETYPE:
                return settings.SERIALIZERS.set_username_retype
            return settings.SERIALIZERS.set_username
        elif self.action == "reset_username":
            return settings.SERIALIZERS.username_reset
        elif self.action == "reset_username_with_sms":
            return settings.SERIALIZERS.username_reset_with_sms
        elif self.action == "reset_username_confirm":
            if settings.USERNAME_RESET_CONFIRM_RETYPE:
                return settings.SERIALIZERS.username_reset_confirm_retype
            return settings.SERIALIZERS.username_reset_confirm
        elif self.action == "reset_username_confirm_with_sms":
            return settings.SERIALIZERS.username_reset_confirm_with_sms
        elif self.action == "me":
            return settings.SERIALIZERS.current_user

        return self.serializer_class

    def get_serializer_context(self):
        if self.action == "register_person": 
            try:
                return {
                    'request': self.request,
                    'format': self.format_kwarg,
                    'view': self,
                    'groups':self.groups
                }
            except:
                return {
                    'request': self.request,
                    'format': self.format_kwarg,
                    'view': self,
                    'groups':"guest"
                }
        else :
            return {
                'request': self.request,
                'format': self.format_kwarg,
                'view': self,
                'groups':"guest"
            }

    def get_instance(self):
        return self.request.user

    def perform_create(self, serializer):
        user = serializer.save()
        signals.user_registered.send(
            sender=self.__class__, user=user, request=self.request
        )

        context = {"user": user}
        to = [get_user_email(user)]
        if settings.SEND_ACTIVATION_EMAIL:
            settings.EMAIL.activation(self.request, context).send(to)
        elif settings.SEND_CONFIRMATION_EMAIL:
            settings.EMAIL.confirmation(self.request, context).send(to)

    def perform_update(self, serializer):
        super().perform_update(serializer)
        user = serializer.instance
        # should we send activation email after update?
        if settings.SEND_ACTIVATION_EMAIL:
            context = {"user": user}
            to = [get_user_email(user)]
            settings.EMAIL.activation(self.request, context).send(to)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data)
        serializer.is_valid(raise_exception=True)

        if instance == request.user:
            utils.logout_user(self.request)
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(["get", "put", "patch", "delete"], detail=False)
    def me(self, request, *args, **kwargs):
        self.get_object = self.get_instance
        if request.method == "GET":
            return self.retrieve(request, *args, **kwargs)
        elif request.method == "PUT":
            return self.update(request, *args, **kwargs)
        elif request.method == "PATCH":
            return self.partial_update(request, *args, **kwargs)
        elif request.method == "DELETE":
            return self.destroy(request, *args, **kwargs)

    @action(["post"], detail=False)
    def send_register_sms(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except Exception as e :
            user = User.objects.get(phone=request.data["new_phone"])
            groups = get_groups(user)
            return Response({
                'detail': 'user exist before',
                'code': 'user_exist_before',
                "groups":groups
            }, status=status.HTTP_400_BAD_REQUEST)
        if settings.SEND_CONFIRMATION_SMS:
            phone = serializer.validated_data['phone']
            key = serializer.validated_data['key']
            if settings.SMS.password_reset(key, phone):
                return Response({
                    'detail': 'OTP sent successfully',
                    'code': 'send_otp_success'
                })
            else:
                return Response({
                    'detail': 'Sending otp error',
                    'code': 'send_error'
                }, status=status.HTTP_400_BAD_REQUEST)

        else:
            return Response({
                'detail': 'We dont have sms service. Please contact customer support.',
                'code': 'server_error'
            }, status=status.HTTP_400_BAD_REQUEST)
    @action(["post"], detail=False)
    def send_add_to_group_sms(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if settings.SEND_CONFIRMATION_SMS:
            phone = serializer.validated_data['phone']
            key = serializer.validated_data['key']
            if settings.SMS.password_reset(key, phone):
                return Response({
                    'detail': 'OTP sent successfully',
                    'code': 'send_otp_success'
                })
            else:
                return Response({
                    'detail': 'Sending otp error',
                    'code': 'send_error'
                }, status=status.HTTP_400_BAD_REQUEST)

        else:
            return Response({
                'detail': 'We dont have sms service. Please contact customer support.',
                'code': 'server_error'
            }, status=status.HTTP_400_BAD_REQUEST)

    @action(["post"], detail=False)
    def register_user(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(is_active=True)
        serializer.otp.delete()
        token = serializer.token
        return Response({
            'detail': 'OTP MATCHED. Account created succesfully',
            'code': 'register_success',
            'token': token
        }, status=status.HTTP_200_OK)

    @action(["post"], detail=False)
    def add_to_group(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.otp.delete()
        try:
            user = User.objects.get(phone=serializer.data["phone"])
        except User.DoesNotExist:
            raise Http404 
        valid_groups = settings.AUTH_VALID_USER_GROUPS
        group=request.data.pop("group",None)
        if group not in valid_groups:
            return Response({
                'detail':"group not valid",
                'code':"group_not_valid"
            },status = status.HTTP_403_FORBIDDEN
        )
        gr, cr = Group.objects.get_or_create(name=group)
        gr.user_set.add(user)
        return Response({
            'detail': 'OTP MATCHED. Escalate Guest to Supplier  succesfully',
            'code': 'operation_success',
        }, status=status.HTTP_200_OK)

    @action(["post"], detail=False)
    def register_person(self, request, *args, **kwargs):
        data = request.data
        valid_groups = settings.AUTH_VALID_USER_GROUPS
        group=data.pop("group",None)
        print(group,valid_groups)
        if group in valid_groups:
            self.groups = group
        else :
            return Response({
                'detail':"group not valid",
                'code':"group_not_valid"
            },status = status.HTTP_403_FORBIDDEN)
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save(is_active=True)
        serializer.otp.delete()
        token = serializer.token
        return Response({
            'detail': 'OTP MATCHED. Account created succesfully',
            'code': 'register_success',
            'token': token
        }, status=status.HTTP_200_OK)

    @action(["post"], detail=False)
    def activation(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.user
        user.is_active = True
        user.save()

        signals.user_activated.send(
            sender=self.__class__, user=user, request=self.request
        )

        if settings.SEND_CONFIRMATION_EMAIL:
            context = {"user": user}
            to = [get_user_email(user)]
            settings.EMAIL.confirmation(self.request, context).send(to)

        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(["post"], detail=False)
    def activation_with_sms(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.user
        user.is_active = True
        user.save()
        serializer.otp.delete()

        signals.user_activated.send(
            sender=self.__class__, user=user, request=self.request
        )
        return Response({
            'detail': 'Account activated successfully.',
            'code': 'activat_success'
        })

    @action(["post"], detail=False)
    def resend_activation(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.get_user(is_active=False)

        if not settings.SEND_ACTIVATION_EMAIL or not user:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        context = {"user": user}
        to = [get_user_email(user)]
        settings.EMAIL.activation(self.request, context).send(to)

        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(["post"], detail=False)
    def resend_activation_with_sms(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if settings.SEND_CONFIRMATION_SMS:
            phone = serializer.validated_data['phone']
            key = serializer.validated_data['key']
            if settings.SMS.password_reset(key, phone):
                return Response({
                    'detail': 'OTP sent successfully',
                    'code': 'send_otp_success'
                })
            else:
                return Response({
                    'detail': 'Sending otp error',
                    'code': 'send_error'
                }, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({
                'detail': 'We dont have sms service. Please contact customer support.',
                'code': 'server_error'
            }, status=status.HTTP_400_BAD_REQUEST)

    @action(["post"], detail=False)
    def set_password(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        self.request.user.set_password(serializer.data["new_password"])
        self.request.user.save()

        if settings.PASSWORD_CHANGED_EMAIL_CONFIRMATION:
            context = {"user": self.request.user}
            to = [get_user_email(self.request.user)]
            settings.EMAIL.password_changed_confirmation(
                self.request, context).send(to)

        if settings.LOGOUT_ON_PASSWORD_CHANGE:
            utils.logout_user(self.request)
        elif settings.CREATE_SESSION_ON_LOGIN:
            update_session_auth_hash(self.request, self.request.user)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(["post"], detail=False)
    def reset_password(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.get_user()
        if user:
            context = {"user": user}
            to = [get_user_email(user)]
            settings.EMAIL.password_reset(self.request, context).send(to)

        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(["post"], detail=False)
    def reset_password_with_sms(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if settings.SEND_CONFIRMATION_SMS:
            phone = serializer.validated_data['phone']
            key = serializer.validated_data['key']
            if settings.SMS.password_reset(key, phone):
                return Response({
                    'detail': 'OTP sent successfully',
                    'code': 'send_otp_success'
                })
            else:
                return Response({
                    'detail': 'Sending otp error',
                    'code': 'send_error'
                }, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({
                'detail': 'We dont have sms service. Please contact customer support.',
                'code': 'server_error'
            }, status=status.HTTP_400_BAD_REQUEST)

    @action(["post"], detail=False)
    def reset_password_confirm(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        serializer.user.set_password(serializer.data["new_password"])
        if hasattr(serializer.user, "last_login"):
            serializer.user.last_login = now()
        serializer.user.save()

        if settings.PASSWORD_CHANGED_EMAIL_CONFIRMATION:
            context = {"user": serializer.user}
            to = [get_user_email(serializer.user)]
            settings.EMAIL.password_changed_confirmation(
                self.request, context).send(to)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(["post"], detail=False)
    def reset_password_confirm_with_sms(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.user.set_password(serializer.data["new_password"])
        if hasattr(serializer.user, "last_login"):
            serializer.user.last_login = now()
        serializer.user.save()
        serializer.otp.delete()

        return Response({
            'detail': 'Password changed successfuly.',
            'code': 'pass_change_success'
        })

    @action(["post"], detail=False, url_path="set_{}".format(User.USERNAME_FIELD))
    def set_username(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = self.request.user
        new_username = serializer.data["new_" + User.USERNAME_FIELD]

        setattr(user, User.USERNAME_FIELD, new_username)
        user.save()
        if settings.USERNAME_CHANGED_EMAIL_CONFIRMATION:
            context = {"user": user}
            to = [get_user_email(user)]
            settings.EMAIL.username_changed_confirmation(
                self.request, context).send(to)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(["post"], detail=False, url_path="reset_{}".format(User.USERNAME_FIELD))
    def reset_username(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.get_user()

        if user:
            context = {"user": user}
            to = [get_user_email(user)]
            settings.EMAIL.username_reset(self.request, context).send(to)

        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(["post"], detail=False, url_path="reset_{}_with_sms".format(User.USERNAME_FIELD))
    def reset_username_with_sms(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if settings.SEND_CONFIRMATION_SMS:
            phone = serializer.validated_data['phone']
            key = serializer.validated_data['key']
            if settings.SMS.password_reset(key, phone):
                return Response({
                    'detail': 'OTP sent successfully',
                    'code': 'send_otp_success'
                })
            else:
                return Response({
                    'detail': 'Sending otp error',
                    'code': 'send_error'
                }, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({
                'detail': 'We dont have sms service. Please contact customer support.',
                'code': 'server_error'
            }, status=status.HTTP_400_BAD_REQUEST)

    @action(
        ["post"], detail=False, url_path="reset_{}_confirm".format(User.USERNAME_FIELD)
    )
    def reset_username_confirm(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        new_username = serializer.data["new_" + User.USERNAME_FIELD]

        setattr(serializer.user, User.USERNAME_FIELD, new_username)
        if hasattr(serializer.user, "last_login"):
            serializer.user.last_login = now()
        serializer.user.save()

        if settings.USERNAME_CHANGED_EMAIL_CONFIRMATION:
            context = {"user": serializer.user}
            to = [get_user_email(serializer.user)]
            settings.EMAIL.username_changed_confirmation(
                self.request, context).send(to)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(
        ["post"], detail=False, url_path="reset_{}_confirm_with_sms".format(User.USERNAME_FIELD)
    )
    def reset_username_confirm_with_sms(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        new_username = serializer.data["new_" + User.USERNAME_FIELD]

        setattr(serializer.user, User.USERNAME_FIELD, new_username)
        if hasattr(serializer.user, "last_login"):
            serializer.user.last_login = now()
        serializer.user.is_active = False
        serializer.user.save()
        serializer.otp.delete()

        return Response({
            'detail': 'Your phone number change successfuly. Please activate it.',
            'code': 'phone_change_success'
        })
