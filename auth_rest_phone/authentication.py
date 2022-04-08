from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
UserModel = get_user_model()

class CsrfExemptSessionAuthentication(BasicAuthentication):

    def enforce_csrf(self, request):
        print("heeeellllooooo")
        return  # To not perform the csrf check previously happening

class MobileModelBackend(ModelBackend):
    def authenticate(self, request, phone=None, password=None, **kwargs):
        try:
            user = UserModel.objects.get(phone=phone)
        except UserModel.DoesNotExist:
            # Run the default password hasher once to reduce the timing
            # difference between an existing and a nonexistent user (#20760).
            UserModel().set_password(password)
        else:
            if user.check_password(password) and self.user_can_authenticate(user):
                return user