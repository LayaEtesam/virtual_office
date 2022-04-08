from rest_framework import generics, permissions, status
from rest_framework.response import Response
from social_django.utils import load_backend, load_strategy

from auth_rest_phone.conf import settings
from auth_rest_phone.social.serializers import ProviderAuthSerializer


class ProviderAuthView(generics.CreateAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = ProviderAuthSerializer

    def get(self, request, *args, **kwargs):
        redirect_uri = request.GET.get("redirect_uri")
        redirect_uri_host = '/'.join(redirect_uri.split("/")[:3])
        # if redirect_uri_host not in settings.SOCIAL_AUTH_ALLOWED_REDIRECT_URIS:
        #     return Response(status=status.HTTP_400_BAD_REQUEST)
        strategy = load_strategy(request)
        strategy.session_set("redirect_uri", redirect_uri)

        backend_name = self.kwargs["provider"]
        backend = load_backend(strategy, backend_name,
                               redirect_uri=redirect_uri)

        authorization_url = backend.auth_url()
        return Response(data={"authorization_url": authorization_url})
