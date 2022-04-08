
from django.contrib import admin
from django.urls import path , re_path , include
from rest_framework import permissions
from drf_yasg2.views import get_schema_view
from drf_yasg2 import openapi
# from django.conf.urls import url

schema_view = get_schema_view(
    openapi.Info(
        title="Snippets API",
        default_version='v1',
        description="Test description",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="contact@snippets.local"),
        license=openapi.License(name="BSD License"),
      ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path('admin/', admin.site.urls),
    re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    path('info/',include('info.urls')),
    path('ticket/',include('ticket.urls')),
    path('auth/',include('auth_rest_phone.urls')),
    path('auth/',include('auth_rest_phone.urls.jwt')),
    path('notification/' , include('notification.urls')),
    path('taketime/' , include('taketime.urls')),
    path('role_manager/', include('role_manager.urls')),
    path(r'api/captcha/', include('rest_captcha.urls')),
    path('secretar/' , include('secretar.urls')),

    ]

