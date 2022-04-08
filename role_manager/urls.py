from django.urls import path, include
from rest_framework import routers

from . import api
from . import views

router = routers.DefaultRouter()
# router.register(r'apiurl', api.ApiUrlViewSet)
router.register(r'consumerproject', api.ConsumerProjectViewSet)
router.register(r'component', api.ComponentViewSet)


urlpatterns = (
    # urls for Django Rest Framework API
    path('', include(router.urls)),
    path("user_roles/",api.UserRolListAPIView.as_view()),
    path("test/<int:pk>/<str:test>/",api.Test.as_view()),
    # path("test/<int:pk>/<str:test>/",api.Test.as_view())

)