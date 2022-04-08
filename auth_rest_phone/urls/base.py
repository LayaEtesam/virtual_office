from django.contrib.auth import get_user_model
from rest_framework.routers import DefaultRouter
from django.urls import path

from auth_rest_phone import views

router = DefaultRouter()
router.register("users", views.UserViewSet)

User = get_user_model()

urlpatterns = router.urls
# urlpatterns += [
# path('validate_phone/', views.validatePhoneSendOTP.as_view()),
# path('validate_otp/', views.ValidateOTP.as_view()),
# path('register/', views.Register.as_view())
# ]
