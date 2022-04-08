from . import views
from django.urls import path, include
from rest_framework import routers

router=routers.DefaultRouter()
router.register(r'notification',views.NotificationView)

urlpatterns = [ 
    path ('',include(router.urls))

]