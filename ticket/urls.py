from ticket import views
from django.urls import path, include
from rest_framework import routers

router=routers.DefaultRouter()
router.register(r'message',views.MessageViewSet)
router.register(r'thread' , views.ThreadViewSet)

urlpatterns = [ 
    path ('',include(router.urls))
]