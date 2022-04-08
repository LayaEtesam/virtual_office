from . import views
from django.urls import path, include
from rest_framework import routers

router=routers.DefaultRouter()
router.register(r'taketime',views.TaketimeView)
# router.register(r'time',views.TaketimeView)

urlpatterns = [ 
    path ('',include(router.urls)),
    path('reserve/' , views.ReserveTimeAPIView.as_view())

]