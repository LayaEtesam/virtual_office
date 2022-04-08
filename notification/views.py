from . import models , serializers
from rest_framework import viewsets , views , permissions
from role_manager.permissions import HasGroupRolePermission


class NotificationView(viewsets.ModelViewSet):
    queryset = models.Notification.objects.all()
    serializer_class = serializers.NotificationSerializer      
    permission_classes = [permissions.IsAuthenticated , HasGroupRolePermission]
