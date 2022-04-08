from rest_framework.views import APIView
from rest_framework.response import Response
from . import models
from . import serializers
from rest_framework import viewsets, permissions
from role_manager import permissions as role_permissions
from rest_framework.generics import ListAPIView, RetrieveAPIView
# class ApiUrlViewSet(viewsets.ModelViewSet):
#     """ViewSet for the ApiUrl class"""

#     queryset = models.ApiUrl.objects.all()
#     serializer_class = serializers.ApiUrlSerializer
#     permission_classes = [permissions.IsAuthenticated,role_permissions.HasGroupRolePermission]




class UserRolListAPIView(RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = serializers.UserRoleSerializer
    def retrieve(self, request, *args, **kwargs):
        instance = request.user
        serializer = self.get_serializer(instance)
        return Response(serializer.data)


class ConsumerProjectViewSet(viewsets.ModelViewSet):
    """ViewSet for the ConsumerProject class"""

    queryset = models.ConsumerProject.objects.all()
    serializer_class = serializers.ConsumerProjectSerializer
    permission_classes = [permissions.IsAuthenticated]


class ComponentViewSet(viewsets.ModelViewSet):
    """ViewSet for the Component class"""

    queryset = models.Component.objects.all()
    serializer_class = serializers.ComponentSerializer
    permission_classes = [permissions.IsAuthenticated]

class Test(APIView):
    permission_classes = [permissions.IsAuthenticated,role_permissions.HasGroupRolePermission]

    def get(self,request,*args,**kwargs):
        return Response({"status":"ok"})
