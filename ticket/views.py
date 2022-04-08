from xml.dom import ValidationErr
from . import models
from . import serializers
from rest_framework import viewsets , permissions , response , status , exceptions
from auth_rest_phone import models as amodels
from rest_framework.parsers import FormParser , MultiPartParser , FileUploadParser
from role_manager.permissions import HasGroupRolePermission

class ThreadViewSet(viewsets.ModelViewSet):
    queryset = models.Thread.objects.all()
    serializer_class = serializers.ThreadSerializer
    permission_classes = [permissions.IsAuthenticated , HasGroupRolePermission]

    def create(self , request , *args , **kwargs):
        data = request.data

        if request.user.is_superuser:
            data['user2'] = request.user.id
            data['user1'] = data.get('user1')

        else:
            data['user1'] = request.user.id
        # users = amodels.UserProfile.objects.filter(is_superuser = False)
        # for item in users:
        #     us = {"id" : item.id }
        #     data['user1'] = us['id']
            superusers = amodels.UserProfile.objects.filter(is_superuser = True)
        
            user = [{"id" : i.id} for i in superusers][0]
            data['user2'] = user['id']
        serializer = self.get_serializer(data = data)
        serializer.is_valid (raise_exception = True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return response.Response(serializer.data , status=status.HTTP_201_CREATED , headers=headers)

class MessageViewSet(viewsets.ModelViewSet):
    queryset = models.Message.objects.all()
    serializer_class = serializers.MessageSerializer
    parser_classes = (FormParser , MultiPartParser)
    permission_classes = [permissions.IsAuthenticated]

    def create(self, request, *args, **kwargs):
        user = request.user
        thread_id = request.data.get('thread' , None)
        thread = 0
        data = request.data
        if (thread_id == None):
            assert exceptions.ValidationError(detail="please enter thread id" , code='thread_id_missed')

        try:
            thread = models.Thread.objects.get(id = thread_id)
        except models.Thread.DoesNotExist:
            assert exceptions.NotFound(
                detail='thread not found' , code= 'thread_not_found'
            )
        user1 = thread.user1
        user2 = thread.user2

        if user == user1:
            data["direction"] = 'u1tou2'

        elif user == user2:
            data["direction"] = 'u2tou1'

        serializer = self.get_serializer(data = data)
        serializer.is_valid(raise_exception = True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return response.Response(serializer.data , status= status.HTTP_201_CREATED , headers=headers)