from pyexpat import model
from rest_framework import serializers
from . import models
from auth_rest_phone.serializers import  UserCreatePasswordRetypeSerializer
from drf_writable_nested.serializers import WritableNestedModelSerializer
class InfoSeriaizers(WritableNestedModelSerializer):
    user = UserCreatePasswordRetypeSerializer()
    class Meta:
        model = models.Info
        fields = ("pk" , 'firstName', 'lastName', 'email', 'phone','nationalcode', 'user', 'userName', 'created', 'lastUpdated', )
    read_only_fields=('username',)