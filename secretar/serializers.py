from pyexpat import model
from rest_framework import serializers
from . import models
from auth_rest_phone.serializers import  UserCreatePasswordRetypeSerializer
from drf_writable_nested.serializers import WritableNestedModelSerializer
class InfoSecSeriaizers(WritableNestedModelSerializer):
    user = UserCreatePasswordRetypeSerializer()
    class Meta:
        model = models.Infosec
        fields = ("pk" , 'firstName', 'lastName', 'email', 'phone','nationalcode', 'user', 'userName','address', 'created', 'lastUpdated', )
    read_only_fields=('username',)