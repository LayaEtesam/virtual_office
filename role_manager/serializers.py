from . import models
from drf_extra_fields.fields import Base64ImageField
from auth_rest_phone.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import Group
from rest_framework import serializers
User = get_user_model()



class ConsumerProjectSerializer(serializers.ModelSerializer):

    class Meta:
        model = models.ConsumerProject
        fields = (
            'pk', 
            'name', 
            'created', 
            'last_updated', 
            'description', 
        )


class ComponentSerializer(serializers.ModelSerializer):

    class Meta:
        model = models.Component
        fields = (
            # 'pk', 
            'name', 
            # 'created', 
            # 'last_updated', 
            'description', 
        )




class ApiUrlSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.ApiUrl
        fields = (
            'pk', 
            'url', 
            'action', 
            'description', 
           
        )


class GroupSerializer(serializers.ModelSerializer):
    apiurls = ApiUrlSerializer(many=True)

    class Meta:
        model=Group
        exclude =["permissions",'id']

class UserRoleSerializer(serializers.ModelSerializer):
    components = serializers.SerializerMethodField()    

    groups = serializers.SerializerMethodField()
    class Meta:
        model = User
        fields = tuple(User.REQUIRED_FIELDS) + (
            settings.USER_ID_FIELD,
            settings.LOGIN_FIELD, "email", "first_name", "last_name","id",'groups', 'components'
        )
        read_only_fields = (settings.LOGIN_FIELD,)    
    def get_groups(self, obj):
        groups = obj.groups.all()
        return GroupSerializer(groups,many=True).data

    def get_components(self, obj):
        groups = obj.groups.all()
        component_list=[]
        for g in groups:
            apiurls = g.apiurls.all()
            for a in apiurls:
                components = a.component.all()
                for c in components:
                    component_list.append({"name":c.name,'description':c.description})
        

        component_list = [dict(t) for t in {tuple(d.items()) for d in component_list}]
        return component_list