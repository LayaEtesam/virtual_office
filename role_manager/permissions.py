from typing import OrderedDict
from coreapi.document import Document, Link, Object
from rest_framework import permissions
from rest_framework.schemas.coreapi import SchemaGenerator
from .models import ApiUrl
from django.urls import resolve
import re
# def dict_generator(indict):
#     global pre
#     for value in indict.keys():
#         if not isinstance(indict[value],Link):
#             dict_generator(indict[value])
#         else :
#             pre.append({"action":value,"url":indict[value].url})
#     pre = pre[:] if pre else []
#     if isinstance(indict, OrderedDict) and len(indict)!=0:
#         for value in indict.keys():
#             v = indict[value]
#             if isinstance(v.data, OrderedDict):
#                 for pre,leaf in dict_generator(v.data,pre):
#                     if leaf :
#                         pre.append({"action":value ,"links":v.links } )
#                         yield (pre,False) 
#                     else :
#                         yield (pre,False)
#             # elif isinstance(value, list) or isinstance(value, tuple):
#             #     for v in value:
#             #         for d in dict_generator(v):
#             #             return d
#             # else:
#             #     return pre + [key, value]
#     else:
#         yield (pre,True)

        # return (pre,True)
class HasGroupRolePermission(permissions.BasePermission):
    """
    Global permission check for blocked IPs.
    """

    def has_permission(self, request, view):
        user = request.user
        if user.is_superuser :
            return True
        user_groups =set (user.groups.all())
        current_url = resolve(request.path_info)
        # api_url = ApiUrl.objects.get()
        # generator = SchemaGenerator(
        #     title="RDMO API",
        #     # patterns=urlpatterns,
        #     # url=request.path
        # )
        # schema = generator.get_schema()
        # print(schema)
        # global pre 
        # pre = []
        # dict_generator(schema.data)
        # for i in pre:
        #     print(i)
        # actions = pre
        # endpoints = generator.endpoints
        # action_endpoints = {x['url']:x for x in lst1 + lst2}.values()
        var_re = re.compile(r"(<\w+:)(\w+)(>)")
        action_url = var_re.sub(r'{\2}', "/"+request._request.resolver_match.route)
        pk_re = re.compile(r"{pk}")
        action_url = pk_re.sub(r'{id}',action_url)
        action = request.parser_context["view"].action
        # print(action_url)
        api_url = ApiUrl.objects.get(url=action_url[:-1],action=action)
        api_groups = set(api_url.groups.all())
        intersect = user_groups.intersection(api_groups) 
        if len(intersect) == 0 :
            return False
        # for endpoint in endpoints:
        #     if endpoint[2].cls == view.__class__:
        #         print(candidate_endpoints)

        return True
        