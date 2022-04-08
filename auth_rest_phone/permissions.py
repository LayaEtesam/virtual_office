from rest_framework import permissions
from rest_framework.permissions import SAFE_METHODS

from rest_framework.permissions import BasePermission, SAFE_METHODS

class CurrentUserOrAdmin(permissions.IsAuthenticated):
    def has_object_permission(self, request, view, obj):
        user = request.user
        return user.is_staff or obj.pk == user.pk


class CurrentUserOrAdminOrReadOnly(permissions.IsAuthenticated):
    def has_object_permission(self, request, view, obj):
        user = request.user
        if type(obj) == type(user) and obj == user:
            return True
        return request.method in SAFE_METHODS or user.is_staff

class ShopManagerPermissions(BasePermission):
    def has_permission(self, request, view):
        # if request.method in SAFE_METHODS:
        #     return True
        return request.user.groups.filter(name='shop_manager').exists() or request.user.is_superuser
