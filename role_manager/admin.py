from django.contrib import admin
from django import forms
from .models import ApiUrl, ConsumerProject, Component
from django.contrib.auth.models import Group
from django.contrib.auth.admin import GroupAdmin

class ApiUrlInline(admin.TabularInline):
    model = ApiUrl.groups.through

class ApiUrlAdminForm(forms.ModelForm):

    class Meta:
        model = ApiUrl
        fields = '__all__'


class ApiUrlAdmin(admin.ModelAdmin):
    form = ApiUrlAdminForm
    list_display = ['created', 'last_updated', 'url', 'action', 'description']
    readonly_fields = ['created', 'last_updated']

admin.site.register(ApiUrl, ApiUrlAdmin)


class ConsumerProjectAdminForm(forms.ModelForm):

    class Meta:
        model = ConsumerProject
        fields = '__all__'


class ConsumerProjectAdmin(admin.ModelAdmin):
    form = ConsumerProjectAdminForm
    list_display = ['name', 'created', 'last_updated', 'description']
    readonly_fields = [ 'created', 'last_updated']

admin.site.register(ConsumerProject, ConsumerProjectAdmin)


class ComponentAdminForm(forms.ModelForm):

    class Meta:
        model = Component
        fields = '__all__'


class ComponentAdmin(admin.ModelAdmin):
    form = ComponentAdminForm
    list_display = ['name', 'created', 'last_updated', 'description']
    readonly_fields = [ 'created', 'last_updated']

admin.site.register(Component, ComponentAdmin)

admin.site.unregister(Group)

@admin.register(Group)
class RoleManagerGroup(GroupAdmin):
    inlines = [ApiUrlInline, ]

