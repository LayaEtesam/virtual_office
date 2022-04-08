from .forms import UserAdminChangeForm, UserAdminCreationForm, AdminPasswordChangeForm
from .models import PhoneOTP
# from hawala_app.models import (UserContact, Notification, Transaction,
#                                Trustline, UserNotification)
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import Group


# from .models import UserProfile
from django.contrib.auth import get_user_model
# UserProfile = get_user_model()
User = get_user_model()
# hawala_app_Models = [UserContact, Notification, Transaction,
#                      Trustline, UserNotification]
admin.site.register(PhoneOTP)
# admin.site.register(hawala_app_Models)


class CustomUserAdmin(UserAdmin):
    # the forms to add and change user instances
    form = UserAdminChangeForm
    add_form = UserAdminCreationForm
    # change_password_form = AdminPasswordChangeForm

    # the fields to be used in desplaying the User model.
    # these override the definitions on the base UserAdmin
    # thet reference specific fields on auth.User
    # As a field, specify the method (avatar_tag) that will return the picture tag in the list of user profiles.
    list_display = ('phone', 'is_superuser', 'avatar_tag')
    list_filter = ('is_staff', 'is_active', 'is_superuser')
    fieldsets = (
        (None, {'fields': ('uid', 'phone', 'password')}),
        ('Personal info', {
         'fields': ('email', 'first_name', 'last_name', 'avatar')}),
        ('Permissions', {
            'fields': ('is_superuser', 'is_staff', 'is_active'),
        }),
        ('Important dates', {'fields': ('last_login', "date_joined")}),
    )

    # add_fieldsets is not a standard ModelAdmin attribute. UserAdmin
    # overrides get_fieldsets to use this attribute when creating a user.
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('phone', 'password1', 'password2'),
        }),
    )

    search_fields = ('phone', 'first_name', 'last_name')
    ordering = ('phone',)
    filter_horizontal = ()

    def get_inline_instances(self, request, obj=None):
        if not obj:
            return list()
        return super(CustomUserAdmin, self).get_inline_instances(request, obj)


admin.site.register(User, CustomUserAdmin)

# remove Group Model from admin. we're not using it.
# admin.site.unregister(Group)
