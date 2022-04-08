# from django.db import models

# from django.contrib.auth.models import AbstractUser
# from django.contrib.auth.models import (
#     AbstractBaseUser, BaseUserManager, PermissionsMixin
# )
# # from django.contrib.auth.models import User

# from django.core.validators import EmailValidator
# from phone.models import TimestampedModel


# class UserProfile(AbstractUser, TimestampedModel):

#     email = models.CharField(
#         max_length=150,
#         unique=True,
#         validators=[validate_email]
#     )

#     is_active = models.BooleanField(default = True)

#     is_staff = models.BooleanField(default = False)

#     # USERNAME_FIELD = 'email'
#     enable_authenticator = models.BooleanField(default=False) #We can use this to enable 2fa for users
#     # objects = UserManager()

#     class Meta(AbstractUser.Meta):
#         # verbose_name ='user'
#         # verbose_name_plural = 'users'
#         pass


#     def __str__(self):
#         """
#         Returns a string representation of this `User`.
#         This string is used when a `User` is printed in the console.
#         """
#         return self.email

#     def get_short_name(self):

#         return self.first_name
from django.contrib import auth
from django.utils import timezone
from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser, BaseUserManager, PermissionsMixin
)
from django.core.validators import EmailValidator
from django.core.validators import RegexValidator
from django.utils.safestring import mark_safe
from django.conf import settings
from django.contrib.auth.models import Group


# if not Group.objects.filter(name__exact="shop_manager").exists():
#    Group.objects.create(name="shop_manager")

class UserManager(BaseUserManager):
    """
    Django requires that custom users define their own Manager class. By
    inheriting from `BaseUserManager`, we get a lot of the same code used by
    Django to create a `User` for free. 
    All we have to do is override the `create_user` function which we will use
    to create `User` objects.
    """

    def _create_user(self, phone, password, **extra_fields):
        """
        Create and save a user with the given phone, email, and password.
        """
        if not phone:
            raise ValueError('user must have a phone number')

        # email = self.normalize_email(email)
        user_obj = self.model(phone=phone, **extra_fields)
        user_obj.set_password(password)
        user_obj.save(using=self._db)
        return user_obj

    def create_user(self, phone, password=None, **extra_fields):
        """Create and return a `User` with an phone and password."""
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(phone, password, **extra_fields)

    def create_superuser(self, phone, password=None, **extra_fields):
        """
        Create and return a `User` with superuser powers.
        Superuser powers means that this use is an admin that can do anything
        they want.
        """
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(phone, password, **extra_fields)

    def create_staffuser(self, phone, password=None, **extra_fields):
        """
        Create and return a `User` with staffuser powers.
        staffuser powers means that ...
        """
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', False)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('staffuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not False:
            raise ValueError('staffuser must have is_superuser=False.')

        return self._create_user(phone, password, **extra_fields)

    def with_perm(self, perm, is_active=True, include_superusers=True, backend=None, obj=None):
        if backend is None:
            backends = auth._get_backends(return_tuples=True)
            if len(backends) == 1:
                backend, _ = backends[0]
            else:
                raise ValueError(
                    'You have multiple authentication backends configured and '
                    'therefore must provide the `backend` argument.'
                )
        elif not isinstance(backend, str):
            raise TypeError(
                'backend must be a dotted import path string (got %r).'
                % backend
            )
        else:
            backend = auth.load_backend(backend)
        if hasattr(backend, 'with_perm'):
            return backend.with_perm(
                perm,
                is_active=is_active,
                include_superusers=include_superusers,
                obj=obj,
            )
        return self.none()

# class UserManager(BaseUserManager):
#     def create_user(self, phone, password=None, is_staff=False, is_active=True, is_admin=False):
#         """
#         Creates and saves a User with the given phone and password.
#         """
#         if not phone:
#             raise ValueError('Users must have an phone number')
#         if not password:
#             raise ValueError('Users must have an password')


#         user_obj = self.model(
#             phone=phone
#         )

#         user_obj.set_password(password)
#         user_obj.staff = is_staff
#         user_obj.active = is_active
#         user_obj.admin = is_admin
#         user_obj.save(using=self._db)
#         return user_obj

#     def create_staffuser(self, phone, password=None):
#         """
#         Creates and saves a staff user with the given phnoe and password.
#         """
#         user = self.create_user(
#             phone,
#             password=password,
#             is_staff=True,
#         )
#         return user

#     def create_superuser(self, phone, password):
#         """
#         Creates and saves a superuser with the given phone and password.
#         """
#         user = self.create_user(
#             phone,
#             password=password,
#             is_staff=True,
#             is_admin=True,
#         )
#         return user

# todo staff user and superuser access must change.
# todo superuser access must be higher than staff user
class UserProfile(AbstractBaseUser, PermissionsMixin):

    def user_directory_path(instance, filename):
        extension = filename.split('.')[-1]
        # file will be uploaded to MEDIA_ROOT/avatar/<uid>.<extension>
        return 'avatar/{0}.{1}'.format(instance.uid, extension)

    # Apply custom validation either here, or in the view.
    # ^(\+98|0)?9\d{9}$
    phone_regex = RegexValidator(
        regex=r'^09[0-9]{9}$', message="Phone number must be entered in the format: '09999999999'. Up to 11 digits allowed.")
    validate_email = EmailValidator(code='invalid_email')
    username = models.CharField(max_length=15, unique=True)
    phone = models.CharField(
        validators=[phone_regex], max_length=15, unique=True)
    email = models.CharField(
        validators=[validate_email], max_length=150, null=True, unique=True)
    uid = models.CharField(max_length=50, unique=True, null=True)
    first_name = models.CharField(max_length=150, blank=True, null=True)
    last_name = models.CharField(max_length=150, blank=True, null=True)
    avatar = models.ImageField(
        upload_to=user_directory_path, default='avatar/default_avatar.jpg', null=True, blank=True)
    is_active = models.BooleanField(default=False)
    # a admin user; non super-user
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)  # a superuser
    # last_login = models.DateTimeField(auto_now_add=True)
    # notice the absence of a "Password field", that is built in
    # We can use this to enable 2fa for users
    enable_authenticator = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['phone',]  # phone & Password are required by default.

    objects = UserManager()

    def __str__(self):
        return self.phone

    def get_full_name(self):
        """
        Return the first_name plus the last_name, with a space in between.
        """
        if self.first_name and self.last_name:
            full_name = '%s %s' % (self.first_name, self.last_name)
            return full_name.strip()
        else:
            return self.phone

    def get_short_name(self):
        """Return the short name for the user."""
        if self.first_name:
            return self.first_name
        else:
            return self.phone

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def active(self):
        "Is the user active?"
        return self.is_active

    @property
    def staff(self):
        "Is the user a member of staff?"
        return self.is_staff

    # @property
    # def is_admin(self):
    #     "Is the user a admin member?"
    #     return self.is_superuser

    @property
    def superuser(self):
        "Is the user a admin member?"
        return self.is_superuser

    # Here I return the avatar or default picture, if the avatar is not selected
    def get_avatar(self):
        if not self.avatar:
            return '/avatar/default_avatar.jpg'
        return self.avatar.url

    # method to create a fake table field in read only mode
    def avatar_tag(self):
        img_tag = '<img src="%s" width="50" height="50" />' % self.get_avatar()
        # use mark_safe to indicate that the text is trusted (i.e. not coming from userinput).
        return mark_safe(img_tag)
        # return img_tag

    avatar_tag.short_description = 'avatar'


class PhoneOTP(models.Model):
    # Apply custom validation either here, or in the view.
    # ^(\+98|0)?9\d{9}$
    phone_regex = RegexValidator(
        regex=r'^09[0-9]{9}$', message="Phone number must be entered in the format: '09999999999'. Up to 11 digits allowed.")

    phone = models.CharField(
        validators=[phone_regex], max_length=15, unique=True)
    key = models.CharField(max_length=100, blank=True)  # unique=True,
    # otp = models.CharField(max_length=9, blank=True, null=True)
    count = models.IntegerField(default=0, help_text='Number of otp send')
    created = models.DateTimeField(default=timezone.now)
    validated = models.BooleanField(
        default=False, help_text='IF it is true, that means user have validate otp correctly in second API')
    logged = models.BooleanField(
        default=False, help_text='If otp verification got successful')
    forget = models.BooleanField(
        default=False, help_text='Only true for forget password')
    forget_logged = models.BooleanField(
        default=False, help_text='Only true if validate otp forget get successful')

    def __str__(self):
        return str(self.phone) + ' is sent ' + str(self.key)


