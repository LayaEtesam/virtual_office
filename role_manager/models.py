from django.urls import reverse
from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth import get_user_model
from django.contrib.auth import models as auth_models
from django.db import models as models


class ApiUrl(models.Model):

    # Fields
    created = models.DateTimeField(auto_now_add=True, editable=False)
    last_updated = models.DateTimeField(auto_now=True, editable=False)
    url = models.CharField(max_length=200)
    action = models.CharField(max_length=200 , null=True , blank=True)
    description = models.TextField(max_length=100 , null=True , blank=True)

    # Relationship Fields
    component = models.ManyToManyField(
        'role_manager.Component',
        related_name="apiurls", null=True , blank=True
    )
    groups = models.ManyToManyField(
        auth_models.Group,
        related_name="apiurls", null=True , blank=True
    )

    class Meta:
        ordering = ('-created',)

    def __str__(self):
        return f"{self.url} : {self.action}"


class ConsumerProject(models.Model):

    # Fields
    name = models.CharField(max_length=255)
    created = models.DateTimeField(auto_now_add=True, editable=False)
    last_updated = models.DateTimeField(auto_now=True, editable=False)
    description = models.TextField(max_length=100)


    class Meta:
        ordering = ('-created',)

    def __str__(self):
        return u'%s' % self.name

class Component(models.Model):

    # Fields
    name = models.CharField(max_length=255)
    created = models.DateTimeField(auto_now_add=True, editable=False)
    last_updated = models.DateTimeField(auto_now=True, editable=False)
    description = models.TextField(max_length=100)

    # Relationship Fields
    consumer = models.ForeignKey(
        'role_manager.ConsumerProject',
        on_delete=models.CASCADE, related_name="components", 
    )

    class Meta:
        ordering = ('-created',)

    def __str__(self):
        return u'%s' % self.name

