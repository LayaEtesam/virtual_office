import unittest
from django.urls import reverse
from django.test import Client
from .models import ApiUrl, ConsumerProject, Component
from django.contrib.auth.models import User
from django.contrib.auth.models import Group
from django.contrib.contenttypes.models import ContentType


def create_django_contrib_auth_models_user(**kwargs):
    defaults = {}
    defaults["username"] = "username"
    defaults["email"] = "username@tempurl.com"
    defaults.update(**kwargs)
    return User.objects.create(**defaults)


def create_django_contrib_auth_models_group(**kwargs):
    defaults = {}
    defaults["name"] = "group"
    defaults.update(**kwargs)
    return Group.objects.create(**defaults)


def create_django_contrib_contenttypes_models_contenttype(**kwargs):
    defaults = {}
    defaults.update(**kwargs)
    return ContentType.objects.create(**defaults)


def create_apiurl(**kwargs):
    defaults = {}
    defaults["url"] = "url"
    defaults["action"] = "action"
    defaults["description"] = "description"
    defaults.update(**kwargs)
    if "component" not in defaults:
        defaults["component"] = create_component()
    if "groups" not in defaults:
        defaults["groups"] = create_django_contrib_auth_models_group()
    return ApiUrl.objects.create(**defaults)


def create_consumerproject(**kwargs):
    defaults = {}
    defaults["name"] = "name"
    defaults["description"] = "description"
    defaults.update(**kwargs)
    return ConsumerProject.objects.create(**defaults)


def create_component(**kwargs):
    defaults = {}
    defaults["name"] = "name"
    defaults["description"] = "description"
    defaults.update(**kwargs)
    if "consumer" not in defaults:
        defaults["consumer"] = create_consumerproject()
    return Component.objects.create(**defaults)


class ApiUrlViewTest(unittest.TestCase):
    '''
    Tests for ApiUrl
    '''
    def setUp(self):
        self.client = Client()

    def test_list_apiurl(self):
        url = reverse('role_manager_apiurl_list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_create_apiurl(self):
        url = reverse('role_manager_apiurl_create')
        data = {
            "url": "url",
            "action": "action",
            "description": "description",
            "component": create_component().pk,
            "groups": create_django_contrib_auth_models_group().pk,
        }
        response = self.client.post(url, data=data)
        self.assertEqual(response.status_code, 302)

    def test_detail_apiurl(self):
        apiurl = create_apiurl()
        url = reverse('role_manager_apiurl_detail', args=[apiurl.pk,])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_update_apiurl(self):
        apiurl = create_apiurl()
        data = {
            "url": "url",
            "action": "action",
            "description": "description",
            "component": create_component().pk,
            "groups": create_django_contrib_auth_models_group().pk,
        }
        url = reverse('role_manager_apiurl_update', args=[apiurl.pk,])
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 302)


class ConsumerProjectViewTest(unittest.TestCase):
    '''
    Tests for ConsumerProject
    '''
    def setUp(self):
        self.client = Client()

    def test_list_consumerproject(self):
        url = reverse('role_manager_consumerproject_list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_create_consumerproject(self):
        url = reverse('role_manager_consumerproject_create')
        data = {
            "name": "name",
            "description": "description",
        }
        response = self.client.post(url, data=data)
        self.assertEqual(response.status_code, 302)

    def test_detail_consumerproject(self):
        consumerproject = create_consumerproject()
        url = reverse('role_manager_consumerproject_detail', args=[consumerproject.pk,])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_update_consumerproject(self):
        consumerproject = create_consumerproject()
        data = {
            "name": "name",
            "description": "description",
        }
        url = reverse('role_manager_consumerproject_update', args=[consumerproject.pk,])
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 302)


class ComponentViewTest(unittest.TestCase):
    '''
    Tests for Component
    '''
    def setUp(self):
        self.client = Client()

    def test_list_component(self):
        url = reverse('role_manager_component_list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_create_component(self):
        url = reverse('role_manager_component_create')
        data = {
            "name": "name",
            "description": "description",
            "consumer": create_consumerproject().pk,
        }
        response = self.client.post(url, data=data)
        self.assertEqual(response.status_code, 302)

    def test_detail_component(self):
        component = create_component()
        url = reverse('role_manager_component_detail', args=[component.pk,])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_update_component(self):
        component = create_component()
        data = {
            "name": "name",
            "description": "description",
            "consumer": create_consumerproject().pk,
        }
        url = reverse('role_manager_component_update', args=[component.pk,])
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 302)


