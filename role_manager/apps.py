from django.apps import AppConfig
from django.db.utils import ProgrammingError
def dict_generator(indict):
    from coreapi.document import  Link
    global pre
    for value in indict.keys():
        if not isinstance(indict[value],Link):
            dict_generator(indict[value])
        else :
            pre.append({"action":value,"url":indict[value].url})

class RoleManagerConfig(AppConfig):
    name = 'role_manager'
    def ready(self):
        from rest_framework.schemas.coreapi import SchemaGenerator
        from .models import ApiUrl
        try:
            api_url_query = ApiUrl.objects.all()
            api_url_list = [ {"action":i.action,"url":i.url} for i in api_url_query]
            # print(api_url_list)
            generator = SchemaGenerator(
                title="RDMO API",
                # patterns=urlpatterns,
                # url=request.path
            )
            schema = generator.get_schema()
            global pre 
            pre = []
            dict_generator(schema.data)
            list_dict_api_urls = list(ApiUrl.objects.values("id"))
            list_id_api_urls = [i["id"] for i in list_dict_api_urls]
            for i in pre:
                try:
                    api_url = ApiUrl.objects.get(action=i["action"],url=i["url"])
                    list_id_api_urls.remove(api_url.id)
                except ApiUrl.DoesNotExist:
                    d = ApiUrl(action=i["action"],url=i["url"])
                    d.save()
            for i in list_id_api_urls:
                obj = ApiUrl.objects.get(id=i)
                obj.delete()
        except ProgrammingError:
            print("please migrate role_manager ")