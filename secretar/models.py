from django.db import models
from django.conf import settings

class Infosec(models.Model):
    firstName = models.CharField(max_length=50)
    lastName = models.CharField(max_length=50)
    email = models.EmailField(max_length=50)
    phone = models.CharField(max_length=11)
    user = models.ForeignKey(settings.AUTH_USER_MODEL , on_delete=models.CASCADE , related_name="Infosec" , null=True , blank=True)
    userName = models.CharField(max_length= 16 , null=True , blank= True)
    nationalcode = models.CharField(max_length=10)
    created =models.DateTimeField(auto_now_add=True,editable=False)
    lastUpdated = models.DateTimeField(auto_now=True,editable=False)
    address = models.TextField(max_length= 200 , null= True , blank= True)



    def __str__(self):
        return f"{self.firstName}    {self.lastName}"
