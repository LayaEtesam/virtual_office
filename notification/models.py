from django.db import models
class Notification(models.Model):
    title = models.CharField(max_length= 50)
    description = models.TextField(max_length= 500)

    def __str__(self):
        return self.title
    