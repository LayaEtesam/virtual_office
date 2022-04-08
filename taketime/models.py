from django.db import models
from django.conf import settings


class Time(models.Model):
    SATURDAY = 'saturday'
    SUNDAY = 'sunday'
    MONDAY = 'monday'
    THURSDAY = 'thursday'
    WEDNESDAY = 'wednesday'
    THUSDAY = 'thusday'
    DAY_STATUS = ((SATURDAY , SATURDAY) ,(SUNDAY , SUNDAY), (MONDAY , MONDAY) ,(THURSDAY , THURSDAY), (WEDNESDAY , WEDNESDAY) , (THURSDAY , THURSDAY))

    T1 = '8-9'
    T2 = '9-10'
    T3 = '10-11'
    T4 = '11-12'
    TIME_STATUS = ((T1 , T1) , (T2 , T2) , (T3 , T3) , (T4 , T4))

    date = models.DateField()
    day = models.CharField( max_length=20, null=True, blank=True )
    user = models.ForeignKey(settings.AUTH_USER_MODEL , on_delete=models.CASCADE , related_name="Taketimes" , null=True , blank=True)
    time = models.CharField( max_length=10 , choices=TIME_STATUS )
    is_active = models.BooleanField(default=True)


    def __str__(self):
        return f"{self.user}   {self.date}"