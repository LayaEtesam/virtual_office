from . import models
from rest_framework import serializers

class TimeSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Time
        fields = ('pk' , 'date', 'day', 'user', 'time' , 'is_active')
