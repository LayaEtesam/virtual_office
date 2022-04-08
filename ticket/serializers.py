from . import models
from rest_framework import serializers

class ThreadSerializer(serializers.ModelSerializer):
    class Meta :
        model = models.Thread
        fields = ('pk' , 'created', 'category', 'ticket_id','user1', 'user2', )
        read_only_fields = ('ticket_id' ,)


class MessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Message
        fields = ('pk' ,'created', 'last_updated', 'message', 'file', 'status', 'direction', 'thread', )

        