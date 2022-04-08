from django.db import models
from django.conf import settings
import uuid


def generate_ticket_id():
    return str(uuid.uuid4()).split("-")[-1]

class Thread (models.Model):
    #fields
    created = models.DateTimeField(auto_now_add=True , editable= False)
    category = models.CharField(max_length= 50 , null= True , blank= True)
    ticket_id = models.CharField(max_length=255 , blank=True)


    def save(self , *args , **kwargs):
        if len(self.ticket_id.strip(' '))==0:
            self.ticket_id = generate_ticket_id()

            super(Thread , self).save(*args , **kwargs)


    #relationship fields
    user1 = models.ForeignKey(settings.AUTH_USER_MODEL , on_delete=models.CASCADE , related_name='thread_u1')
    user2 = models.ForeignKey(settings.AUTH_USER_MODEL , on_delete=models.CASCADE , related_name='thread_u2')

    class Meta:
        ordering = ('-created' , )

    def __str__(self):
        return f'{self.category} : {self.pk}'

class Message(models.Model):
    DELIVERED = "delivered"
    READ =  "read"
    ANSWERED = "answered"
    STATUS_TYPE = ((DELIVERED , DELIVERED) , (READ , READ) , (ANSWERED , ANSWERED))

    U1TOU2 = "u1tou2"
    U2TOU1 = "u2tou1"
    DIRECTION_TYPE = ((U1TOU2 , U1TOU2) , (U2TOU1 , U2TOU1))

    #fields 
    created = models.DateTimeField(auto_now_add=True , editable= False)
    last_updated = models.DateTimeField(auto_now= True , editable= False)
    message = models.TextField(max_length= 1000)
    file = models.FileField(upload_to="upload/message_files/" , blank=True , null=True)
    status = models.CharField(max_length=10 , choices=STATUS_TYPE)
    direction = models.CharField(max_length=7 , choices=DIRECTION_TYPE)

    #relationship fields
    thread = models.ForeignKey('ticket.Thread' , on_delete=models.CASCADE , related_name= 'messages')