from django.db import IntegrityError
from django.db.models.signals import (
    m2m_changed, pre_save, post_save, pre_delete, post_delete)
from django.dispatch import Signal, receiver
from django.contrib.auth import get_user_model
import uuid
from django.conf import settings
# from hawala_app.models import UserContact, UserNotification, Notification

User = get_user_model()

# New user has registered.
user_registered = Signal(providing_args=["user", "request"])
# User has activated his or her account.
user_activated = Signal(providing_args=["user", "request"])


# def contact_changed(sender, **kwargs):
#     print("contact is changed")
#     pass


# m2m_changed.connect(
#     contact_changed, sender=UserContact.contact.through, weak=False)
# usercontact.contact.add(user)
# user.usercontact_set.remove(p)


# @receiver(post_save, sender=User,  dispatch_uid='post_save_uid_field')
# def post_save_register_user(sender, **kwargs):
#     instance = kwargs.get("instance")
#     created = kwargs.get("created")
#     if settings.DEBUG:
#         print("inside post save signal")
#     if created:  # and not instance.uid:
#         # if settings.DEBUG:
#         #     print("inside created")
#         # while True:
#         #     uid = uuid.uuid4().hex
#         #     is_unique = sender.objects.filter(uid__exact=uid)
#         #     if not is_unique.exists():
#         #         instance.uid = uid
#         #         if settings.DEBUG:
#         #             print("inside post save, uid is :", uid)
#         #         break
#         # if settings.DEBUG:
#         #     print('before save')
#         # instance.save()
#         # if settings.DEBUG:
#         #     print("after save")
#         phone = instance.phone
#         newuser, createstatus = UserContact.objects.get_or_create(
#             phone_number=phone)
#         if createstatus:
#             newuser.status = True
#             if settings.DEBUG:
#                 print("new user isn't contact of enyone")
#         else:
#             newuser.status = True
#             contacts = newuser.contact.all()
#             if settings.DEBUG:
#                 print("new user is contact of :")
#             message = "{} join to hawala".format(str(newuser.phone_number))
#             for entry in contacts:
#                 if settings.DEBUG:
#                     print(entry.phone, entry.pk)
#                 newnotification = UserNotification.objects.create(source_user_id=instance,
#                                                                   destination_user_id=entry,
#                                                                   message=message,
#                                                                   notification_type="join")
#                 Notification.objects.create(description=message,
#                                             user_id=entry,
#                                             content_object=newnotification)
#         newuser.save()
#     else:
#         if settings.DEBUG:
#             print("created flag is false or uid already exist :", str(instance.uid))


@receiver(pre_save, sender=User, dispatch_uid='pre_save_uid_field')
def pre_save_register_user(sender, **kwargs):
    instance = kwargs.get("instance")
    if settings.DEBUG:
        print("inside pre save signal")
    if not instance.uid:
        while True:
            uid = uuid.uuid4().hex
            is_unique = sender.objects.filter(uid__exact=uid)
            if not is_unique.exists():
                instance.uid = uid
                if settings.DEBUG:
                    print("new uid is :", uid)
                break
        if settings.DEBUG:
            print('end of pre save signal')
    else:
        if settings.DEBUG:
            print('user uid already exists, uid is :', str(instance.uid))
