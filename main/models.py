# Create your models here.
import json
import uuid

from channels.db import database_sync_to_async
from django.contrib.auth.models import User
from django.core.serializers.json import DjangoJSONEncoder
from django.core.validators import MaxValueValidator
from django.db import models
from django.dispatch import Signal
from django.utils import timezone
from pusher.errors import PusherError

from ReiserX_Tunnel.settings import pusher_client
from main.Utils import send_message_to_device


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    api = models.CharField(max_length=255, blank=True)
    connected_clients = models.ManyToManyField('Client', blank=True)
    max_receiver = models.IntegerField(validators=[MaxValueValidator(10)], default=1)
    status = models.BooleanField(default=False)
    image = models.ImageField(default=None, upload_to='profile_pics/')
    auto_save = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        if not self.api:
            # Generate a unique API key if it doesn't exist
            self.api = str(uuid.uuid4())

        super().save(*args, **kwargs)

    def add_connected_client(self, client):
        if self.connected_clients.count() < self.max_receiver:
            self.connected_clients.get_or_create(client_id=client)
            return True
        return False

    def regenerate_api_key(self):
        # Regenerate the API key
        self.api = str(uuid.uuid4())
        self.save()

    @staticmethod
    @database_sync_to_async
    def get_user(api):
        try:
            user_profile = UserProfile.objects.get(api=api)
            return user_profile.user
        except UserProfile.DoesNotExist:
            return None

    @database_sync_to_async
    def remove_client(self, client_id):
        client_instance = Client.objects.get(client_id=client_id)
        if client_instance in self.connected_clients.all():
            client_instance.delete()
            self.save()
        return

    # Create a user profile for each user
    def create_user_profile(sender, instance, created, **kwargs):
        if created:
            UserProfile.objects.create(user=instance)

    # Connect the user profile creation to the User model's post_save signal
    from django.db.models.signals import post_save
    post_save.connect(create_user_profile, sender=User)


class Client(models.Model):
    client_id = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return self.client_id


class Room(models.Model):
    room = models.CharField(max_length=128, unique=True)
    sender_status = models.BooleanField(default=False, null=True)
    receiver_status = models.BooleanField(default=False, null=True)
    sender_username = models.CharField(max_length=128, default=None)
    receiver_username = models.CharField(max_length=128, default=None)

    def __str__(self):
        return f'{self.room}'

    def delete_all_messages(self):
        # Delete all messages associated with this room
        Message.objects.filter(room=self).delete()

    def get_last_message(self):
        last_message = Message.objects.filter(room=self).order_by('-timestamp').first()
        return last_message if last_message else None


new_signal_message = Signal()
connected_users = {}


def get_connected_users():
    return connected_users


class Message(models.Model):
    message_id = models.CharField(primary_key=True, max_length=16)
    message = models.TextField(max_length=10000)
    timestamp = models.DateTimeField(auto_now_add=True)
    room = models.ForeignKey(Room, on_delete=models.CASCADE, related_name='rooms')
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sender_rooms')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='receiver_rooms')
    reply_id = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='replies', default=None)
    temp = models.ForeignKey(User, on_delete=models.CASCADE, related_name='temp', null=True, blank=True, default=None)
    saved = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        if self.temp and get_connected_users().get(self.receiver.username) and not self.saved:
            time = timezone.now()
            new_signal_message.send(sender=Message, message=self.message, timestamp=time, sender_username=self.sender.username)
        elif self.temp and not self.saved:
            time = timezone.now()
            message_data = {
                'message': self.message,
                'timestamp': time,
                'sender_username': self.sender.username,
                'temp_username': self.temp.username if self.temp else None,
            }
            message_data = json.dumps(message_data, cls=DjangoJSONEncoder)
            try:
                # Your Pusher API calls here
                pusher_client.trigger(f'{self.receiver.username}-channel', f'{self.receiver.username}-new-message',
                                      message_data)
            except PusherError:
                pass
            send_message_to_device(self.receiver, f'{self.sender.username}: sent a message', message=self.message)

        super().save(*args, **kwargs)

    def get_sender_username(self):
        return self.sender.username

    def get_receiver_username(self):
        return self.receiver.username