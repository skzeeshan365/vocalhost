# Create your models here.
import hashlib
import uuid

from channels.db import database_sync_to_async
from django.contrib.auth.models import User
from django.core.validators import MaxValueValidator
from django.db import models


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    api = models.CharField(max_length=255, blank=True)
    connected_clients = models.ManyToManyField('Client', blank=True)
    max_receiver = models.IntegerField(validators=[MaxValueValidator(10)], default=1)
    status = models.BooleanField(default=False)

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

    def __str__(self):
        return f'{self.room}'

    def delete_all_messages(self):
        # Delete all messages associated with this room
        Message.objects.filter(room=self).delete()


class Message(models.Model):
    message = models.TextField(max_length=10000)
    timestamp = models.DateTimeField(auto_now_add=True)
    room = models.ForeignKey(Room, on_delete=models.CASCADE, related_name='rooms')
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sender_rooms')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='receiver_rooms')
