# Create your models here.
import uuid

from channels.db import database_sync_to_async
from django.contrib.auth.models import User
from django.db import models


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    api = models.CharField(max_length=255, blank=True)
    connected_clients = models.ManyToManyField('Client', blank=True)

    def save(self, *args, **kwargs):
        if not self.api:
            # Generate a unique API key if it doesn't exist
            self.api = str(uuid.uuid4())

        super().save(*args, **kwargs)

    @staticmethod
    @database_sync_to_async
    def get_user(api):
        try:
            user_profile = UserProfile.objects.get(api=api)
            return user_profile
        except UserProfile.DoesNotExist:
            return None

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
