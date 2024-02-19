import hashlib
import threading
import uuid

from channels.db import database_sync_to_async
from django.contrib.auth.models import User
from django.core.validators import MaxValueValidator
from django.db import models
from django.dispatch import Signal
from django.utils import timezone

from main.Utils import send_message_to_device, send_pusher_update


def get_or_create_room(sender_username, receiver_username):
    # Ensure that the users are sorted before creating the room identifier
    combined_usernames_set = frozenset([sender_username, receiver_username])
    sorted_usernames = sorted(combined_usernames_set)

    room_identifier = hashlib.sha256(str(sorted_usernames).encode()).hexdigest()

    room, created = Room.objects.get_or_create(
        room=room_identifier,
        sender_username=sorted_usernames[0],
        receiver_username=sorted_usernames[1]
    )

    return room


class Room(models.Model):
    room = models.CharField(max_length=128, unique=True)
    sender_channel = models.CharField(max_length=255, blank=True, null=True)
    receiver_channel = models.CharField(max_length=255, blank=True, null=True)
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


def update_message_status(temp, receiver_username, sender_username, receiver, message):
    # time = timezone.now()
    # message_data = {
    #     'type': 'new_message_background',
    #     'timestamp': time,
    #     'sender_username': sender_username,
    #     'temp_username': temp.username if temp else None,
    # }
    # send_pusher_update(message_data=message_data, receiver_username=receiver_username)
    send_message_to_device(receiver, f'{sender_username}: sent a message', message=message)


class Message(models.Model):
    message_id = models.CharField(primary_key=True, max_length=16)
    message = models.TextField(max_length=10000, null=True, blank=True, )
    timestamp = models.DateTimeField(auto_now_add=True)
    room = models.ForeignKey(Room, on_delete=models.CASCADE, related_name='rooms')
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sender_rooms')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='receiver_rooms')
    reply_id = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='replies',
                                 default=None)
    temp = models.ForeignKey(User, on_delete=models.CASCADE, related_name='temp', null=True, blank=True, default=None)
    saved = models.BooleanField(default=False)
    image_url = models.URLField(default=None, null=True, blank=True)

    def save(self, *args, **kwargs):
        if self.temp and not self.saved and not get_connected_users().get(self.receiver.username):
            thread = threading.Thread(target=update_message_status, args=(
                self.temp,
                self.receiver.username,
                self.sender.username,
                self.receiver,
                self.message,
            ))
            thread.start()

        super().save(*args, **kwargs)

    def get_sender_username(self):
        return self.sender.username

    def get_receiver_username(self):
        return self.receiver.username


def update_request(type, sender, receiver, title, message, accept=False):
    if accept:
        if get_connected_users().get(receiver.username):
            message_data = {
                'type': type,
                'username': sender.username,
                'fullname': sender.get_full_name(),
                'image_url': sender.userprofile.image.url if sender.userprofile.image else None,
            }
            new_signal_message.send(sender=sender.username, receiver_username=receiver.username, message=message_data)
        else:
            message_data = {
                'type': type,
                'username': sender.username,
            }
            send_pusher_update(message_data=message_data, receiver_username=receiver.username)
            send_message_to_device(receiver, title=title, message=message)
    else:
        message_data = {
            'type': type,
            'username': sender.username,
        }
        send_pusher_update(message_data=message_data, receiver_username=receiver.username)
        send_message_to_device(receiver, title=title, message=message)


class FriendRequest(models.Model):
    DEFAULT = 0
    PENDING = 1
    ACCEPTED = 2

    STATUS_CHOICES = [
        (PENDING, 'Pending'),
        (ACCEPTED, 'Accepted'),
    ]

    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sender')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='receiver')
    status = models.IntegerField(choices=STATUS_CHOICES, default=DEFAULT)

    def __str__(self):
        return f"{self.sender} to {self.receiver}: {self.get_status_display()}"

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        if self.status == self.ACCEPTED:
            update_request('friend_request_accepted', sender=self.receiver, receiver=self.sender, title='Friend request accepted', message=f'{self.receiver.username} has accepted your friend request', accept=True)

            room = get_or_create_room(sender_username=self.sender.username, receiver_username=self.receiver.username)
            if not room:
                raise Exception("Error creating room")
            self.delete()
        elif self.status == self.PENDING:
            thread = threading.Thread(target=update_request, args=(
                'friend_request_added',
                self.sender,
                self.receiver,
                'New friend request',
                f'{self.sender.username} has added you on vocalhost chat'
            ))
            thread.start()