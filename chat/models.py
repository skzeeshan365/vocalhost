import base64
import binascii
import copy
import hashlib
import json
import pickle
import threading

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.contrib.auth.models import User
from django.db import models
from django.dispatch import Signal

from main.Utils import send_message_to_device, send_pusher_update


class SenderKeyBundle:
    def __init__(self, ik_public_key, ek_public_key, DHratchet, isNew, username):
        self.ik_public_key = ik_public_key
        self.ek_public_key = ek_public_key
        self.DHratchet = DHratchet
        self.username = username
        self.isNew = isNew

    def get_keys(self):
        return [self.ik_public_key, self.ek_public_key]

    def get_type(self):
        return 'sender'

    def get_new(self):
        return self.isNew

    def set_new(self, new):
        self.isNew = new

    def to_dict(self):
        return {
            'ik_public_key': self.ik_public_key,
            'ek_public_key': self.ek_public_key,
            'DHratchet': self.DHratchet,
            'username': self.username,
            'isNew': self.isNew,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            ik_public_key=data['ik_public_key'],
            ek_public_key=data['ek_public_key'],
            DHratchet=data['DHratchet'],
            username=data['username'],
            isNew=data['isNew'],
        )


class ReceiverKeyBundle:
    def __init__(self, IKb, SPKb, OPKb, DHratchet, isNew, username):
        self.IKb = IKb
        self.SPKb = SPKb
        self.OPKb = OPKb
        self.DHratchet = DHratchet
        self.username = username
        self.isNew = isNew

    def get_keys(self):
        return [self.IKb, self.SPKb, self.OPKb]

    def get_type(self):
        return 'receiver'

    def get_new(self):
        return self.isNew

    def set_new(self, new):
        self.isNew = new

    def to_dict(self):
        return {
            'IKb': self.IKb,
            'SPKb': self.SPKb,
            'OPKb': self.OPKb,
            'DHratchet': self.DHratchet,
            'username': self.username,
            'isNew': self.isNew,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            IKb=data['IKb'],
            SPKb=data['SPKb'],
            OPKb=data['OPKb'],
            DHratchet=data['DHratchet'],
            username=data['username'],
            isNew=data['isNew'],
        )


def create_room(sender_username, receiver_username, sender_key_bundle, receiver_key_bundle):
    combined_usernames_set = frozenset([sender_username, receiver_username])
    sorted_usernames = sorted(combined_usernames_set)

    room_identifier = hashlib.sha256(str(sorted_usernames).encode()).hexdigest()
    room = Room(
        room=room_identifier,
        sender_username=sorted_usernames[0],
        receiver_username=sorted_usernames[1]
    )
    if sender_username == sorted_usernames[0]:
        room.set_sender_key_bundle(sender_key_bundle)
        room.set_receiver_key_bundle(receiver_key_bundle)

        room.sender_ratchet = base64.b64decode(sender_key_bundle.DHratchet)
        room.receiver_ratchet = base64.b64decode(receiver_key_bundle.DHratchet)
    else:
        room.set_receiver_key_bundle(sender_key_bundle)
        room.set_sender_key_bundle(receiver_key_bundle)

        room.receiver_ratchet = base64.b64decode(sender_key_bundle.DHratchet)
        room.sender_ratchet = base64.b64decode(receiver_key_bundle.DHratchet)
    room.save()


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

    sender_key_bundle = models.JSONField(default=dict, blank=True, null=True)
    receiver_key_bundle = models.JSONField(default=dict, blank=True, null=True)

    sender_ratchet = models.BinaryField(default=None, null=True, blank=True)
    receiver_ratchet = models.BinaryField(default=None, null=True, blank=True)

    def __str__(self):
        return f'{self.room}'

    def delete_all_messages(self):
        # Delete all messages associated with this room
        Message.objects.filter(room=self).delete()

    def get_last_message(self):
        last_message = Message.objects.filter(room=self).order_by('-timestamp').first()
        return last_message if last_message else None

    def set_sender_key_bundle(self, key_bundle):
        self.sender_key_bundle = key_bundle.to_dict()

    def set_receiver_key_bundle(self, key_bundle):
        self.receiver_key_bundle = key_bundle.to_dict()

    def get_sender_key_bundle(self):
        return SenderKeyBundle.from_dict(self.sender_key_bundle) if self.sender_key_bundle else None

    def get_receiver_key_bundle(self):
        return ReceiverKeyBundle.from_dict(self.receiver_key_bundle) if self.receiver_key_bundle else None

    def get_bundle_key(self, username):
        if username == self.sender_username:
            if self.sender_key_bundle.get('ik_public_key', False):
                old_bundle = SenderKeyBundle.from_dict(self.sender_key_bundle)
            else:
                old_bundle = ReceiverKeyBundle.from_dict(self.sender_key_bundle)
            if old_bundle.get_new():
                old_bundle.set_new(False)
                self.sender_key_bundle = old_bundle.to_dict()
                self.save()
                old_bundle.set_new(True)
        else:
            if self.receiver_key_bundle.get('ik_public_key', False):
                old_bundle = SenderKeyBundle.from_dict(self.receiver_key_bundle)
            else:
                old_bundle = ReceiverKeyBundle.from_dict(self.receiver_key_bundle)
            if old_bundle.get_new():
                old_bundle.set_new(False)
                self.receiver_key_bundle = old_bundle.to_dict()
                self.save()
                old_bundle.set_new(True)

        return old_bundle

    def get_ratchet_key(self, username):
        if username == self.sender_username:
            return self.sender_ratchet
        else:
            return self.receiver_ratchet

    def set_sender_ratchet_key(self, key):
        self.sender_ratchet = key

    def set_receiver_ratchet_key(self, key):
        self.receiver_ratchet = key

    def set_ratchet_key(self, username, ratchet_key):
        try:
            decoded_key_bytes = base64.urlsafe_b64decode(ratchet_key)
            decoded_key_str = decoded_key_bytes.decode('utf-8')

            # Deserialize JWK string
            jwk = json.loads(decoded_key_str)

            x_bytes = base64.urlsafe_b64decode(jwk['x'] + '==')
            y_bytes = base64.urlsafe_b64decode(jwk['y'] + '==')

            # Use the elliptic curve public key method
            public_key = ec.EllipticCurvePublicNumbers(
                x=int.from_bytes(x_bytes, 'big'),
                y=int.from_bytes(y_bytes, 'big'),
                curve=ec.SECP256R1()  # Adjust the curve as needed
            ).public_key(default_backend())

            # Get the public key in bytes (DER format)
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            if username == self.sender_username:
                self.sender_ratchet = public_key_bytes
            else:
                self.receiver_ratchet = public_key_bytes
        except binascii.Error as e:
            print(f"Error decoding Base64: {e}")


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

    public_key = models.BinaryField(default=None, null=True, blank=True)

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

        if self.public_key:
            self.set_public_key(self.public_key)

        super().save(*args, **kwargs)

    def get_sender_username(self):
        return self.sender.username

    def get_receiver_username(self):
        return self.receiver.username

    def set_public_key(self, public_key):
        try:
            decoded_key_bytes = base64.urlsafe_b64decode(public_key)
            decoded_key_str = decoded_key_bytes.decode('utf-8')

            # Deserialize JWK string
            jwk = json.loads(decoded_key_str)

            x_bytes = base64.urlsafe_b64decode(jwk['x'] + '==')
            y_bytes = base64.urlsafe_b64decode(jwk['y'] + '==')

            # Use the elliptic curve public key method
            public_key = ec.EllipticCurvePublicNumbers(
                x=int.from_bytes(x_bytes, 'big'),
                y=int.from_bytes(y_bytes, 'big'),
                curve=ec.SECP256R1()  # Adjust the curve as needed
            ).public_key(default_backend())

            # Get the public key in bytes (DER format)
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.public_key = public_key_bytes
        except binascii.Error as e:
            print(f"Error decoding Base64: {e}")


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

    key_bundle = models.JSONField(default=dict, blank=True, null=True)
    receiver_key_bundle = models.JSONField(default=dict, blank=True, null=True)

    def __str__(self):
        return f"{self.sender} to {self.receiver}: {self.get_status_display()}"

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        if self.status == self.ACCEPTED:
            update_request('friend_request_accepted', sender=self.receiver, receiver=self.sender,
                           title='Friend request accepted',
                           message=f'{self.receiver.username} has accepted your friend request', accept=True)

            create_room(sender_username=self.sender.username, receiver_username=self.receiver.username,
                        sender_key_bundle=self.get_key_bundle(), receiver_key_bundle=self.get_receiver_key_bundle())

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

    def set_key_bundle(self, key_bundle):
        self.key_bundle = key_bundle.to_dict()

    def get_key_bundle(self):
        return SenderKeyBundle.from_dict(self.key_bundle) if self.key_bundle else None

    def set_receiver_key_bundle(self, key_bundle):
        self.receiver_key_bundle = key_bundle.to_dict()

    def get_receiver_key_bundle(self):
        return ReceiverKeyBundle.from_dict(self.receiver_key_bundle) if self.receiver_key_bundle else None
