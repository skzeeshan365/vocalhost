import base64
import binascii
import copy
import hashlib
import json
import pickle
import threading
import uuid

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.contrib.auth.models import User
from django.db import models
from django.dispatch import Signal

from main.Utils import send_message_to_device, send_pusher_update


class SenderKeyBundle:
    def __init__(self, ik_public_key, ek_public_key, DHratchet, isNew):
        self.ik_public_key = ik_public_key
        self.ek_public_key = ek_public_key
        self.DHratchet = DHratchet
        self.isNew = isNew

    def get_keys(self):
        return [self.ik_public_key, self.ek_public_key]

    def get_type(self):
        return 'Sender'

    def get_new(self):
        return self.isNew

    def set_new(self, new):
        self.isNew = new

    def to_pickle(self):
        return pickle.dumps(self)

    @classmethod
    def from_pickle(cls, data):
        return pickle.loads(data)


class ReceiverKeyBundle:
    def __init__(self, IKb, SPKb, OPKb, DHratchet, isNew):
        self.IKb = IKb
        self.SPKb = SPKb
        self.OPKb = OPKb
        self.DHratchet = DHratchet
        self.isNew = isNew

    def get_keys(self):
        return [self.IKb, self.SPKb, self.OPKb]

    def get_type(self):
        return 'Receiver'

    def get_new(self):
        return self.isNew

    def set_new(self, new):
        self.isNew = new

    def to_pickle(self):
        return pickle.dumps(self)

    @classmethod
    def from_pickle(cls, data):
        return pickle.loads(data)


def create_room(sender_username, receiver_username, sender_device_id, sender_key_bundle, receiver_key_bundle, receiver_device_id):
    combined_usernames_set = frozenset([sender_username, receiver_username])
    sorted_usernames = sorted(combined_usernames_set)

    try:
        sender = User.objects.get(username=sender_username)
        receiver = User.objects.get(username=receiver_username)

        room_identifier = hashlib.sha256(str(sorted_usernames).encode()).hexdigest()
        room = Room(
            room=room_identifier,
            sender_username=sorted_usernames[0],
            receiver_username=sorted_usernames[1]
        )
        room.save()

        PublicKey.create_key(bundle=sender_key_bundle, user=sender, room=room, device_identifier=sender_device_id)
        PublicKey.create_key(bundle=receiver_key_bundle, user=receiver, room=room, device_identifier=receiver_device_id)
    except User.DoesNotExist:
        pass


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

    def get_ratchet_keys(self, user):
        public_keys = {}
        device_identifiers = Devices.objects.filter(user=user).values_list('device_identifiers__identifier', flat=True)

        for device_identifier in device_identifiers:
            try:
                device_id = DeviceIdentifier.objects.get(identifier=device_identifier)
                public_key = PublicKey.objects.get(user=user, room=self, device_identifier=device_id)
                public_keys[str(device_identifier)] = PublicKey.format_key(public_key.get_ratchet_key())
            except PublicKey.DoesNotExist:
                public_keys[str(device_identifier)] = None
        return public_keys

    @staticmethod
    def get_ratchet_key(device_id, public_key):
        device_id = DeviceIdentifier.objects.get(identifier=device_id)
        ratchet_key = RatchetPublicKey.get_ratchet_public_key(device_id=device_id, public_keys=public_key)
        if ratchet_key:
            return PublicKey.format_key(public_key)
        else:
            return PublicKey.format_key(public_key.get_bundle_key().DHratchet)

    def get_public_key(self, user, device_id):
        try:
            public_key = PublicKey.objects.get(user=user, room=self, device_identifier=device_id)
            key_bundle = public_key.get_bundle_key()
            return PublicKey.format_keys(key_bundle.get_keys())
        except PublicKey.DoesNotExist:
            return None

    def get_public_keys(self, user):
        public_keys = {}
        device_identifiers = Devices.objects.filter(user=user).values_list('device_identifiers__identifier', flat=True)

        for device_identifier in device_identifiers:
            try:
                device_id = DeviceIdentifier.objects.get(identifier=device_identifier)
                public_key = PublicKey.objects.get(user=user, room=self, device_identifier=device_id)
                key_bundle = public_key.get_bundle_key()
                public_keys[str(device_identifier)] = {
                    'public_keys': PublicKey.format_keys(key_bundle.get_keys()),
                    'ratchet_public_key': self.get_ratchet_key(device_identifier, public_key)
                }
            except PublicKey.DoesNotExist:
                public_keys[str(device_identifier)] = None
        return public_keys


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


class DeviceIdentifier(models.Model):
    identifier = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    def __str__(self):
        return str(self.identifier)


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

    sender_device_id = models.ForeignKey(DeviceIdentifier, on_delete=models.CASCADE, related_name='sender_device_id', default=None, null=True, blank=True)
    receiver_device_id = models.ForeignKey(DeviceIdentifier, on_delete=models.CASCADE, related_name='receiver_device_id', default=None, null=True, blank=True)

    key_bundle = models.BinaryField(default=None, null=True, blank=True)
    receiver_key_bundle = models.BinaryField(default=None, null=True, blank=True)

    def __str__(self):
        return f"{self.sender} to {self.receiver}: {self.get_status_display()}"

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        if self.status == self.ACCEPTED:
            update_request('friend_request_accepted', sender=self.receiver, receiver=self.sender,
                           title='Friend request accepted',
                           message=f'{self.receiver.username} has accepted your friend request', accept=True)

            create_room(sender_username=self.sender.username, receiver_username=self.receiver.username, sender_device_id=self.sender_device_id,
                        sender_key_bundle=self.get_key_bundle(), receiver_key_bundle=self.get_receiver_key_bundle(), receiver_device_id=self.receiver_device_id)

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
        self.key_bundle = pickle.dumps(key_bundle)

    def get_key_bundle(self):
        return pickle.loads(self.key_bundle) if self.key_bundle else None

    def set_receiver_key_bundle(self, key_bundle):
        self.receiver_key_bundle = pickle.dumps(key_bundle)

    def get_receiver_key_bundle(self):
        return pickle.loads(self.receiver_key_bundle) if self.receiver_key_bundle else None


class Devices(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='devices')
    device_identifiers = models.ManyToManyField(DeviceIdentifier, related_name='device')

    def add_device_identifier(self, device_id):
        device_identifier = DeviceIdentifier.objects.create(identifier=device_id)
        self.device_identifiers.add(device_identifier)

    def get_device_identifiers(self):
        return self.device_identifiers.all()

    def __str__(self):
        return f"{self.user.username}'s Devices"

    @staticmethod
    def get_device_by_id(device_id):
        try:
            return DeviceIdentifier.objects.get(identifier=device_id)
        except DeviceIdentifier.DoesNotExist:
            return None


class PublicKey(models.Model):
    SENDER = 0
    RECEIVER = 1
    KEY_TYPE_CHOICES = [
        (SENDER, 'Sender'),
        (RECEIVER, 'Receiver'),
    ]

    key_type = models.IntegerField(choices=KEY_TYPE_CHOICES)
    key_bundle = models.BinaryField()

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    device_identifier = models.OneToOneField(DeviceIdentifier, on_delete=models.CASCADE, related_name='public_key')
    room = models.ForeignKey(Room, on_delete=models.CASCADE, related_name='public_key')

    @classmethod
    def create_key(cls, bundle, user, device_identifier, room):
        if bundle.get_type() == 'Sender':
            choice = cls.SENDER
        else:
            choice = cls.RECEIVER
        key_bundle = pickle.dumps(bundle)
        public_key = cls.objects.create(
            key_type=choice,
            key_bundle=key_bundle,
            user=user,
            device_identifier=device_identifier,
            room=room,
        )
        return public_key

    @classmethod
    def update_keys(cls, bundle, ratchet_key, user, device_identifier, room):
        device_id = Devices.get_device_by_id(device_id=device_identifier)
        try:
            public_key = PublicKey.objects.get(user=user, room=room, device_identifier=device_id)
            public_key.key_bundle = pickle.dumps(bundle)
            RatchetPublicKey.objects.filter(public_keys=public_key).delete()
            public_key.save()
        except PublicKey.DoesNotExist:
            cls.create_key(bundle, user, device_id, room)

    @staticmethod
    def get_public_key(user, room, device_id):
        try:
            device_id = Devices.get_device_by_id(device_id)
            public_key = PublicKey.objects.get(user=user, room=room, device_identifier=device_id)
            return public_key
        except PublicKey.DoesNotExist:
            return None
    def get_bundle(self):
        return pickle.loads(self.key_bundle)

    def get_bundle_key(self):
        key_bundle = pickle.loads(self.key_bundle)

        if key_bundle.get_new():
            key_bundle.set_new(False)
            self.key_bundle = pickle.dumps(key_bundle)
            self.save()
            key_bundle.set_new(True)

        return key_bundle

    @staticmethod
    def format_keys(keys):
        key = []
        for i in keys:
            if isinstance(i, bytes):
                key.append(base64.b64encode(i).decode('utf-8'))
            else:
                key.append(i)
        return key

    @staticmethod
    def format_key(key):
        return base64.b64encode(key).decode('utf-8')

    @staticmethod
    def get_user_by_identifier(identifier_value):
        try:
            # Assuming identifier_value is the UUID you want to search for
            device_identifier = DeviceIdentifier.objects.get(identifier=identifier_value)
            user = device_identifier.device.first().user  # Assuming devices is the related_name in the Devices model
            return user
        except DeviceIdentifier.DoesNotExist:
            # Handle the case where the identifier is not found
            return None


class RatchetPublicKey(models.Model):
    dhRatchet_key = models.BinaryField(default=None, null=True, blank=True)
    device_id = models.OneToOneField(DeviceIdentifier, on_delete=models.CASCADE, related_name='device_id')
    public_keys = models.ForeignKey(PublicKey, on_delete=models.CASCADE, related_name='public_keys')

    @staticmethod
    def get_ratchet_key(device_id, public_keys):
        try:
            ratchet_key = RatchetPublicKey.objects.get(device_id=device_id, public_keys=public_keys)
            return ratchet_key
        except RatchetPublicKey.DoesNotExist:
            return None

    @staticmethod
    def get_ratchet_public_key(device_id, public_keys):
        try:
            ratchet_key = RatchetPublicKey.objects.get(device_id=device_id, public_keys=public_keys)
            return ratchet_key.dhRatchet_key
        except RatchetPublicKey.DoesNotExist:
            return None

    def set_ratchet_key(self, ratchet_key):
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

            self.dhRatchet_key = public_key_bytes
        except binascii.Error as e:
            print(f"Error decoding Base64: {e}")


    @staticmethod
    def load_ratchet_key(ratchet_key):
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

            return public_key_bytes
        except binascii.Error as e:
            print(f"Error decoding Base64: {e}")
            return None