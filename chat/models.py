import base64
import binascii
import hashlib
import json
import pickle
import threading
import uuid

from channels.db import database_sync_to_async
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.contrib.auth.models import User
from django.db import models
from django.db.models import Max, Exists, OuterRef, Subquery
from django.dispatch import Signal
from django.utils.timesince import timesince
from django.utils.timezone import now

from main.Utils import send_message_to_device, send_pusher_update, cloudinary_image_delete
from main.models import UserProfile


class UserDevice(models.Model):
    ANDROID = 'android'
    IOS = 'ios'
    WEB = 'web'
    DEVICE_TYPE_CHOICES = [
        (ANDROID, 'android'),
        (IOS, 'ios'),
        (WEB, 'web'),
    ]
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_device')
    identifier = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    device_public_key = models.BinaryField(default=None, null=True, blank=True)
    device_type = models.CharField(max_length=10, choices=DEVICE_TYPE_CHOICES)
    name = models.CharField(max_length=20, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    login_time = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.username} - {self.identifier}"

    def get_id_str(self):
        return str(self.identifier)

    def last_login(self):
        if not self.login_time:
            return 'Never'
        return timesince(self.login_time, now()) + ' ago'

    @staticmethod
    def get_device_by_id(device_id):
        try:
            return UserDevice.objects.get(identifier=device_id)
        except UserDevice.DoesNotExist:
            return None

    @staticmethod
    @database_sync_to_async
    def get_device_by_id_async(device_id):
        try:
            return UserDevice.objects.get(identifier=device_id)
        except UserDevice.DoesNotExist:
            return None

    @staticmethod
    def get_user_by_device(identifier_value):
        try:
            device_identifier = UserDevice.objects.get(identifier=identifier_value)
            user = device_identifier.user
            return user
        except UserDevice.DoesNotExist:
            return None

    @staticmethod
    def get_user_devices(user):
        devices = UserDevice.objects.filter(user=user)
        if devices.exists():
            return devices
        return None

    @staticmethod
    def get_user_device_public_keys(user):
        devices = UserDevice.get_user_devices(user)
        public_keys_dict = {}

        if devices:
            for device in devices:
                device_id = str(device.identifier)
                if device.device_public_key:
                    public_key = PublicKey.format_key(device.device_public_key)

                    public_keys_dict[device_id] = public_key
                else:
                    continue

            return public_keys_dict
        return None

    @staticmethod
    def has_reached_device_limit(user):
        return UserDevice.objects.filter(user=user).count() >= user.userprofile.max_devices

    @staticmethod
    def create_user_device(user, request):
        if UserDevice.has_reached_device_limit(user):
            return None
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        if 'Chrome' in user_agent:
            name = 'Chrome'
        elif 'Firefox' in user_agent:
            name = 'Firefox'
        elif 'Safari' in user_agent:
            name = 'Safari'
        elif 'Edge' in user_agent:
            name = 'Edge'
        elif 'Opera' in user_agent:
            name = 'Opera'
        else:
            name = 'Unknown'

        user_ip = request.META.get('HTTP_X_FORWARDED_FOR')
        if user_ip:
            user_ip = user_ip.split(',')[0].strip()
        else:
            user_ip = request.META.get('REMOTE_ADDR')

        new_device_id = str(uuid.uuid4())
        device = UserDevice.objects.create(user=user, identifier=new_device_id,
                                  device_type=UserDevice.WEB, name=name,
                                  ip_address=user_ip)
        return device


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


def create_room(sender_username, receiver_username, sender_device_id, sender_key_bundle, receiver_key_bundle,
                receiver_device_id):
    combined_usernames_set = frozenset([sender_username, receiver_username])
    sorted_usernames = sorted(combined_usernames_set)

    try:
        sender = User.objects.get(username=sender_username)
        receiver = User.objects.get(username=receiver_username)

        room_identifier = hashlib.sha256(str(sorted_usernames).encode()).hexdigest()
        room = Room(
            room=room_identifier,
            sender_username=sender_username,
            receiver_username=receiver_username
        )
        room.save()

        PublicKey.create_key(bundle=sender_key_bundle, user=sender, room=room, device_identifier=sender_device_id)
        PublicKey.create_key(bundle=receiver_key_bundle, user=receiver, room=room, device_identifier=receiver_device_id)
        return room.room
    except User.DoesNotExist:
        return None


class Room(models.Model):
    room = models.CharField(max_length=128, unique=True)
    sender_message_status = models.SmallIntegerField(default=-1)
    receiver_message_status = models.CharField(max_length=255, blank=True, null=True)
    sender_username = models.CharField(max_length=128, default=None)
    receiver_username = models.CharField(max_length=128, default=None)

    def __str__(self):
        return f'{self.room[:30]}'

    def get_user_type(self, username):
        if username == self.sender_username:
            return 'Sender'
        else:
            return 'Receiver'

    def clear_chat(self):
        try:
            message_ids_in_room = self.rooms.values_list('pk', flat=True)
            SentMessage.objects.filter(base_message__in=message_ids_in_room).delete()
            return True
        except Exception as e:
            # Handle any exceptions
            print(f"Error deleting sent messages: {e}")
            return False

    def get_last_message(self):
        last_message = Message.objects.filter(room=self).order_by('-timestamp').first()
        return last_message if last_message else None

    def get_ratchet_keys(self, user):
        public_keys = {}
        device_identifiers = UserDevice.objects.filter(user=user).values_list('identifier', flat=True)

        for device_identifier in device_identifiers:
            try:
                device_id = UserDevice.objects.get(identifier=device_identifier)
                public_key = PublicKey.get_latest_public_key(user=user, room=self, device_id=device_id)
                public_keys[str(device_identifier)] = PublicKey.format_key(public_key.get_ratchet_key())
            except PublicKey.DoesNotExist:
                public_keys[str(device_identifier)] = None
        return public_keys

    @staticmethod
    def get_ratchet_key(device_id, public_key):
        device_id = UserDevice.get_device_by_id(device_id=device_id)
        if device_id:
            ratchet_key = RatchetPublicKey.get_ratchet_public_key(device_id=device_id, public_keys=public_key)
            if ratchet_key:
                return PublicKey.format_key(ratchet_key)
            else:
                return PublicKey.format_key(public_key.get_bundle_key().DHratchet)
        else:
            return None

    def get_public_key(self, user, device_id, user_device_id):
        device_id = UserDevice.get_device_by_id(device_id)
        public_key = PublicKey.get_latest_public_key(user=user, room=self, device_id=device_id)
        if public_key:
            key_bundle = public_key.get_bundle_key()
            key = {
                'public_keys': PublicKey.format_keys(key_bundle.get_keys()),
                'ratchet_public_key': self.get_ratchet_key(user_device_id, public_key),
                'version': public_key.version
            }
            return key
        else:
            return None

    def get_public_keys(self, user, user_device_id):
        public_keys = {}
        device_identifiers = UserDevice.objects.filter(user=user).values_list('identifier', flat=True)
        active_devices = self.get_active_devices(user.username)
        if active_devices:
            for device_identifier in device_identifiers:
                device_id = UserDevice.objects.get(identifier=device_identifier)
                if str(device_identifier) in active_devices or ChildMessage.get_child_messages_exists(device_id.id,
                                                                                                      UserDevice.get_device_by_id(
                                                                                                              user_device_id)):
                    public_key = PublicKey.get_latest_public_key(user=user, room=self, device_id=device_id)
                    if public_key:
                        key_bundle = public_key.get_bundle_key()
                        public_keys[str(device_identifier)] = {
                            'public_keys': PublicKey.format_keys(key_bundle.get_keys()),
                            'ratchet_public_key': self.get_ratchet_key(user_device_id, public_key),
                            'version': public_key.version
                        }
                    else:
                        continue
                else:
                    continue
        else:
            for device_identifier in device_identifiers:
                device_id = UserDevice.objects.get(identifier=device_identifier)
                public_key = PublicKey.get_latest_public_key(user=user, room=self, device_id=device_id)
                if public_key:
                    key_bundle = public_key.get_bundle_key()
                    public_keys[str(device_identifier)] = {
                        'public_keys': PublicKey.format_keys(key_bundle.get_keys()),
                        'ratchet_public_key': self.get_ratchet_key(user_device_id, public_key),
                        'version': public_key.version
                    }
                else:
                    pass
        return public_keys

    def get_active_devices(self, username):
        user = connected_users.get(username)
        if user and user.get('room') == self.room:
            devices_in_room = [device_id for device_id in user['devices'].keys()]
            return devices_in_room
        else:
            return []

    @staticmethod
    def getRoom(sender_username, receiver_username):
        try:
            combined_usernames_set = frozenset([sender_username, receiver_username])
            sorted_usernames = sorted(combined_usernames_set)

            room = hashlib.sha256(str(sorted_usernames).encode()).hexdigest()
            return Room.objects.get(room=room)
        except Room.DoesNotExist:
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
    version = models.PositiveIntegerField(default=1)

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    device_identifier = models.ForeignKey(UserDevice, on_delete=models.CASCADE, related_name='public_key')
    room = models.ForeignKey(Room, on_delete=models.CASCADE, related_name='public_key')

    def __str__(self):
        return f'{self.user} - PublicKey - v{self.version}'

    def save(self, *args, **kwargs):
        self.delete_unused_public_keys(self.user, self.room, self.device_identifier.identifier)
        super().save(*args, **kwargs)

    @classmethod
    def create_key(cls, bundle, user, device_identifier, room):
        device_identifier = UserDevice.get_device_by_id(device_identifier)
        max_version = \
        cls.objects.filter(user=user, device_identifier=device_identifier, room=room).aggregate(Max('version'))[
            'version__max']
        version = max_version + 1 if max_version is not None else 1
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
            version=version
        )
        message = {
            'type': 'update_device_status',
            'device_id': str(device_identifier.identifier),
            'room': room.room,
        }
        new_signal_message.send(sender=user.username, receiver_username=None, message=message)
        return public_key

    @classmethod
    def update_keys(cls, bundle, ratchet_key, user, device_identifier, room):
        device_id = UserDevice.get_device_by_id(device_id=device_identifier)
        try:
            public_key = PublicKey.get_latest_public_key(user, room, device_id)
            public_key.key_bundle = pickle.dumps(bundle)
            RatchetPublicKey.objects.filter(public_keys=public_key).delete()
            public_key.save()
        except PublicKey.DoesNotExist:
            cls.create_key(bundle, user, device_id, room)

    @staticmethod
    def get_public_key_by_version(user, room, device_id, version):
        try:
            public_key = PublicKey.objects.get(user=user, room=room, device_identifier=device_id, version=version)
            return public_key
        except PublicKey.DoesNotExist:
            return None

    @staticmethod
    def get_latest_public_key(user, room, device_id):
        try:
            public_key = PublicKey.objects.filter(user=user, room=room, device_identifier=device_id).latest('version')
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
    def delete_unused_public_keys(user, room, device_id):
        device_id = UserDevice.get_device_by_id(device_id)
        latest_version = PublicKey.objects.filter(user=user, room=room, device_identifier=device_id) \
            .aggregate(latest_version=Max('version'))['latest_version']

        if latest_version is not None:
            public_keys_with_related_child_messages = PublicKey.objects.filter(
                Exists(ChildMessage.objects.filter(
                    key_version=OuterRef('version'),
                    base_message__room=room
                ))
            )

            public_keys_to_delete = PublicKey.objects.filter(
                user=user, room=room, device_identifier=device_id
            ).exclude(
                version=latest_version
            ).exclude(
                version__in=Subquery(public_keys_with_related_child_messages.values('version'))
            )

            public_keys_to_delete.delete()


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
    saved = models.BooleanField(default=False)
    image_url = models.URLField(default=None, null=True, blank=True)

    def __str__(self):
        return self.message_id

    def delete(self, *args, **kwargs):
        if self.image_url:
            thread = threading.Thread(target=self.delete_image,
                                      args=(self.image_url,))
            thread.start()
        super().delete(*args, **kwargs)

    @staticmethod
    def delete_image(image_url):
        try:
            cloudinary_image_delete(image_url)
        except Exception:
            pass

    def get_sender_username(self):
        return self.sender.username

    def get_receiver_username(self):
        return self.receiver.username

    def get_child_messages_exists(self):
        child_message = ChildMessage.objects.filter(base_message=self).exists()
        if child_message:
            return True
        return False

    @staticmethod
    def get_message_by_id(message_id):
        try:
            return Message.objects.get(message_id=message_id)
        except Message.DoesNotExist:
            return None

    @staticmethod
    @database_sync_to_async
    def get_message_by_id_async(message_id):
        try:
            return Message.objects.get(message_id=message_id)
        except Message.DoesNotExist:
            return None

    @staticmethod
    @database_sync_to_async
    def create_message_from_id(message_id, sender, receiver, room, message=None, reply_id=None, saved=False,
                               image_url=None):
        base_message = Message.objects.create(
            message=message,
            room=room,
            sender=sender,
            receiver=receiver,
            message_id=message_id,
            reply_id_id=reply_id,
            saved=saved,
            image_url=image_url,
        )
        return base_message


class ChildMessage(models.Model):
    cipher = models.TextField(null=True, blank=True)
    bytes_cipher = models.BinaryField(default=None, null=True, blank=True)

    public_key = models.BinaryField(default=None, null=True, blank=True)
    key_version = models.PositiveIntegerField(default=1)

    sender_device_id = models.ForeignKey(UserDevice, on_delete=models.CASCADE, related_name='message_sender_device_id',
                                         default=None, null=True, blank=True)
    receiver_device_id = models.ForeignKey(UserDevice, on_delete=models.CASCADE,
                                           related_name='message_receiver_device_id',
                                           default=None, null=True, blank=True)
    base_message = models.ForeignKey(Message, on_delete=models.CASCADE, related_name='base_message')

    def __str__(self):
        return f'ChildMessage - {self.base_message.message_id}'

    @staticmethod
    def create_child_message(public_key, key_version, sender_device_id, receiver_device_id, message, cipher=None,
                             bytes_cipher=None):
        child_message = ChildMessage.objects.create(cipher=cipher, bytes_cipher=bytes_cipher, public_key=public_key,
                                                    key_version=key_version, sender_device_id=sender_device_id,
                                                    receiver_device_id=receiver_device_id, base_message=message)
        return child_message

    @staticmethod
    def get_child_message(device_id, message):
        try:
            return ChildMessage.objects.get(receiver_device_id=device_id, base_message=message)
        except ChildMessage.DoesNotExist:
            return None

    @staticmethod
    def get_base_child_message(message):
        try:
            return ChildMessage.objects.get(base_message=message)
        except ChildMessage.DoesNotExist:
            return None

    @staticmethod
    def get_child_messages(message):
        if message:
            child_messages = ChildMessage.objects.filter(base_message=message)
            if child_messages.exists():
                return child_messages
            else:
                return None
        return None

    @staticmethod
    def get_child_messages_exists(sender_device_id, receiver_device_id):
        child_messages = ChildMessage.objects.filter(sender_device_id=sender_device_id,
                                                     receiver_device_id=receiver_device_id).exists()
        if child_messages:
            return True
        return False

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

    def nullify_all(self):
        self.cipher = None
        self.bytes_cipher = None

    @staticmethod
    def nullify_all(message_id):
        ChildMessage.objects.filter(base_message_id=message_id).update(cipher=None, bytes_cipher=None)


class SentMessage(models.Model):
    cipher = models.TextField(null=True, blank=True)
    bytes_cipher = models.BinaryField(default=None, null=True, blank=True)

    AES = models.TextField(null=True, blank=True)
    device_id = models.ForeignKey(UserDevice, on_delete=models.CASCADE,
                                  related_name='sent_receiver_device_id',
                                  default=None, null=True, blank=True)
    base_message = models.ForeignKey(Message, on_delete=models.CASCADE, related_name='sent_base_message')

    def __str__(self):
        return f'SentMessage - {self.base_message.message_id}'

    @staticmethod
    def get_sent_message(device_id, base_message):
        try:
            return SentMessage.objects.get(device_id=device_id, base_message=base_message)
        except SentMessage.DoesNotExist:
            return None


def update_request(type, room, sender, receiver, title, message, accept=False):
    if accept:
        if get_connected_users().get(receiver.username):
            message_data = {
                'type': type,
                'username': sender.username,
                'room': room,
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

    sender_device_id = models.ForeignKey(UserDevice, on_delete=models.CASCADE, related_name='sender_device_id',
                                         default=None, null=True, blank=True)
    receiver_device_id = models.ForeignKey(UserDevice, on_delete=models.CASCADE, related_name='receiver_device_id',
                                           default=None, null=True, blank=True)

    key_bundle = models.BinaryField(default=None, null=True, blank=True)
    receiver_key_bundle = models.BinaryField(default=None, null=True, blank=True)

    def __str__(self):
        return f"{self.sender} to {self.receiver}: {self.get_status_display()}"

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        if self.status == self.ACCEPTED:
            room = create_room(sender_username=self.sender.username,
                               receiver_username=self.receiver.username,
                               sender_device_id=self.sender_device_id,
                               sender_key_bundle=self.get_key_bundle(),
                               receiver_key_bundle=self.get_receiver_key_bundle(),
                               receiver_device_id=self.receiver_device_id
                               )

            update_request('friend_request_accepted', room=room, sender=self.receiver, receiver=self.sender,
                           title='Friend request accepted',
                           message=f'{self.receiver.username} has accepted your friend request', accept=True)

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


class RatchetPublicKey(models.Model):
    dhRatchet_key = models.BinaryField(default=None, null=True, blank=True)
    device_id = models.ForeignKey(UserDevice, on_delete=models.CASCADE, related_name='device_id')
    public_keys = models.ForeignKey(PublicKey, on_delete=models.CASCADE, related_name='public_keys')

    def __str__(self):
        return f'{self.device_id}'

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
