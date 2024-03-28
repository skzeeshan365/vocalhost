import json
import threading
import time
from urllib.parse import parse_qs

import msgpack
from channels.db import database_sync_to_async
from channels.exceptions import StopConsumer
from channels.generic.websocket import AsyncWebsocketConsumer
from cloudinary.api import delete_resources
from django.contrib.auth.models import User
from django.core.serializers.json import DjangoJSONEncoder
from django.db import transaction
from django.http import SimpleCookie

from ReiserX_Tunnel import settings
from ReiserX_Tunnel.AuthBackend import CustomAuthBackend
from chat.models import Room, Message, new_signal_message, connected_users, PublicKey, UserDevice, ChildMessage, \
    SentMessage, UserSecure
from main import Utils
from main.Utils import cloudinary_image_delete, cloudinary_image_upload, get_image_public_id, send_message_to_device
from main.models import UserProfile


class ChatConsumer(AsyncWebsocketConsumer):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.room = None
        self.sender = None
        self.receiver = None
        self.sender_username = None
        self.receiver_username = None
        self.device_id = None
        self.api = None

    @database_sync_to_async
    def authenticate(self, api_key):
        return CustomAuthBackend().authenticate_api(api_key=api_key)

    async def connect(self):
        query_string = self.scope['query_string'].decode('utf-8')
        query_params = parse_qs(query_string)

        api = query_params.get('api', None)
        device_id = query_params.get('device_id', None)
        await self.listen_for_signal_messages()

        if api is not None and device_id is not None:
            self.sender = await self.authenticate(api[0])
            self.sender_username = self.sender.get_username()

            if self.sender is not None:
                await self.channel_layer.group_send(
                    'chat',
                    {
                        "type": "update_user_status",
                        "status": "online",
                        "username": self.sender_username,
                    },
                )
                connected_users[self.sender_username] = {}
                connected_users[self.sender_username][self.device_id] = {'channel_name': self.channel_name}
            else:
                await self.close()
        else:
            headers = dict(self.scope['headers'])
            cookies = SimpleCookie()
            cookies.load(headers.get(b'cookie').decode())

            device_id = cookies.get('device_id')
            token = cookies.get('internal')
            if device_id and token:
                self.device_id = device_id.value
                self.sender = self.scope.get('user')

                device_user = await UserDevice.get_user_by_device_async(self.device_id)
                if self.sender and device_user:
                    secrets = UserSecure.get_user_secret_by_token_async(self.sender, UserDevice.get_device_by_id_async(
                        self.device_id), token)
                    if self.sender.is_authenticated and self.sender == device_user and secrets:
                        await self.accept()
                        # Connection accepted

                        self.sender_username = self.sender.get_username()
                        await self.channel_layer.group_add(
                            self.sender_username,
                            self.channel_name
                        )
                        await self.channel_layer.group_send(
                            'chat',
                            {
                                "type": "update_user_status",
                                "status": "online",
                                "username": self.sender_username,
                            },
                        )
                        if self.sender_username in connected_users:
                            # Update the devices dictionary for the existing user
                            connected_users[self.sender_username]['devices'].update({
                                self.device_id: {
                                    'channel_name': self.channel_name
                                }
                            })
                        else:
                            # If the user doesn't exist, create a new entry
                            connected_users[self.sender_username] = {
                                'room': None,
                                'devices': {
                                    self.device_id: {
                                        'channel_name': self.channel_name
                                    }
                                }
                            }
                        # thread = threading.Thread(target=PublicKey.delete_unused_public_keys, args=(
                        #     self.sender, self.room, self.device_id
                        # ))
                        # thread.start()
                    else:
                        await self.close(code=1000)
                else:
                    await self.close(code=1000)
            else:
                await self.close(code=1000)

    async def listen_for_signal_messages(self):
        async def forward_signal_messages(sender, receiver_username, message, **kwargs):
            if receiver_username:
                if receiver_username == self.sender_username:
                    await self.send(text_data=json.dumps(message, cls=DjangoJSONEncoder))
            elif sender == self.receiver_username:
                await self.send(text_data=json.dumps(message))
        new_signal_message.connect(forward_signal_messages)

    async def disconnect(self, close_code):
        await self.channel_layer.group_send(
            'chat',
            {
                "type": "update_user_status",
                "status": "offline",
                "username": self.sender_username,
            },
        )
        if self.device_id and self.room:
            await self.channel_layer.group_send(
                f'{self.room.room}_{self.receiver_username}',
                {
                    "type": "update_device_status",
                    "status": False,
                    "device_id": self.device_id,
                },
            )
        if self.sender_username in connected_users:
            if self.device_id in connected_users[self.sender_username]['devices']:
                del connected_users[self.sender_username]['devices'][self.device_id]
            if not connected_users[self.sender_username]['devices']:
                connected_users[self.sender_username]['room'] = None
        raise StopConsumer

    async def receive(self, text_data=None, bytes_data=None):
        channel_active = self.get_room_user_status_realtime(self.receiver_username)

        if text_data is not None:
            text_data_json = json.loads(text_data)
            type = text_data_json.get('type')
            message = text_data_json.get("message")
            message_id = text_data_json.get('message_id')
            reply_id = text_data_json.get('reply_id')
            storeMessage = text_data_json.get("storeMessage")

            if type == 'initialize_receiver':
                receiver_username = text_data_json.get('receiver_username')
                await self.initialize_receiver(receiver_username)

            elif type == 'message':
                # Generate message_id
                message_id = int(time.time() * 1000)

                await self.send(
                    text_data=json.dumps(
                        {
                            "type": 'message_sent',
                            'message_id': message_id,
                            'data_type': 'text'
                        }
                    )
                )

                data = json.loads(message)
                for device_id, properties in data.items():
                    cipher = properties.get('cipher')
                    public_key = properties.get('ratchet_key')
                    key_version = properties.get('key_version')
                    await self.process_messages(device_id, public_key, key_version, cipher,
                                                message_id, reply_id)

                sent_messages = text_data_json.get('sent_message')
                if sent_messages:
                    await self.process_sent_messages(sent_messages, message_id, reply_id)


            elif type == 'save_message':
                save_message = text_data_json.get("save_message")
                sender = text_data_json.get("sender")
                receiver = text_data_json.get("receiver")
                image_url = text_data_json.get('image_url')
                if channel_active:
                    await self.channel_layer.group_send(
                        f'{self.room.room}_{self.receiver_username}',
                        {
                            "type": "save_message",
                            "message_id": message_id,
                            'save_message': save_message,
                            'sender_username': self.sender_username
                        },
                    )
                if save_message:
                    await self.save_message_db(message=message, message_id=message_id, sender=sender,
                                               receiver=receiver,
                                               reply_id=reply_id, saved=True, image_url=image_url)
                else:
                    await self.unsave_message_db(message_id)
                await self.send(
                    text_data=json.dumps(
                        {
                            "type": "save_message",
                            "message_id": message_id,
                            'save_message': save_message,
                            'sender_username': self.sender_username
                        }
                    )
                )
            elif type == 'delete_message':
                sender_username = text_data_json.get("sender_username")
                permission = await self.delete_permission_db(message_id, sender_username)
                if permission:
                    await self.delete_message_db(message_id)
                    if channel_active:
                        await self.channel_layer.group_send(
                            f'{self.room.room}_{self.receiver_username}',
                            {
                                "type": "delete_message",
                                "message_id": message_id,
                                'sender_username': self.sender_username,
                            },
                        )

                    await self.send(
                        text_data=json.dumps(
                            {
                                "type": "delete_message",
                                "message_id": message_id,
                                'sender_username': self.sender_username
                            }
                        )
                    )

            elif type == 'message_seen':
                if channel_active:
                    await self.channel_layer.group_send(
                        f'{self.room.room}_{self.receiver_username}',
                        {
                            "type": "message_seen",
                            "message_id": message_id,
                            "sender_username": self.sender_username,
                        },
                    )
            elif type == 'typing_status':
                if self.get_user_status_realtime(self.receiver_username):
                    typing = text_data_json.get('typing')
                    await self.channel_layer.group_send(
                        self.receiver_username,
                        {
                            "type": "typing_status",
                            "typing": typing,
                            "sender_username": self.sender_username,
                        },
                    )

        if bytes_data:
            data = msgpack.unpackb(bytes_data)
            await self.process_bytes_data(data)

    async def process_bytes_data(self, data):
        message_type = data.get('type')

        if message_type == 0:
            message = data.get('message')

            reply_id = data.get('reply_id')

            message_id = int(time.time() * 1000)

            await self.send(
                text_data=json.dumps(
                    {
                        "type": 'message_sent',
                        'message_id': message_id,
                        'data_type': 'text'
                    }
                )
            )

            for device_id, properties in message.items():
                cipher = properties.get('cipher').data
                public_key = properties.get('ratchet_key').data
                key_version = properties.get('key_version')
                await self.process_messages(device_id, public_key, key_version, cipher,
                                            message_id, reply_id)

            sent_messages = data.get('sent_message')
            if sent_messages:
                await self.process_sent_messages(sent_messages, message_id, reply_id)
        elif message_type == 1:
            device_id = data.get('device_id')
            channel_name = self.get_device_channel_name(self.receiver_username, device_id)
            channel_active = self.get_room_device_status_realtime(self.receiver_username, device_id)

            if data.get('message'):
                text_message = data.get("message").data
            else:
                text_message = ''
            public_key = data.get('public_key').data
            key_version = data.get('key_version')
            flag = data.get('flag')

            message_id = data.get('message_id')
            image_data = data.get('image_bytes').data

            # Extract binary image data
            if channel_active:
                await self.channel_layer.send(
                    channel_name,
                    {
                        "type": "image_bytes_data",
                        "message": text_message,
                        "image_data": image_data,
                        'message_id': message_id,
                        "sender_username": self.sender_username,
                        'public_key': public_key,
                        'device_id': self.device_id,
                    }
                )
            elif channel_name:
                await self.channel_layer.send(
                    channel_name,
                    {
                        'type': 'new_message_background',
                        'timestamp': message_id,
                        'sender_username': self.sender_username
                    }
                )
                if text_message == '':
                    text_message = None
                await self.save_message_db_temp(device_id=device_id, cipher=text_message, bytes_cipher=image_data,
                                                message_id=message_id,
                                                public_key=public_key, key_version=key_version)
            else:
                if text_message == '':
                    text_message = None
                await self.save_message_db_temp(device_id=device_id, cipher=text_message, bytes_cipher=image_data,
                                                message_id=message_id,
                                                public_key=public_key, key_version=key_version)
            if flag == 1:
                await self.send(
                    text_data=json.dumps(
                        {
                            "type": 'message_sent',
                            'message_id': message_id,
                            'data_type': 'bytes'
                        }
                    )
                )
            await self.update_public_key_db(self.sender, public_key, device_id)
        elif message_type == 2:
            if data.get('message'):
                cipher_text = data.get('message').data
            else:
                cipher_text = ''
            AES = data.get('AES').data
            message_id = data.get('message_id')
            device_id = data.get('device_id')
            image_data = data.get('image_bytes').data

            if device_id != self.device_id:
                channel_name = self.get_device_channel_name(self.sender_username, device_id)
                if channel_name:
                    await self.channel_layer.send(
                        channel_name,
                        {
                            'type': 'chat_sent_bytes',
                            'cipher': cipher_text,
                            'bytes_cipher': image_data,
                            'AES': AES,
                            'room': self.room.room,
                            'message_id': message_id,
                        }
                    )

            base_message = await Message.get_message_by_id_async(message_id)
            device = await UserDevice.get_device_by_id_async(device_id)
            if not base_message and not self.get_room_user_status_realtime(self.receiver_username):
                base_message = await Message.create_message_from_id(
                    message=None,
                    room=self.room,
                    sender=self.sender,
                    receiver=self.receiver,
                    message_id=message_id,
                )
            if base_message:
                instance = SentMessage(cipher=cipher_text, bytes_cipher=image_data, AES=AES, device_id=device,
                                       base_message=base_message)
                await self.save_sent_message_instance(instance)

    async def process_messages(self, device_id, public_key, key_version, message, message_id,
                               reply_id):
        channel_name = self.get_device_channel_name(self.receiver_username, device_id)
        channel_active = self.get_room_device_status_realtime(self.receiver_username, device_id)

        if channel_active:
            await self.channel_layer.send(
                channel_name,
                {
                    "type": "chat_message",
                    "message": message,
                    "message_id": message_id,
                    "sender_username": self.sender_username,
                    'device_id': self.device_id,
                    'public_key': public_key,
                    'reply_id': reply_id
                },
            )
            # if storeMessage:
            #     await self.save_message_db(message=message, message_id=message_id, reply_id=reply_id,
            #                                saved=True)
        elif channel_name:
            await self.channel_layer.send(
                channel_name,
                {
                    'type': 'new_message_background',
                    'timestamp': message_id,
                    'sender_username': self.sender_username
                }
            )
            await self.save_message_db_temp(device_id=device_id, cipher=message, message_id=message_id,
                                            public_key=public_key, key_version=key_version)
        else:
            await self.save_message_db_temp(device_id=device_id, cipher=message, message_id=message_id,
                                            public_key=public_key, key_version=key_version)
            thread = threading.Thread(target=send_message_to_device, args=(
                self.receiver, 'New message received', f'{self.sender_username}: sent a message', device_id
            ))
            thread.start()
        await self.update_public_key_db(self.sender, public_key, device_id)

    async def process_sent_messages(self, sent_messages, message_id, reply_id):
        base_message = await Message.get_message_by_id_async(message_id)
        instances = []

        for device_id, data in sent_messages.items():
            cipher = data.get('cipher').data
            aes = data.get('Aes').data

            if base_message:
                device = await UserDevice.get_device_by_id_async(device_id)
                instance = SentMessage(cipher=cipher, AES=aes, device_id=device, base_message=base_message)
                instances.append(instance)

            if device_id == self.device_id:
                continue

            channel_name = self.get_device_channel_name(self.sender_username, device_id)
            if channel_name:
                await self.channel_layer.send(
                    channel_name,
                    {
                        'type': 'chat_sent_message',
                        'cipher': cipher,
                        'AES': aes,
                        'room': self.room.room,
                        'message_id': message_id,
                        'reply_id': reply_id,
                    }
                )

        await self.save_sent_message_instances(instances)

    async def chat_message(self, event):
        sender_username = event["sender_username"]
        message = event["message"]
        message_id = event['message_id']
        reply_id = event.get('reply_id', None)
        public_key = event.get('public_key')
        device_id = event.get('device_id', None)

        data = {
            'type': 0,
            "message": message,
            'message_id': message_id,
            'reply_id': reply_id,
            "sender_username": sender_username,
            'public_key': public_key,
            'device_id': device_id
        }

        packed_data = msgpack.packb(data)

        await self.send(bytes_data=packed_data)

    async def chat_sent_message(self, event):
        message_id = event.get('message_id')
        reply_id = event.get('reply_id', None)
        cipher = event.get('cipher')
        AES = event.get('AES')
        room = event.get('room')
        data = {
            'type': 2,
            'cipher': cipher,
            'AES': AES,
            'room': room,
            'message_id': message_id,
            'reply_id': reply_id,
        }

        packed_data = msgpack.packb(data)

        await self.send(bytes_data=packed_data)

    async def message_seen(self, event):
        message_id = event.get("message_id")
        sender_username = event.get('sender_username')
        await self.send(
            text_data=json.dumps(
                {
                    "type": 'message_seen',
                    'message_id': message_id,
                    'sender_username': sender_username
                }
            )
        )

    async def image_bytes_data(self, event):
        sender_username = event["sender_username"]
        message_id = event['message_id']
        image_data = event["image_data"]
        message = event.get("message")
        public_key = event.get("public_key")
        device_id = event.get("device_id")

        data = {
            'type': 1,
            'message_id': message_id,
            'message': message,
            'sender_username': sender_username,
            'public_key': public_key,
            'device_id': device_id,
            'image_bytes': image_data
        }

        packed_data = msgpack.packb(data)

        await self.send(bytes_data=packed_data)

    async def chat_sent_bytes(self, event):
        message_id = event.get('message_id')
        cipher = event.get('cipher')
        bytes_cipher = event.get('bytes_cipher')
        AES = event.get('AES')
        room = event.get('room')

        data = {
            'type': 3,
            'message_id': message_id,
            'cipher': cipher,
            'AES': AES,
            'room': room,
            'image_bytes': bytes_cipher
        }

        packed_data = msgpack.packb(data)

        await self.send(bytes_data=packed_data)

    async def save_message(self, event):
        message_id = event['message_id']
        save_message = event.get("save_message")
        sender_username = event.get('sender_username')
        await self.send(
            text_data=json.dumps(
                {
                    "type": "save_message",
                    "message_id": message_id,
                    'save_message': save_message,
                    'sender_username': sender_username
                }
            )
        )

    async def delete_message(self, event):
        message_id = event['message_id']
        sender_username = event.get('sender_username')
        await self.send(
            text_data=json.dumps(
                {
                    "type": "delete_message",
                    "message_id": message_id,
                    'sender_username': sender_username
                }
            )
        )

    async def new_message_background(self, event):
        timestamp = event.get('timestamp')
        sender_username = event.get('sender_username')
        await self.send(
            text_data=json.dumps(
                {
                    'type': 'new_message_background',
                    'timestamp': timestamp,
                    'sender_username': sender_username
                }
            )
        )

    async def update_user_status(self, event):
        status = event['status']
        username = event['username']
        status_bool = (status == 'online')

        await self.set_user_status(username, status_bool)

        await self.send(text_data=json.dumps({
            'type': 'user_status',
            'username': username,
            'status': status,
        }))

    async def initialize_receiver(self, receiver_username):
        if receiver_username:
            self.receiver = await self.get_user(receiver_username)
            self.room = await Room.get_room_async(self.sender, self.receiver)
            self.receiver_username = receiver_username

            if self.room is not None:
                await self.channel_layer.group_add(
                    'chat',
                    self.channel_name
                )

                await self.channel_layer.group_add(
                    f'{self.room.room}_{self.sender_username}',
                    self.channel_name
                )

                if settings.DEBUG is False:
                    subject = "A New Message Is Received"

                    message = f"{self.sender_username} has added you on Vocalhost chat."

                    to_email = self.receiver.email
                    try:
                        Utils.send_email(subject=subject, message=message, to_email=to_email)
                    except Exception:
                        pass

                if self.receiver:
                    await self.send(text_data=json.dumps({
                        'type': 'user_status',
                        'username': receiver_username,
                        'status': await self.get_user_status(self.receiver),
                    }))
                    await self.channel_layer.group_send(
                        f'{self.room.room}_{self.receiver_username}',
                        {
                            "type": "update_device_status",
                            "status": True,
                            "device_id": self.device_id,
                        },
                    )
                if self.sender_username in connected_users:
                    connected_users[self.sender_username]['room'] = self.room.room
                if not connected_users[self.sender_username]['devices']:
                    connected_users[self.sender_username]['devices'] = {}
                if not connected_users[self.sender_username]['devices'][self.device_id]:
                    connected_users[self.sender_username]['devices'][self.device_id] = {}
                connected_users[self.sender_username]['devices'][self.device_id] = {
                            'channel_name': self.channel_name,
                            'room': self.room.room
                }
            else:
                await self.close()
        else:
            self.room = None
            await self.close()

    async def typing_status(self, event):
        typing = event.get('typing')
        sender_username = event.get('sender_username')

        await self.send(text_data=json.dumps({
            'type': 'typing_status',
            'typing': typing,
            'sender_username': sender_username
        }))

    async def update_device_status(self, event):
        device_id = event.get('device_id', None)
        status = event.get('status', False)
        public_keys = event.get('public_keys')
        if status:
            if device_id and self.room and self.device_id and self.get_room_device_status_realtime(
                    self.receiver_username, device_id):
                if not public_keys:
                    public_keys = await self.get_device_public_keys(self.room, self.receiver, device_id, self.device_id)
                await self.send(text_data=json.dumps({
                    'type': 'device_online',
                    'device_id': device_id,
                    'room': self.room.room,
                    'public_keys': public_keys,
                    'active_device_ids': self.get_room_devices_realtime(self.receiver_username)
                }))
        else:
            await self.send(text_data=json.dumps({
                'type': 'device_online',
                'device_id': device_id,
                'room': self.room.room,
            }))

    @database_sync_to_async
    def get_device_public_keys(self, room, user, device_id, self_device_id):
        public_keys = room.get_public_key(user, device_id, self_device_id)
        if public_keys:
            return public_keys
        return None

    @database_sync_to_async
    def get_user(self, username):
        try:
            return User.objects.get(username=username)
        except User.DoesNotExist:
            return None

    @database_sync_to_async
    def get_device_user(self, device_id):
        return UserDevice.get_user_by_device(device_id)

    @database_sync_to_async
    def save_message_db(self, message=None, message_id=None, sender=None, receiver=None, reply_id=None,
                        saved=False, image_url=None):
        try:
            exists = Message.objects.get(message_id=message_id)
            if exists:
                exists.saved = True
                exists.message = message
                exists.save()
        except Message.DoesNotExist:
            if sender is None:
                sender = self.sender
            else:
                sender = User.objects.get(username=sender)
            if receiver is None:
                receiver = self.receiver
            else:
                receiver = User.objects.get(username=receiver)
            try:
                if reply_id:
                    reply_message = Message.objects.get(message_id=reply_id)
                else:
                    reply_message = None
            except Message.DoesNotExist:
                reply_message = None

            if image_url is None:
                url = cloudinary_image_upload(image_data=image_url)
                image_url = url if url else None
            if message_id is not None and self.room is not None:
                Message.objects.create(
                    message=message,
                    room=self.room,
                    sender=sender,
                    receiver=receiver,
                    message_id=message_id,
                    reply_id=reply_message,
                    saved=saved,
                    image_url=image_url,
                )

    @database_sync_to_async
    def save_message_db_temp(self, device_id, cipher=None, bytes_cipher=None, message_id=None, sender=None,
                             receiver=None, reply_id=None,
                             public_key=None, key_version=0):
        if sender is None:
            sender = self.sender
        else:
            sender = User.objects.get(username=sender)
        if receiver is None:
            receiver = self.receiver
        else:
            receiver = User.objects.get(username=receiver)
        if reply_id:
            try:
                reply_message = Message.objects.get(message_id=reply_id)
            except Message.DoesNotExist:
                reply_message = None
        else:
            reply_message = None
        base_message = None
        try:
            base_message = Message.objects.get(message_id=message_id)
            if reply_message:
                base_message.reply_id_id = reply_message
                base_message.save()
        except Message.DoesNotExist:
            if message_id is not None and self.room is not None:
                base_message = Message.objects.create(
                    message=None,
                    room=self.room,
                    sender=sender,
                    receiver=receiver,
                    message_id=message_id,
                    reply_id=reply_message,
                    saved=False,
                    image_url=None,
                )
        if (cipher or bytes_cipher) and base_message:
            device_id = UserDevice.get_device_by_id(device_id)
            sender_device_id = UserDevice.get_device_by_id(self.device_id)
            public_key = PublicKey.load_ratchet_key_raw(public_key)
            ChildMessage.create_child_message(public_key=public_key, key_version=key_version,
                                              sender_device_id=sender_device_id, receiver_device_id=device_id,
                                              message=base_message, cipher=cipher, bytes_cipher=bytes_cipher)

    @database_sync_to_async
    def get_latest_public_key_async(self, user, room, device_id):
        return PublicKey.get_latest_public_key(user, room, device_id)

    @database_sync_to_async
    def get_public_key_by_version_async(self, user, room, device_id, version):
        return PublicKey.get_public_key_by_version(user, room, device_id, version)

    @database_sync_to_async
    def save_sent_message_instances(self, instances):
        with transaction.atomic():
            SentMessage.objects.bulk_create(instances)

    @database_sync_to_async
    def save_sent_message_instance(self, instance):
        instance.save()

    @database_sync_to_async
    def delete_message_db(self, message_id):
        try:
            message = Message.objects.get(message_id=message_id)
            if message.image_url:
                cloudinary_image_delete(message.image_url)
            if message.get_child_messages_exists():
                ChildMessage.objects.filter(base_message=message).update(cipher=None)
                message.image_url = None
                message.message = None
                message.save()
            else:
                message.delete()
        except Message.DoesNotExist:
            pass

    @database_sync_to_async
    def unsave_message_db(self, message_id):
        try:
            message = Message.objects.get(message_id=message_id)
            if message.get_child_messages_exists():
                message.saved = False
                message.message = None
                message.save()
            else:
                if message.image_url:
                    cloudinary_image_delete(message.image_url)
                message.delete()
        except Message.DoesNotExist:
            pass

    @database_sync_to_async
    def delete_permission_db(self, message_id, sender_username):
        try:
            user = User.objects.get(username=sender_username)
            if user.is_authenticated:
                message = Message.objects.get(message_id=message_id, sender=user)
                if message:
                    return True
                else:
                    return False
            else:
                return False
        except Message.DoesNotExist:
            return True
        except User.DoesNotExist:
            return False

    @database_sync_to_async
    def get_user_status(self, user):
        if user.userprofile.status:
            return 'online'
        else:
            return 'offline'

    def get_room_user_status_realtime(self, username):
        user = connected_users.get(username)
        if user and user.get('room') == self.room.room:
            return True
        else:
            return False

    def get_user_status_realtime(self, username):
        user = connected_users.get(username)
        if user:
            return True
        else:
            return False

    def get_room_device_status_realtime(self, username, device_id):
        user = connected_users.get(username)
        if user and self.room:
            device_info = user['devices'].get(device_id)
            if device_info and device_info.get('room') == self.room.room:
                return True
        return False

    def get_room_devices_realtime(self, username):
        user = connected_users.get(username)
        if user and self.room:
            devices_in_room = [device_id for device_id, device_info in user['devices'].items() if
                               device_info.get('room') == self.room.room]
            return devices_in_room
        else:
            return []

    @database_sync_to_async
    def get_room_user_message_status(self, username):
        if self.room.sender_username == username:
            return self.room.sender_message_status
        elif self.room.receiver_username == username:
            return self.room.receiver_message_status

    @database_sync_to_async
    def set_user_status(self, username, status):
        user_profile = UserProfile.objects.get(
            user__username=username)

        user_profile.status = status
        user_profile.save()

    @database_sync_to_async
    def set_room_user_message_status(self, username=None, status=-1):
        try:
            room = Room.objects.get(room=self.room.room)
            if self.room.sender_username == username:
                room.sender_message_status = status
                room.save()
            elif self.room.receiver_username == username:
                room.receiver_message_status = status
                room.save()
            self.room = room
        except Room.DoesNotExist:
            pass

    @database_sync_to_async
    def update_public_key_db(self, user=None, ratchet_public_key=None, device_id=None):
        if self.room and ratchet_public_key:
            public_key = PublicKey.get_latest_public_key(user=user, room=self.room,
                                                         device_id=UserDevice.get_device_by_id(self.device_id))
            if public_key:
                public_key.ratchet_key = PublicKey.load_ratchet_key_raw(ratchet_public_key)
                public_key.save()

    @staticmethod
    def get_channel_name(username):
        user = connected_users.get(username)
        if user:
            return user.get('channel_name')
        return None

    @staticmethod
    def get_device_channel_name(username, device_id):
        user = connected_users.get(username)
        if user:
            device_info = user['devices'].get(device_id)
            if device_info:
                return device_info.get('channel_name', None)
        return None

    @staticmethod
    def delete_messages_data(receiver_user, username, room, sender):
        messages_db = Message.objects.filter(room=room, saved=False)

        if messages_db.exists():
            public_ids_to_delete = []
            for message in messages_db:
                if message.image_url:
                    public_id = get_image_public_id(message.image_url)
                    if public_id:
                        public_ids_to_delete.append(public_id)
            # messages_db.delete()
            if public_ids_to_delete:
                try:
                    delete_resources(public_ids_to_delete)
                except Exception:
                    pass
