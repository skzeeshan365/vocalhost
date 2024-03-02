import hashlib
import hashlib
import json
import threading
import time
from urllib.parse import parse_qs

from channels.db import database_sync_to_async
from channels.exceptions import StopConsumer
from channels.generic.websocket import AsyncWebsocketConsumer
from cloudinary.api import delete_resources
from django.contrib.auth.models import User
from django.core.serializers.json import DjangoJSONEncoder

from ReiserX_Tunnel import settings
from ReiserX_Tunnel.AuthBackend import CustomAuthBackend
from main import Utils
from main.Utils import cloudinary_image_delete, cloudinary_image_upload, get_image_public_id
from chat.models import Room, Message, new_signal_message, connected_users
from main.models import UserProfile


@database_sync_to_async
def get_room_db(sender_username, receiver_username):
    # Ensure that the users are sorted before creating the room identifier
    combined_usernames_set = frozenset([sender_username, receiver_username])
    sorted_usernames = sorted(combined_usernames_set)

    room_identifier = hashlib.sha256(str(sorted_usernames).encode()).hexdigest()

    try:
        room = Room.objects.get(
            room=room_identifier,
            sender_username=sorted_usernames[0],
            receiver_username=sorted_usernames[1]
        )
        return room
    except Room.DoesNotExist:
        return None


def getRoom(sender_username, receiver_username):
    combined_usernames_set = frozenset([sender_username, receiver_username])
    sorted_usernames = sorted(combined_usernames_set)

    room = hashlib.sha256(str(sorted_usernames).encode()).hexdigest()
    room = Room.objects.filter(room=room).first()
    return room


class ChatConsumer(AsyncWebsocketConsumer):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.room = None
        self.sender = None
        self.receiver = None
        self.sender_username = None
        self.receiver_username = None
        self.api = None

    @database_sync_to_async
    def authenticate(self, api_key):
        return CustomAuthBackend().authenticate_api(api_key=api_key)

    async def connect(self):
        await self.accept()
        query_string = self.scope['query_string'].decode('utf-8')
        query_params = parse_qs(query_string)
        sender_username = query_params.get('sender_username', None)
        api = query_params.get('api', None)
        await self.listen_for_signal_messages()

        if api is not None:
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
                connected_users[self.sender_username] = {'channel_name': self.channel_name}
            else:
                await self.close()
        elif sender_username is not None:
            self.sender_username = sender_username[0]
            self.sender = await self.get_user(self.sender_username)

            if self.sender.is_authenticated:
                await self.channel_layer.group_send(
                    'chat',
                    {
                        "type": "update_user_status",
                        "status": "online",
                        "username": self.sender_username,
                    },
                )
                connected_users[self.sender_username] = {'channel_name': self.channel_name}
            else:
                await self.close()

        else:
            await self.close()

    async def listen_for_signal_messages(self):
        async def forward_signal_messages(sender, receiver_username, message, **kwargs):
            if receiver_username == self.sender_username:
                await self.send(text_data=json.dumps(message, cls=DjangoJSONEncoder))

        new_signal_message.connect(forward_signal_messages)

    async def disconnect(self, close_code):
        if self.room:
            await self.set_room_user_status_db(self.sender_username)
        await self.channel_layer.group_send(
            'chat',
            {
                "type": "update_user_status",
                "status": "offline",
                "username": self.sender_username,
            },
        )
        if self.sender_username in connected_users:
            del connected_users[self.sender_username]
        raise StopConsumer

    async def receive(self, text_data=None, bytes_data=None):
        channel_name = self.get_channel_name(self.receiver_username)
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
            elif type == 'reply_message':
                # Generate message_id
                message_id = int(time.time() * 1000)

                public_key = text_data_json.get('public_key')
                await self.update_public_key_db(self.sender_username, public_key)

                if channel_active:
                    await self.channel_layer.send(
                        channel_name,
                        {
                            "type": "chat_message",
                            "message": message,
                            "message_id": message_id,
                            'reply_id': reply_id,
                            "sender_username": self.sender_username,
                            'public_key': public_key
                        },
                    )
                    if storeMessage:
                        await self.save_message_db(message=message, message_id=message_id, reply_id=reply_id,
                                                   saved=True)
                elif channel_name:
                    await self.channel_layer.send(
                        channel_name,
                        {
                            'type': 'new_message_background',
                            'timestamp': message_id,
                            'sender_username': self.sender_username
                        }
                    )
                    await self.save_message_db(message=message, message_id=message_id, reply_id=reply_id,
                                               temp=self.receiver)
                else:
                    await self.save_message_db(message=message, message_id=message_id, reply_id=reply_id,
                                               temp=self.receiver)

                await self.send(
                    text_data=json.dumps(
                        {
                            "type": 'message_sent',
                            'message_id': message_id,
                            'data_type': 'text'
                        }
                    )
                )
            elif type == 'message':
                # Generate message_id
                message_id = int(time.time() * 1000)
                public_key = text_data_json.get('public_key')
                await self.update_public_key_db(self.sender_username, public_key)
                if channel_active:
                    await self.channel_layer.send(
                        channel_name,
                        {
                            "type": "chat_message",
                            "message": message,
                            "message_id": message_id,
                            "sender_username": self.sender_username,
                            'public_key': public_key
                        },
                    )
                    if storeMessage:
                        await self.save_message_db(message=message, message_id=message_id, reply_id=reply_id,
                                                   saved=True)
                elif channel_name:
                    await self.channel_layer.send(
                        channel_name,
                        {
                            'type': 'new_message_background',
                            'timestamp': message_id,
                            'sender_username': self.sender_username
                        }
                    )
                    await self.save_message_db(message=message, message_id=message_id, temp=self.receiver, public_key=public_key)
                else:
                    await self.save_message_db(message=message, message_id=message_id, temp=self.receiver, public_key=public_key)
                await self.send(
                    text_data=json.dumps(
                        {
                            "type": 'message_sent',
                            'message_id': message_id,
                            'data_type': 'text'
                        }
                    )
                )

            elif type == 'save_message':
                save_message = text_data_json.get("save_message")
                sender = text_data_json.get("sender")
                receiver = text_data_json.get("receiver")
                image_url = text_data_json.get('image_url')
                if channel_active:
                    await self.channel_layer.send(
                        channel_name,
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
                        await self.channel_layer.send(
                            channel_name,
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
                    await self.channel_layer.send(
                        channel_name,
                        {
                            "type": "message_seen",
                            "message_id": message_id,
                            "sender_username": self.sender_username,
                        },
                    )
            elif type == 'typing_status':
                typing = text_data_json.get('typing')
                if channel_name:
                    await self.channel_layer.send(
                        channel_name,
                        {
                            "type": "typing_status",
                            "typing": typing,
                            "sender_username": self.sender_username,
                        },
                    )

        if bytes_data:
            json_end = bytes_data.index(b'}') + 1
            json_data = bytes_data[:json_end].decode('utf-8')
            data = json.loads(json_data)

            text_message = data.get("message")
            message_id = int(time.time() * 1000)

            # Extract binary image data
            image_data = bytes_data[json_end:]

            if channel_active:
                await self.channel_layer.send(
                    channel_name,
                    {
                        "type": "image_bytes_data",
                        "message": text_message,
                        "image_data": image_data,
                        'message_id': message_id,
                        "sender_username": self.sender_username,
                    }
                )
                if data.get("storeMessage"):
                    await self.save_message_db(message=text_message, message_id=message_id, saved=True)
            elif channel_name:
                await self.channel_layer.send(
                    channel_name,
                    {
                        'type': 'new_message_background',
                        'timestamp': message_id,
                        'sender_username': self.sender_username
                    }
                )
                await self.save_message_db(message=text_message, message_id=message_id, temp=self.receiver,
                                           image_url=image_data)
            else:
                await self.save_message_db(message=text_message, message_id=message_id, temp=self.receiver,
                                           image_url=image_data)

            await self.send(
                text_data=json.dumps(
                    {
                        "type": 'message_sent',
                        'message_id': message_id,
                        'data_type': 'bytes'
                    }
                )
            )

    async def chat_message(self, event):
        sender_username = event["sender_username"]
        message = event["message"]
        message_id = event['message_id']
        reply_id = event.get('reply_id', None)
        public_key = event.get('public_key')

        if reply_id:
            await self.send(
                text_data=json.dumps(
                    {
                        "message": message,
                        'message_id': message_id,
                        'reply_id': reply_id,
                        "sender_username": sender_username,
                        'public_key': public_key
                    }
                )
            )
        else:
            await self.send(
                text_data=json.dumps(
                    {
                        "message": message,
                        'message_id': message_id,
                        "sender_username": sender_username,
                        'public_key': public_key
                    }
                )
            )

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

        message = event["message"]
        combined_data = f"{message_id}\n{message}\n{sender_username}".encode('utf-8') + b'\n' + image_data

        # Send the combined data as bytes_data
        await self.send(bytes_data=combined_data)

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
        if self.room and receiver_username:
            await self.set_room_user_status_db(self.sender_username, None)
        if receiver_username:
            self.room = await get_room_db(self.sender_username, receiver_username)
            self.receiver_username = receiver_username

            self.receiver = await self.get_user(receiver_username)

            if self.room is not None:
                await self.set_room_user_status_db(self.sender_username, self.channel_name)
                await self.channel_layer.group_add(
                    'chat',
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
                connected_users[self.sender_username] = {'channel_name': self.channel_name, 'room': self.room.room}
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

    @database_sync_to_async
    def get_user(self, username):
        try:
            return User.objects.get(username=username)
        except User.DoesNotExist:
            return None

    @database_sync_to_async
    def save_message_db(self, message=None, message_id=None, sender=None, receiver=None, reply_id=None, temp=None,
                        saved=False, image_url=None, public_key=None):
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

        try:
            exists = Message.objects.get(message_id=message_id)
            if exists and temp is None:
                exists.saved = True
                exists.public_key = None
                exists.save()
        except Message.DoesNotExist:
            if image_url is not None:
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
                    temp=temp,
                    saved=saved,
                    image_url=image_url,
                    public_key=public_key
                )

    @database_sync_to_async
    def delete_message_db(self, message_id):
        try:
            message = Message.objects.get(message_id=message_id)
            if message.image_url:
                cloudinary_image_delete(message.image_url)
            message.delete()
        except Message.DoesNotExist:
            pass

    @database_sync_to_async
    def unsave_message_db(self, message_id):
        try:
            message = Message.objects.get(message_id=message_id)
            if message.temp:
                message.saved = False
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

    @database_sync_to_async
    def get_room_user_status_db(self, username):
        if self.room.sender_username == username:
            return self.room.sender_channel
        elif self.room.receiver_username == username:
            return self.room.receiver_channel

    @database_sync_to_async
    def set_user_status(self, username, status):
        user_profile = UserProfile.objects.get(
            user__username=username)

        user_profile.status = status
        user_profile.save()

    @database_sync_to_async
    def set_room_user_status_db(self, username=None, channel=None):
        if channel is None:
            thread = threading.Thread(target=self.delete_messages_data,
                                      args=(self.receiver_username, self.sender_username, self.room, self.sender))
            thread.start()
        try:
            room = Room.objects.get(room=self.room.room)
            if self.room.sender_username == username:
                room.sender_channel = channel
                room.save()
            elif self.room.receiver_username == username:
                room.receiver_channel = channel
                room.save()
            self.room = room
        except Room.DoesNotExist:
            pass

    @database_sync_to_async
    def update_public_key_db(self, username=None, public_key=None):
        if self.room and username and public_key:
            try:
                room = Room.objects.get(room=self.room.room)
                room.set_ratchet_key(username, public_key)
                room.save()
                self.room = room
            except Room.DoesNotExist:
                pass

    @staticmethod
    def get_channel_name(username):
        user = connected_users.get(username)
        if user:
            return user.get('channel_name')
        return None

    @staticmethod
    def delete_messages_data(receiver_user, username, room, sender):
        messages_db = Message.objects.filter(room=room, temp=sender, saved=False)

        if messages_db.exists():
            public_ids_to_delete = []
            for message in messages_db:
                if message.image_url:
                    public_id = get_image_public_id(message.image_url)
                    if public_id:
                        public_ids_to_delete.append(public_id)
            if public_ids_to_delete:
                try:
                    delete_resources(public_ids_to_delete)
                except Exception:
                    pass
            messages_db.delete()