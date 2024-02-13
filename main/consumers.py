import asyncio
import hashlib
import json
import time
import uuid
from urllib.parse import parse_qs

from channels.db import database_sync_to_async
from channels.exceptions import StopConsumer
from channels.generic.websocket import AsyncWebsocketConsumer
from django.contrib.auth.models import User
from django.core.serializers.json import DjangoJSONEncoder
from django.db import IntegrityError

from ReiserX_Tunnel import settings
from ReiserX_Tunnel.AuthBackend import CustomAuthBackend
from main import Utils
from main.models import UserProfile, Room, Message, new_signal_message, connected_users


class ClientBusyException(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


def generate_unique_id():
    # Generate a unique ID using UUID version 4
    unique_id = str(uuid.uuid4())
    return unique_id


class MyWebSocketConsumer(AsyncWebsocketConsumer):
    connected_clients = {}
    client_responses = {}
    event_loop = None
    client_id = None
    user = None

    @database_sync_to_async
    def authenticate(self, api_key, client_id):
        # Call your custom authentication backend's authenticate method
        return CustomAuthBackend().authenticate(request=None, api_key=api_key, client_id=client_id)

    async def connect(self):
        await self.accept()

        query_string = self.scope['query_string'].decode('utf-8')
        query_params = parse_qs(query_string)

        client_id = query_params.get('client_id', [''])[0]

        api_key = query_params.get('api_key', [''])[0]

        # Authenticate the user based on the provided client_id and api_key
        self.user, limit = await self.authenticate(api_key=api_key, client_id=client_id)

        if self.user is None:
            await self.close(4000)
            return
        else:
            if not limit:
                await self.close(4001)
                return
            elif client_id in self.connected_clients:
                await self.close(4002)
                return

        # Add the WebSocket instance to the dictionary of connected clients
        self.connected_clients[client_id] = {
            'websocket': self,
            'status': 'idle',
            'response_queue': asyncio.Queue(),
            'user': self.user
        }

        # Set the client ID as an attribute of the WebSocket instance
        self.client_id = client_id

    async def disconnect(self, close_code):
        # Perform any necessary cleanup or handling of disconnections
        # Remove the WebSocket instance from the set of connected clients
        if self.client_id in self.connected_clients:
            del self.connected_clients[self.client_id]

        # Remove the client ID from the UserProfile's connected clients
        if self.user is not None:
            await self.user.userprofile.remove_client(client_id=self.client_id)

        raise StopConsumer()

    async def receive(self, text_data=None, bytes_data=None):
        # Process the received message from the client
        response_tuple = text_data

        # Put the response tuple into the response queue
        await self.connected_clients[self.client_id]['response_queue'].put(response_tuple)

    @classmethod
    async def forward_to_client(cls, client_id, data):
        client_data = cls.connected_clients.get(client_id)
        client_data['status'] = 'busy'

        if client_data is None:
            # Client does not exist
            return

        client_websocket = client_data['websocket']

        # Send the modified data to the specified client
        await client_websocket.send(data.decode('utf-8'))

        return

    @classmethod
    def get_client(cls, client_id, user):
        try:
            if cls.connected_clients[client_id]['status'] == 'idle' and cls.connected_clients[client_id][
                'user'] == user:
                return cls.connected_clients[client_id]['websocket']
            raise ClientBusyException('Client is not available or busy')
        except KeyError:
            return None

    @classmethod
    def get_client_details(cls, client_id):
        try:
            return cls.connected_clients[client_id]
        except KeyError:
            return None

    @classmethod
    def get_connected_clients(cls):
        return list(cls.connected_clients.keys())

    @classmethod
    def get_busy_clients(cls):
        # Return a list of client IDs that are currently busy
        return [client_id for client_id, client_data in cls.connected_clients.items() if
                client_data['status'] == 'busy']

    @classmethod
    def get_idle_clients(cls):
        # Return a list of client IDs that are currently idle
        return [client_id for client_id, client_data in cls.connected_clients.items() if
                client_data['status'] == 'idle']


@database_sync_to_async
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
        # Call your custom authentication backend's authenticate method
        return CustomAuthBackend().authenticate_api(api_key=api_key)

    async def connect(self):
        await self.accept()
        query_string = self.scope['query_string'].decode('utf-8')
        query_params = parse_qs(query_string)

        sender_username = query_params.get('sender_username', None)
        receiver_username = query_params.get('receiver_username', None)
        api = query_params.get('api', None)
        await self.listen_for_signal_messages()

        if receiver_username is not None and api is not None:
            sender = await self.authenticate(api[0])
            sender_username = sender.get_username()
            receiver_username = receiver_username[0]

            if sender is not None:
                await self.connect_chat(sender_username=sender_username, receiver_username=receiver_username,
                                        sender=sender)
            else:
                await self.close()
        elif receiver_username is not None and sender_username is not None:
            sender_username = sender_username[0]
            receiver_username = receiver_username[0]
            sender = await self.get_user(sender_username)

            if sender.is_authenticated:
                await self.connect_chat(sender_username=sender_username, receiver_username=receiver_username,
                                        sender=sender)
            else:
                await self.close()

        else:
            await self.close()

    async def listen_for_signal_messages(self):
        async def forward_signal_messages(sender, message, timestamp, sender_username, **kwargs):
            # Forward the User1 message to User3
            if sender_username != self.sender_username:
                await self.send(text_data=json.dumps({
                    'type': 'new_message_background',
                    'message': message,
                    'timestamp': timestamp,
                    'sender_username': sender_username
                }, cls=DjangoJSONEncoder))

        new_signal_message.connect(forward_signal_messages)

    async def connect_chat(self, sender_username, receiver_username, sender):
        self.room = await get_or_create_room(sender_username, receiver_username)
        self.sender_username = sender_username
        self.receiver_username = receiver_username

        self.sender = sender
        self.receiver = await self.get_user(receiver_username)

        if self.room is not None:
            await self.channel_layer.group_add(
                self.room.room,
                self.channel_name
            )

            if settings.DEBUG is False:
                subject = "A New Message Is Received"

                message = f"{sender_username} has added you on Vocalhost chat."

                to_email = self.receiver.email
                try:
                    Utils.send_email(subject=subject, message=message, to_email=to_email)
                except Exception as e:
                    pass

            if self.receiver:
                await self.send(text_data=json.dumps({
                    'type': 'user_status',
                    'username': receiver_username,
                    'status': await self.get_user_status(self.receiver),
                }))

            await self.channel_layer.group_send(
                self.room.room,
                {
                    "type": "update_user_status",
                    "status": "online",
                    "username": sender_username,
                },
            )
            connected_users[self.sender_username] = self.sender_username
        else:
            await self.close()

    async def disconnect(self, close_code):
        if self.room.room is not None:
            await self.set_room_user_status(self.sender_username, False)
            await self.channel_layer.group_send(
                self.room.room,
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
        if text_data is not None:
            text_data_json = json.loads(text_data)
            type = text_data_json.get('type')
            message = text_data_json.get("message")
            message_id = text_data_json.get('message_id')
            reply_id = text_data_json.get('reply_id')
            storeMessage = text_data_json.get("storeMessage")

            if type == 'reply_message':
                # Generate message_id
                message_id = int(time.time() * 1000)
                await self.channel_layer.group_send(
                    self.room.room,
                    {
                        "type": "chat_message",
                        "message": message,
                        "message_id": message_id,
                        'reply_id': reply_id,
                        "sender_username": self.sender_username,
                    },
                )
                if storeMessage:
                    await self.save_message_db(message=message, message_id=message_id, reply_id=reply_id)
                else:
                    status = await self.get_room_user_status(self.receiver_username)
                    if not status:
                        await self.save_message_db(message=message, message_id=message_id, reply_id=reply_id,
                                                   temp=self.receiver)
            elif type == 'message':
                # Generate message_id
                message_id = int(time.time() * 1000)
                await self.channel_layer.group_send(
                    self.room.room,
                    {
                        "type": "chat_message",
                        "message": message,
                        "message_id": message_id,
                        "sender_username": self.sender_username,
                    },
                )
                if storeMessage:
                    await self.save_message_db(message=message, message_id=message_id, reply_id=reply_id)
                else:
                    status = await self.get_room_user_status(self.receiver_username)
                    if not status:
                        await self.save_message_db(message=message, message_id=message_id, temp=self.receiver)
            elif type == 'save_message':
                save_message = text_data_json.get("save_message")
                sender = text_data_json.get("sender")
                receiver = text_data_json.get("receiver")
                await self.channel_layer.group_send(
                    self.room.room,
                    {
                        "type": "save_message",
                        "message_id": message_id,
                        'save_message': save_message
                    },
                )
                if save_message:
                    await self.save_message_db(message, message_id, sender, receiver, reply_id)
                else:
                    await self.delete_message_db(message_id)
            elif type == 'delete_message':
                sender_username = text_data_json.get("sender_username")
                permission = await self.delete_permission_db(message_id, sender_username)
                if permission:
                    await self.delete_message_db(message_id)
                    await self.channel_layer.group_send(
                        self.room.room,
                        {
                            "type": "delete_message",
                            "message_id": message_id,
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

            await self.channel_layer.group_send(
                self.room.room,
                {
                    "type": "image_bytes_data",
                    "message": text_message,
                    "image_data": image_data,
                    'message_id': message_id,
                    "sender_username": self.sender_username,
                }
            )
            if data.get("storeMessage"):
                await self.save_message_db(message=text_message, message_id=message_id)
            else:
                status = await self.get_room_user_status(self.receiver_username)
                if not status:
                    await self.save_message_db(message=text_message, message_id=message_id, temp=self.receiver)

    async def chat_message(self, event):
        sender_username = event["sender_username"]
        message = event["message"]
        message_id = event['message_id']
        if sender_username != self.sender_username:
            reply_id = event.get('reply_id', None)
            if reply_id:
                await self.send(
                    text_data=json.dumps(
                        {
                            "message": message,
                            'message_id': message_id,
                            'reply_id': reply_id,
                            "sender_username": sender_username,
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
                        }
                    )
                )

        else:
            await self.send(
                text_data=json.dumps(
                    {
                        "type": 'message_sent',
                        'message_id': message_id,
                        'data_type': 'text'
                    }
                )
            )

    async def image_bytes_data(self, event):
        sender_username = event["sender_username"]
        message_id = event['message_id']
        print(message_id)

        await self.send(
            text_data=json.dumps(
                {
                    "type": 'message_sent',
                    'message_id': message_id,
                    'data_type': 'bytes'
                }
            )
        )

        if sender_username != self.sender_username:
            image_data = event["image_data"]

            message = event["message"]
            combined_data = f"{message_id}\n{message}\n{sender_username}\n".encode('utf-8') + b'\n' + image_data

            # Send the combined data as bytes_data
            await self.send(bytes_data=combined_data)

    async def save_message(self, event):
        message_id = event['message_id']
        save_message = event.get("save_message")
        await self.send(
            text_data=json.dumps(
                {
                    "type": "save_message",
                    "message_id": message_id,
                    'save_message': save_message
                }
            )
        )

    async def delete_message(self, event):
        message_id = event['message_id']
        await self.send(
            text_data=json.dumps(
                {
                    "type": "delete_message",
                    "message_id": message_id,
                }
            )
        )

    async def update_user_status(self, event):
        status = event['status']
        username = event['username']
        status_bool = (status == 'online')

        await self.set_user_status(username, status_bool)

        await self.set_room_user_status(username, status_bool)

        await self.send(text_data=json.dumps({
            'type': 'user_status',
            'username': username,
            'status': status,
        }))

    @database_sync_to_async
    def get_user(self, username):
        try:
            return User.objects.get(username=username)
        except User.DoesNotExist:
            return None

    @database_sync_to_async
    def save_message_db(self, message=None, message_id=None, sender=None, receiver=None, reply_id=None, temp=None):
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
        if message is not None and message != '' and message_id is not None:
            try:
                Message.objects.create(
                    message=message,
                    room=self.room,
                    sender=sender,
                    receiver=receiver,
                    message_id=message_id,
                    reply_id=reply_message,
                    temp=temp
                )
            except IntegrityError:
                pass

    @database_sync_to_async
    def delete_message_db(self, message_id):
        try:
            message = Message.objects.get(message_id=message_id)
            message.delete()
        except Message.DoesNotExist:
            pass

    @database_sync_to_async
    def delete_permission_db(self, message_id, sender_username):
        try:
            message = Message.objects.get(message_id=message_id)
            if message.sender.username == sender_username:
                return True
            else:
                return False
        except Message.DoesNotExist:
            return True

    @database_sync_to_async
    def get_user_status(self, user):
        if user.userprofile.status:
            return 'online'
        else:
            return 'offline'

    @database_sync_to_async
    def get_room_user_status(self, username):
        if self.room.sender_username == username:
            return self.room.sender_status
        elif self.room.receiver_username == username:
            return self.room.receiver_status
        else:
            return False

    @database_sync_to_async
    def set_user_status(self, username, status):
        user_profile = UserProfile.objects.get(user__username=username)  # Replace 'username' with the actual username

        user_profile.status = status
        user_profile.save()

    @database_sync_to_async
    def set_room_user_status(self, username=None, status=False):
        if self.room.sender_username == username:
            self.room.sender_status = status
            self.room.save()
        elif self.room.receiver_username == username:
            self.room.receiver_status = status
            self.room.save()
