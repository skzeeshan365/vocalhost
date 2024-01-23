import asyncio
import hashlib
import json
import threading
import time
import uuid
from urllib.parse import parse_qs

from channels.db import database_sync_to_async
from channels.exceptions import StopConsumer
from channels.generic.websocket import AsyncWebsocketConsumer
from django.contrib.auth.models import User

from ReiserX_Tunnel.AuthBackend import CustomAuthBackend
from main import Utils
from main.models import UserProfile, Client, Room, Message


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
    def authenticate(self, api_key, client, client_id):
        # Call your custom authentication backend's authenticate method
        return CustomAuthBackend().authenticate(request=None, api_key=api_key, client_id=client_id)

    async def connect(self):
        await self.accept()

        query_string = self.scope['query_string'].decode('utf-8')
        query_params = parse_qs(query_string)

        client_id = query_params.get('client_id', [''])[0]

        api_key = query_params.get('api_key', [''])[0]

        # Authenticate the user based on the provided client_id and api_key
        self.user, limit = await self.authenticate(api_key=api_key, client_id=client_id, client=self)

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
            if cls.connected_clients[client_id]['status'] == 'idle' and cls.connected_clients[client_id]['user'] == user:
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
        room=room_identifier
    )

    return room


class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        query_string = self.scope['query_string'].decode('utf-8')
        query_params = parse_qs(query_string)

        self.sender_username = query_params.get('sender_username', [''])[0]
        self.receiver_username = query_params.get('receiver_username', [''])[0]

        self.room = await get_or_create_room(self.sender_username, self.receiver_username)

        self.sender = await self.get_user(self.sender_username)
        self.receiver = await self.get_user(self.receiver_username)

        if self.room is not None:
            await self.channel_layer.group_add(
                self.room.room,
                self.channel_name
            )

            subject = "A New Message Is Received"

            message = f"{self.sender_username} is connected on Vocalhost, Respond immediately."

            to_email = 'skzeeshan3650@gmail.com'

            try:
                Utils.send_email(subject=subject, message=message, to_email=to_email)
            except Exception as e:
                pass
        else:
            await self.close()

    async def disconnect(self, close_code):
        pass  # You may want to handle disconnections here

    async def receive(self, text_data):
        text_data_json = json.loads(text_data)
        message = text_data_json["message"]

        # Broadcast the message to all connected clients
        await self.channel_layer.group_send(
            self.room.room,
            {
                "type": "chat_message",
                "message": message,
                "sender_username": self.sender_username,
            },
        )

        await self.save_message(message)

    async def chat_message(self, event):
        message = event["message"]
        sender_username = event["sender_username"]

        # Send the message to the current user's WebSocket
        await self.send(
            text_data=json.dumps(
                {
                    "message": message,
                    "sender_username": sender_username,
                }
            )
        )

    @database_sync_to_async
    def get_user(self, username):
        try:
            return User.objects.get(username=username)
        except User.DoesNotExist:
            return None

    @database_sync_to_async
    def save_message(self, chat_message):
        Message.objects.create(
            message=chat_message,
            room=self.room,
            sender=self.sender,
            receiver=self.receiver
        )