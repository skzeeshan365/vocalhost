import asyncio
import uuid
from urllib.parse import parse_qs

from channels.db import database_sync_to_async
from channels.exceptions import StopConsumer
from channels.generic.websocket import AsyncWebsocketConsumer

from ReiserX_Tunnel.AuthBackend import CustomAuthBackend
from main.models import UserProfile, Client


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
            await self.send("Invalid api")
            await self.close()
            return
        else:
            if not limit:
                await self.send("Max receiver limit")
                await self.close()
                return
            elif client_id in self.connected_clients:
                await self.send("Client id already exists")
                await self.close()
                return

        # Add the WebSocket instance to the dictionary of connected clients
        self.connected_clients[client_id] = {
            'websocket': self,
            'status': 'idle',
            'response_queue': asyncio.Queue()
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
            await self.remove_client_id_from_user_profile(self.user, self.client_id)

        raise StopConsumer()

    @staticmethod
    @database_sync_to_async
    def remove_client_id_from_user_profile(user, client_id):
        try:
            user_profile = UserProfile.objects.get(user=user)
            client_instance = Client.objects.get(client_id=client_id)
            if client_instance in user_profile.connected_clients.all():
                client_instance.delete()
                user_profile.save()
        except UserProfile.DoesNotExist:
            pass
        except Client.DoesNotExist:
            pass

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
    def get_client(cls, client_id):
        try:
            if cls.connected_clients[client_id]['status'] == 'idle':
                return cls.connected_clients[client_id]['websocket']
            raise ClientBusyException('Client is busy')
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