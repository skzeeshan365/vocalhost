import asyncio
import uuid
from urllib.parse import parse_qs

from channels.exceptions import StopConsumer
from channels.generic.websocket import AsyncWebsocketConsumer


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

    async def connect(self):
        # Perform any necessary initialization or authentication
        await self.accept()

        query_string = self.scope['query_string'].decode('utf-8')
        query_params = parse_qs(query_string)

        client_id = query_params.get('client_id', [''])[0]

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
    def get_client(cls, client_id):
        try:
            if cls.connected_clients[client_id]['status'] == 'idle':
                return cls.connected_clients[client_id]['websocket']
            raise ClientBusyException('Client is busy')
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