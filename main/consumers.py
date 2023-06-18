import asyncio
import json
import time
import uuid
from urllib.parse import parse_qs

from channels.generic.websocket import AsyncWebsocketConsumer


def generate_unique_id():
    # Generate a unique ID using UUID version 4
    unique_id = str(uuid.uuid4())
    return unique_id


class MyWebSocketConsumer(AsyncWebsocketConsumer):
    connected_clients = {}
    client_responses = {}

    async def connect(self):
        # Perform any necessary initialization or authentication
        await self.accept()

        query_string = self.scope['query_string'].decode('utf-8')
        query_params = parse_qs(query_string)

        client_id = query_params.get('client_id', [''])[0]

        print(client_id)

        # Add the WebSocket instance to the dictionary of connected clients
        self.connected_clients[client_id] = {
            'websocket': self,
            'status': 'idle',
            'response_queue': asyncio.Queue(),
            'request_queue': asyncio.Queue(),
            'request_id': generate_unique_id()
        }

        # Set the client ID as an attribute of the WebSocket instance
        self.client_id = client_id

    async def disconnect(self, close_code):
        # Perform any necessary cleanup or handling of disconnections
        # Remove the WebSocket instance from the set of connected clients
        if self.client_id in self.connected_clients:
            del self.connected_clients[self.client_id]

    async def receive(self, text_data=None, bytes_data=None):
        # Process the received message from the client
        response_tuple = (self.connected_clients[self.client_id]['request_id'], text_data)

        # Put the response tuple into the response queue
        await self.connected_clients[self.client_id]['response_queue'].put(response_tuple)

    @classmethod
    async def forward_to_client(cls, client_id, data):
        client_data = cls.connected_clients.get(client_id)

        if client_data is None:
            # Client does not exist
            return

        client_status = client_data['status']
        client_queue = client_data['request_queue']
        client_websocket = client_data['websocket']

        if client_status == 'busy':
            # Client is busy, queue the request
            await client_queue.put((cls.connected_clients[client_id]['request_id'], data))
        else:
            # Client is idle, send the request immediately
            client_data['status'] = 'busy'

            # Send the modified data to the specified client
            await client_websocket.send(data.decode('utf-8'))

            return cls.connected_clients[client_id]['request_id']

    @classmethod
    async def get_client_response(cls, client_id, request_id, timeout=120):
        # Get the response queue for the client ID
        response_queue = cls.connected_clients[client_id]['response_queue']

        # Create a task to wait for the response
        task = asyncio.create_task(response_queue.get())

        start_time = time.time()
        remaining_time = timeout

        while remaining_time > 0:
            try:
                # Wait for the task to complete with the remaining timeout
                response = await asyncio.wait_for(task, remaining_time)
            except asyncio.TimeoutError:
                return None

            # Check if the response has a matching request ID
            if isinstance(response, tuple) and response[0] == request_id:
                # Update the status of the client to idle
                cls.connected_clients[client_id]['status'] = 'idle'
                return response[1]

            # Create a new task for the next response
            task = asyncio.create_task(response_queue.get())

            # Calculate the elapsed time
            elapsed_time = time.time() - start_time
            remaining_time = timeout - elapsed_time

        return None

    @classmethod
    def get_clients(cls, client_id):
        if client_id in cls.connected_clients:
            return True
        return False

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