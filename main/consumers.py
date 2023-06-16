import asyncio
import json
import time
from urllib.parse import parse_qs

from channels.generic.websocket import AsyncWebsocketConsumer


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
        # Handle the request and send a response back, if required
        data = json.loads(text_data)

        # Access the data fields as needed
        request_id = data.get('request_id')

        # Create a tuple with None as the request ID and the response data
        data['data'].pop('request_id', None)
        data = json.dumps(data['data'])
        response_tuple = (request_id, data)

        # Put the response tuple into the response queue
        await self.connected_clients[self.client_id]['response_queue'].put(response_tuple)

    @classmethod
    async def forward_to_client(cls, client_id, request_id, data):
        client_data = cls.connected_clients.get(client_id)

        if client_data is None:
            # Client does not exist
            return

        client_status = client_data['status']
        client_queue = client_data['request_queue']
        client_websocket = client_data['websocket']

        if client_status == 'busy':
            # Client is busy, queue the request
            await client_queue.put((request_id, data))
        else:
            # Client is idle, send the request immediately
            client_data['status'] = 'busy'

            # Convert the data string to a dictionary
            data_dict = json.loads(data)

            # Create a new dictionary with the client ID and request ID included
            data_with_client_id = data_dict.copy()
            data_with_client_id['request_id'] = request_id

            # Convert the dictionary back to a string
            data_with_client_id_str = json.dumps(data_with_client_id)

            # Send the modified data to the specified client
            await client_websocket.send(data_with_client_id_str)

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