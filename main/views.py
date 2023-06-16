import asyncio
import uuid

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.http import HttpResponse
from django.shortcuts import render

# Create your views here.
from main.consumers import MyWebSocketConsumer


def generate_unique_id():
    # Generate a unique ID using UUID version 4
    unique_id = str(uuid.uuid4())
    return unique_id


async def my_api_view(request):
    client_id = request.GET.get('CLIENT_ID')
    data = '{"message": "Hello from the main server", "test": "test"}'
    request_id = generate_unique_id()

    if MyWebSocketConsumer.get_clients(client_id=client_id):

        # Forward the data to the selected client
        await MyWebSocketConsumer.forward_to_client(client_id=client_id, request_id=request_id, data=data)

        # Wait for the client response
        client_response = await MyWebSocketConsumer.get_client_response(client_id, request_id=request_id)

        # Return the client response as the API response
        if client_response is not None:
            return HttpResponse(client_response)
        else:
            return HttpResponse(client_response)
    else:
        return HttpResponse('No idle clients available')