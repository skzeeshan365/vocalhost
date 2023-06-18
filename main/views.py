import asyncio
import uuid

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render

# Create your views here.
from django.views.decorators.csrf import csrf_exempt

from main.consumers import MyWebSocketConsumer


def home(request):
    return HttpResponse('Welcome to Vocalhost')


@csrf_exempt
def connect(request, client_id):
    if request.method == 'POST':
        data = request.body

        if MyWebSocketConsumer.get_clients(client_id=client_id):
            # Forward the data to the selected client
            forward_to_client_sync = async_to_sync(MyWebSocketConsumer.forward_to_client)
            request_id = forward_to_client_sync(client_id=client_id, data=data)

            # Wait for the client response
            get_client_response_sync = async_to_sync(MyWebSocketConsumer.get_client_response)
            client_response = get_client_response_sync(client_id, request_id=request_id)

            # Return the client response as the API response
            if client_response is not None:
                return HttpResponse(client_response, content_type='text/plain')
            else:
                return HttpResponse(client_response, content_type='text/plain')
        else:
            return HttpResponse('Client not found', content_type='text/plain')
    else:
        return HttpResponse('Invalid request')