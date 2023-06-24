import asyncio
from json import JSONDecodeError

from django.core.signals import request_finished
from django.dispatch import receiver
from django.http import HttpResponse
from django.shortcuts import render

from ReiserX_Tunnel import settings
from main.consumers import MyWebSocketConsumer


# Create your views here.


def home(request):
    return render(request, 'index.html')


def docs(request):
    return render(request, 'main.html')


cancel_event = asyncio.Event()


@receiver(request_finished)
def terminate(sender, **kwargs):
    cancel_event.set()


async def connect(request, client_id):
    if request.method == 'POST':
        if request.headers.get('Authorization') == 'key=' + settings.CONNECT_KEY:
            try:
                client = MyWebSocketConsumer.get_client(client_id=client_id)
                if client:
                    data = request.body
                    timeout = int(request.headers.get('Timeout'))

                    if timeout > 120:
                        return HttpResponse('Invalid timeout')

                    # Forward the data to the selected client
                    await client.forward_to_client(client_id=client_id, data=data)

                    try:
                        response_queue = client.connected_clients[client_id]['response_queue']
                        client.connected_clients[client_id]['status'] = 'idle'
                        cancel_event.clear()

                        try:
                            task = asyncio.ensure_future(response_queue.get())
                            done, _ = await asyncio.wait(
                                [task],
                                timeout=timeout,
                                return_when=asyncio.FIRST_COMPLETED
                            )

                            if task in done:
                                # Task completed successfully, retrieve the result
                                client_response = task.result()
                                # Return the client response as the API response
                                if client_response is not None:
                                    return HttpResponse(client_response, content_type='text/plain')
                                else:
                                    return HttpResponse('Client never responded', content_type='text/plain')
                            else:
                                # Request was finished, cancel the task
                                task.cancel()
                                return HttpResponse('Request cancelled', content_type='text/plain')

                        except asyncio.CancelledError:
                            # Task was cancelled due to request finished
                            return HttpResponse('Request cancelled', content_type='text/plain')

                    except BaseException as e:
                        return HttpResponse(str(e), content_type='text/plain')
                else:
                    return HttpResponse('Client not found', content_type='text/plain')

            except JSONDecodeError as e:
                return HttpResponse(f'An error occurred: {e}', content_type='text/plain')
            except Exception as e:
                return HttpResponse(str(e), content_type='text/plain')
        else:
            return HttpResponse('Invalid key')
    else:
        return HttpResponse('Invalid request')


def connected_clients(request):
    clients = MyWebSocketConsumer.get_connected_clients()
    if not clients:
        return HttpResponse('No available clients')
    return HttpResponse(clients)


def idle_clients(request):
    clients = MyWebSocketConsumer.get_idle_clients()
    if not clients:
        return HttpResponse('No available clients')
    return HttpResponse(clients)


def busy_clients(request):
    clients = MyWebSocketConsumer.get_busy_clients()
    if not clients:
        return HttpResponse('No available clients')
    return HttpResponse(clients)
