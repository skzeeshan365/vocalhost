import asyncio
from json import JSONDecodeError

from asgiref.sync import sync_to_async, async_to_sync
from django.contrib import auth
from django.contrib.auth import authenticate, login
from django.core.signals import request_finished
from django.dispatch import receiver
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

from ReiserX_Tunnel import settings
from main.consumers import MyWebSocketConsumer
# Create your views here.
from main.forms import RegistrationForm, LoginForm
from main.models import UserProfile

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
        user = await UserProfile.get_user(request.headers.get('Authorization'))
        if user is not None:
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
            return HttpResponse('Invalid api key')
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


def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            # Create a new User instance
            if form.email_exists():
                form.add_error('email', 'This email is already taken.')
            else:
                # Create a new User instance
                user = form.save()

                user = authenticate(username=user.username, password=form.cleaned_data['password1'])
                login(request, user)

                return redirect('profile')
    else:
        form = RegistrationForm()

    return render(request, 'registration/register.html', {'form': form})


def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username_or_email = form.cleaned_data['username_or_email']
            password = form.cleaned_data['password']

            # Authenticate using either username or email
            user = authenticate(request, username=username_or_email, password=password)
            if user is None:
                user = authenticate(request, email=username_or_email, password=password)

            if user is not None:
                login(request, user)
                return redirect('profile')  # Redirect to the home page or any other desired page
            else:
                form.add_error(None, 'Invalid username/email or password.')
    else:
        form = LoginForm()

    return render(request, 'registration/login.html', {'form': form})


def get_api(request):
    if request.method == 'GET':
        # Assuming you have a User model with an 'api_key' field
        if request.user.is_authenticated:
            api_key = request.user.userprofile.api
            return JsonResponse({'api_content': api_key})
        else:
            return JsonResponse({'error': 'User is not authenticated'}, status=401)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)


def logout(request):
    auth.logout(request)
    return redirect('home')


def profile(request):
    user = request.user
    username = user.username
    email = user.email
    api = user.userprofile.api
    clients = user.userprofile.connected_clients.all()
    context = {'username': username, 'email': email, 'api': api, 'clients': clients}

    return render(request, 'registration/profile.html', context)