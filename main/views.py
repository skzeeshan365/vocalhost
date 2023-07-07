import asyncio
from json import JSONDecodeError

from django.contrib import auth
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.core.signals import request_finished
from django.dispatch import receiver
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect

from ReiserX_Tunnel import AuthBackend
from main.consumers import MyWebSocketConsumer
# Create your views here.
from main.forms import RegistrationForm, LoginForm
from main.models import UserProfile, Client


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


@login_required(login_url='/account/login/')
def connected_clients(request):
    if request.user.is_superuser:
        clients = MyWebSocketConsumer.get_connected_clients()
        if not clients:
            return HttpResponse('No available clients')
        return HttpResponse(clients)
    else:
        return HttpResponse('Permission denied')


@login_required(login_url='/account/login/')
def idle_clients(request):
    if request.user.is_superuser:
        clients = MyWebSocketConsumer.get_idle_clients()
        if not clients:
            return HttpResponse('No available clients')
        return HttpResponse(clients)
    else:
        return HttpResponse('Permission denied')


@login_required(login_url='/account/login/')
def busy_clients(request):
    if request.user.is_superuser:
        clients = MyWebSocketConsumer.get_busy_clients()
        if not clients:
            return HttpResponse('No available clients')
        return HttpResponse(clients)
    else:
        return HttpResponse('Permission denied')


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


@login_required(login_url='/account/login/')
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


@login_required(login_url='/account/login/')
def logout(request):
    auth.logout(request)
    return redirect('home')


@login_required(login_url='/account/login/')
def profile(request):
    user = request.user
    username = user.username
    email = user.email
    api = user.userprofile.api
    clients = user.userprofile.connected_clients.all()
    receiver_limit = AuthBackend.MAX_CLIENTS_LIMIT
    receiver_percentage = (clients.count() / receiver_limit) * 100

    context = {'username': username, 'email': email, 'api': api, 'clients': clients, 'receiver_usage': clients.count(),
               'receiver_limit': receiver_limit, 'receiver_percentage': receiver_percentage}
    return render(request, 'registration/profile.html', context)


@login_required(login_url='/account/login/')
def delete_client(request, client_id):
    user = request.user
    try:
        if user.userprofile.connected_clients.get(client_id=client_id) is not None:
            client = MyWebSocketConsumer.get_client_details(client_id)
            if client is None:
                remove_client_id_from_user_profile(request, client_id)
                return redirect('profile')
            else:
                return HttpResponse('Receiver is connected')
    except UserProfile.DoesNotExist:
        return HttpResponse('Client not found in database')


@login_required(login_url='/account/login/')
def remove_client_id_from_user_profile(request, client_id):
    try:
        client_instance = Client.objects.get(client_id=client_id)
        client_instance.delete()
    except UserProfile.DoesNotExist:
        pass
    except Client.DoesNotExist:
        pass


@login_required(login_url='/account/login/')
def regenerate_api(request):
    request.user.userprofile.regenerate_api_key()
    return HttpResponse('regenerated')
