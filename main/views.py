import asyncio
import hashlib
import json
import threading
import time
from datetime import datetime, timezone
from json import JSONDecodeError

from asgiref.sync import sync_to_async
from cloudinary import uploader
from cloudinary.api import delete_resources
from django.contrib import auth
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.serializers.json import DjangoJSONEncoder
from django.core.signals import request_finished
from django.dispatch import receiver
from django.http import HttpResponse, JsonResponse, Http404
from django.shortcuts import render, redirect, get_object_or_404, resolve_url
from django.template.loader import render_to_string
from fcm_django.models import FCMDevice

from ReiserX_Tunnel import settings
from main import forms
from main.Utils import send_pusher_update, get_image_public_id
from main.consumers import MyWebSocketConsumer, getRoom
# Create your views here.
from main.forms import RegistrationForm, LoginForm, ImageUploadForm
from main.models import UserProfile, Client, Message, Room, get_connected_users, new_signal_message


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
                client = MyWebSocketConsumer.get_client(client_id=client_id, user=user)
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
                # Redirect to the previous page or profile if 'next' is not present
                next_page = request.POST.get('next', 'profile')

                # Ensure 'next_page' is a relative URL
                next_page = resolve_url(next_page)
                return redirect(next_page)
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
    receiver_limit = user.userprofile.max_receiver
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
    new_api_key = request.user.userprofile.api
    response_data = {
        'api': new_api_key
    }
    return JsonResponse(response_data)


@login_required(login_url='/account/login/')
def increase_limit(request, username):
    if request.user.is_superuser:
        user = get_object_or_404(User, username=username)

        if request.method == 'POST':
            form = forms.EditForm(request.POST)
            if form.is_valid():
                new_limit = form.cleaned_data['limit']
                user.userprofile.max_receiver = new_limit
                user.userprofile.save()
                return HttpResponse('Limit updated')
        else:
            initial_data = {'limit': user.userprofile.max_receiver}  # Provide the initial data for the form

            form = forms.EditForm(initial=initial_data)

            return render(request, 'EditLimit.html', {'form': form, 'username': username})
    else:
        return HttpResponse('Permission denied')


@login_required(login_url='/account/login/')
def user_accounts(request):
    if request.user.is_superuser:
        users = User.objects.all()
        return render(request, 'user_accounts.html', {'users': users})
    else:
        return HttpResponse('Permission denied')


@login_required(login_url='/account/login/')
def chat_box(request):
    user = request.user
    users = User.objects.exclude(username=user.username)

    if settings.DEBUG is False:
        protocol = 'wss'
    else:
        protocol = 'ws'
    room_messages_info = []

    for other_user in users:
        room = getRoom(user.username, other_user.username)
        if room is None:
            continue

        # Get the count of messages
        messages_count = Message.objects.filter(
            room=room,
            temp=user,
        ).count()

        last_message = room.get_last_message()

        status = -1
        new_message = None
        if last_message:
            if last_message.temp == user:
                new_message = True
            else:
                new_message = False
            if last_message.temp == other_user:
                status = 2
            elif last_message.temp == user:
                status = 1
            elif last_message.temp is None:
                if last_message.sender == user:
                    status = 0
                elif last_message.sender == other_user:
                    status = 1

        room_messages_info.append({
            'user': other_user,
            'message_count': str(messages_count) if messages_count > 0 else '',
            'last_message': last_message.message if last_message else None,
            'last_message_timestamp': str(last_message.timestamp) if last_message else None,
            'new': new_message,
            'status': status
        })
    room_messages_info.sort(
        key=lambda x: datetime.strptime(x['last_message_timestamp'], '%Y-%m-%d %H:%M:%S.%f%z').replace(
            tzinfo=timezone.utc)
        if x['last_message_timestamp']
        else datetime.min.replace(tzinfo=timezone.utc),
        reverse=True
    )
    return render(request, "chat/chat.html",
                  {'protocol': protocol,
                   'abcf': settings.FIREBASE_API_KEY,
                   'users': room_messages_info,
                   'storeMessage': user.userprofile.auto_save,
                   'pusher': settings.PUSHER_KEY})


def delete_messages_data(messages_db, receiver_user, username):
    from django.utils import timezone
    public_ids_to_delete = []
    for message in messages_db:
        if message.image_url:
            public_id = get_image_public_id(message.image_url)
            if public_id:
                public_ids_to_delete.append(public_id)
    if public_ids_to_delete:
        try:
            delete_resources(public_ids_to_delete)
        except Exception:
            pass
    messages_db.delete()
    time = timezone.now()
    if get_connected_users().get(receiver_user):
        new_signal_message.send(sender=Message, message_type='message_status_background', timestamp=time,
                                sender_username=username)
    else:
        message_data = {
            'type': 'message_status_background',
            'timestamp': time,
            'sender_username': username,
        }
        send_pusher_update(message_data=message_data, receiver_username=receiver_user)


@login_required(login_url='/account/login/')
def load_messages(request, receiver):
    if request.method == 'POST':
        user = request.user
        receiver_user = receiver
        combined_usernames_set = frozenset([user.username, receiver_user])
        sorted_usernames = sorted(combined_usernames_set)

        room = hashlib.sha256(str(sorted_usernames).encode()).hexdigest()
        room = Room.objects.filter(room=room).first()
        if room:
            messages_db = Message.objects.filter(room=room)
            messages = list(
                messages_db.values('message', 'sender__username', 'message_id', 'reply_id',
                                   'timestamp', 'temp__username', 'saved', 'image_url'))

            messages_db = Message.objects.filter(room=room, temp=user, saved=False)
            Message.objects.filter(room=room, temp=user, saved=True).update(temp=None)

            if messages_db.exists():
                thread = threading.Thread(target=delete_messages_data, args=(messages_db, receiver_user, user.username))
                thread.start()
        else:
            messages = []
        messages = json.dumps(messages, cls=DjangoJSONEncoder)
        return JsonResponse({'status': 'success', 'data': messages})
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request'})


@login_required(login_url='/account/login/')
def delete_messages(request, receiver):
    user = request.user
    receiver_user = receiver
    combined_usernames_set = frozenset([user.username, receiver_user])
    sorted_usernames = sorted(combined_usernames_set)

    room = hashlib.sha256(str(sorted_usernames).encode()).hexdigest()
    room = Room.objects.filter(room=room).first()

    if room:
        room.delete_all_messages()
    return redirect('chat', chat_box_name=receiver)


def register_device(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        user = request.user
        registration_token = data.get('token')
        device_type = data.get('device_type', 'web')  # Default to 'web' if not provided

        # Check if the device is already registered for the user

        objects = FCMDevice.objects.filter(user=user)
        objects.delete()
        FCMDevice.objects.create(
            user=user,
            registration_id=registration_token,
            type=device_type,
        )

        return JsonResponse({'status': 'success'})

    return JsonResponse({'status': 'error', 'error_message': 'Invalid request method'})


def showFirebaseJS(request):
    rendered_template = render_to_string('chat/firebase-messaging-sw.js', {'api_key': settings.FIREBASE_API_KEY})
    data = rendered_template
    return HttpResponse(data, content_type="text/javascript")


def get_or_create_room(sender_username, receiver_username):
    # Ensure that the users are sorted before creating the room identifier
    combined_usernames_set = frozenset([sender_username, receiver_username])
    sorted_usernames = sorted(combined_usernames_set)

    room_identifier = hashlib.sha256(str(sorted_usernames).encode()).hexdigest()

    room, created = Room.objects.get_or_create(
        room=room_identifier,
        sender_username=sorted_usernames[0],
        receiver_username=sorted_usernames[1]
    )

    return room


def add_chat(request):
    if request.method == 'POST':
        user = request.user
        data = json.loads(request.body)
        username = data.get('username')

        room = get_or_create_room(user.username, username)
        if room:
            print(room)
            return JsonResponse({'success': True})
        else:
            return JsonResponse({'error': True})
    else:
        user = request.user
        users = User.objects.exclude(username=user.username)

        room_messages_info = []

        for other_user in users:
            room = getRoom(user.username, other_user.username)
            if room is not None:
                continue

            room_messages_info.append({
                'user': other_user,
            })

        return render(request, "chat/contacts.html", {'users': room_messages_info})


def clear_chat(request):
    if request.method == 'POST':
        user = request.user
        data = json.loads(request.body)
        username = data.get('username')
        if user is not None and username is not None:
            try:
                room = getRoom(user.username, username)
                if room:
                    room.delete_all_messages()
                    return JsonResponse({'success': True})
                else:
                    return JsonResponse({'error': 'Failed to clear chat'})
            except Room.DoesNotExist:
                return JsonResponse({'error': 'Failed to clear chat'})
        return JsonResponse({'error': 'Failed to clear chat'})
    else:
        return JsonResponse({'error': 'Invalid request'})


def remove_chat(request):
    if request.method == 'POST':
        user = request.user
        data = json.loads(request.body)
        username = data.get('username')
        if user is not None and username is not None:
            try:
                room = getRoom(user.username, username)
                if room:
                    room.delete()
                    return JsonResponse({'success': True})
                else:
                    return JsonResponse({'error': 'Failed to remove chat'})
            except Room.DoesNotExist:
                return JsonResponse({'error': 'Failed to remove chat'})
        return JsonResponse({'error': 'Failed to remove chat'})
    else:
        return JsonResponse({'error': 'Invalid request'})


def chat_profile(request, username):
    try:
        if request.user.username == username:
            user = request.user
            count = Message.objects.filter(sender=user).count()
            messages = Message.objects.filter(sender=user).order_by('-timestamp')[:4]
            form = ImageUploadForm()
            if user.userprofile.image:
                image = user.userprofile.image.url
            else:
                image = None
            return render(request, 'chat/profile.html', {'username': user.username,
                                                         'fullname': user.get_full_name(),
                                                         'profile_pic': image,
                                                         'messages': messages,
                                                         'message_count': count,
                                                         'form': form,
                                                         'user': user.pk,
                                                         'auto_save': user.userprofile.auto_save})
        else:
            user = User.objects.get(username=username)
            if user:
                room = getRoom(request.user.username, username)
                count = Message.objects.filter(room=room).count()
                messages = Message.objects.filter(room=room).order_by('-timestamp')[:4]
                form = ImageUploadForm()
                if user.userprofile.image:
                    image = user.userprofile.image.url
                else:
                    image = None
                return render(request, 'chat/profile.html', {'username': user.username,
                                                             'fullname': user.get_full_name(),
                                                             'profile_pic': image,
                                                             'messages': messages,
                                                             'message_count': count,
                                                             'form': form,
                                                             'user': user.pk})
            else:
                raise Http404("User not found")
    except User.DoesNotExist or Message.DoesNotExist or Room.DoesNotExist:
        raise Http404("User not found")


def update_profile(request):
    if request.method == 'POST':
        user = request.user
        form = ImageUploadForm(data=request.POST, files=request.FILES, instance=user.userprofile)

        if form.is_valid():
            output = form.save()
            return JsonResponse({'success': True, 'image_url': output.image.url})
        else:
            return JsonResponse({'error': form.errors})

    else:
        return JsonResponse({'error': 'Invalid request'})


def update_profile_info(request):
    if request.method == 'POST':
        user = request.user
        data = json.loads(request.body)
        fullname = data.get('fullname')
        auto_save = data.get('storeMessage')

        if auto_save is not None:
            user.userprofile.auto_save = auto_save
            user.userprofile.save()
            return JsonResponse({'success': True})
        if fullname:
            if len(fullname) == 2:
                first_name, last_name = fullname.split(maxsplit=1)
                user.first_name = first_name
                user.last_name = last_name
                user.save()
            else:
                user.first_name = fullname
                user.last_name = ''
                user.save()
            return JsonResponse({'success': True})

        return JsonResponse({'error': 'Invalid data format'})

    else:
        return JsonResponse({'error': 'Invalid request'})


def upload_image(request):
    if request.method == 'POST':
        image_data = request.FILES.get('image_data')

        message_id = request.POST.get('message_id')

        message = Message.objects.filter(message_id=message_id).exists()
        if message:
            timestamp = int(time.time())
            public_id = f'chat/uploaded_image_{timestamp}'
            result = uploader.upload(
                image_data,
                public_id=public_id,
            )
            # The Cloudinary URL of the uploaded image
            cloudinary_url = result['secure_url']
            return JsonResponse({'success': True, 'image_url': cloudinary_url})
        else:
            return JsonResponse({'success': True, 'image_url': None})
    return JsonResponse({'success': False, 'error': 'Invalid request'})
