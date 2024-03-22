import hashlib
import json
import threading
import time
import uuid
from datetime import datetime, timezone, timedelta

from cloudinary import uploader
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.serializers.json import DjangoJSONEncoder
from django.db.models import OuterRef, Subquery
from django.http import HttpResponse, JsonResponse, Http404
from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from django.utils.safestring import mark_safe
from fcm_django.models import FCMDevice
from jwcrypto import jwk

from ReiserX_Tunnel import settings
from chat.models import Message, Room, get_connected_users, new_signal_message, FriendRequest, SenderKeyBundle, \
    ReceiverKeyBundle, PublicKey, UserDevice, ChildMessage
from chat.utils import format_key, generate_sender_keys, generate_receiver_keys, generate_room_id, \
    process_messages, clear_temp_messages, generate_key_pair, get_browser_name, get_ip, get_current_time
from main.Utils import send_pusher_update
from main.forms import ImageUploadForm


@login_required(login_url='/account/login/')
def chat_box(request):
    user = request.user
    users = User.objects.exclude(username=user.username)

    token = FCMDevice.objects.filter(user=user).exists()

    if settings.DEBUG is False:
        protocol = 'wss'
    else:
        protocol = 'ws'
    room_messages_info = []

    for other_user in users:
        room = Room.getRoom(user.username, other_user.username)
        if room is None:
            continue

        messages_with_child_messages = ChildMessage.objects.filter(
            base_message_id=OuterRef('message_id'),  # Link to the primary key of the outer Message
            cipher__isnull=False
        ).values('base_message_id')

        # Get all Message instances where at least one related ChildMessage has a non-None cipher
        messages_with_cipher = Message.objects.filter(
            room=room,
            receiver=user,
            saved=False,
            message_id__in=Subquery(messages_with_child_messages)
        )

        messages_with_cipher_other = Message.objects.filter(
            room=room,
            receiver=other_user,
            saved=False,
            message_id__in=Subquery(messages_with_child_messages)
        )

        # Then you can count the number of such messages
        messages_count = messages_with_cipher.count()

        last_message = room.get_last_message()

        status = -1
        new_message = None
        if last_message:
            if last_message.receiver == user and messages_with_cipher:
                new_message = True
            else:
                new_message = False

            if last_message.receiver == other_user and messages_with_cipher_other.exists():
                status = 2
            elif messages_with_cipher is None and messages_with_cipher_other is None:
                status = -1
        room_messages_info.append({
            'user': other_user,
            'room': room.room,
            'message_count': str(messages_count) if messages_count > 0 else '',
            'last_message': last_message.message_id if last_message else None,
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

    for item in room_messages_info:
        if item['last_message_timestamp']:
            utc_time = datetime.strptime(item['last_message_timestamp'], '%Y-%m-%d %H:%M:%S.%f%z')
            kolkata_offset = timedelta(hours=5, minutes=30)  # Kolkata time zone offset
            kolkata_time = utc_time + kolkata_offset
            item['last_message_timestamp'] = kolkata_time.strftime('%I:%M %p')

    received_friend_request = FriendRequest.objects.filter(receiver=user).count()

    device_id_cookie = request.COOKIES.get('device_id')

    device_keys = UserDevice.get_user_device_public_keys(request.user)

    user_device = None
    if device_id_cookie:
        user_device = UserDevice.get_user_by_device(device_id_cookie)

    if user_device and user_device.username == user.username:
        device = UserDevice.get_device_by_id(device_id_cookie)

        if device.device_public_key is None:
            private_key, public_key = generate_key_pair()
            device.device_public_key = public_key
        else:
            private_key = None
        device.ip_address = get_ip(request)
        device.save()

        context = {'protocol': protocol,
                   'abcf': settings.FIREBASE_API_KEY,
                   'users': room_messages_info,
                   'storeMessage': user.userprofile.auto_save,
                   'pusher': settings.PUSHER_KEY,
                   'token_status': token,
                   'received_requests': received_friend_request,
                   'device_keys': mark_safe(device_keys)}
        if private_key:
            context['private_key'] = mark_safe(private_key)
        response = render(request, "chat/chat.html",
                          context)
    else:
        device = UserDevice.create_user_device(user, request)
        if device:
            private_key, public_key = generate_key_pair()
            device.device_public_key = public_key
            device.save()
            context = {'protocol': protocol,
                       'abcf': settings.FIREBASE_API_KEY,
                       'users': room_messages_info,
                       'storeMessage': user.userprofile.auto_save,
                       'pusher': settings.PUSHER_KEY,
                       'token_status': token,
                       'received_requests': received_friend_request,
                       'device_keys': mark_safe(device_keys),
                       'private_key': mark_safe(private_key)}
            response = render(request, "chat/chat.html",
                              context)
            response.set_cookie('device_id', str(device.identifier), max_age=365 * 24 * 60 * 60)
            return response
        else:
            return redirect('chat_profile', user.username)

    return response


def generate_secondary_key_pair(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        device_id = data.get('device_id')
        device = UserDevice.get_device_by_id(device_id)

        if device and UserDevice.get_user_by_device(device_id).username == request.user.username:
            private_key, public_key = generate_key_pair()
            device.device_public_key = public_key
            device.save()
            return JsonResponse({'status': 'success', 'private_key': mark_safe(private_key),
                                 'public_key': PublicKey.format_key(public_key)})
        else:
            return JsonResponse({'status': 'error', 'message': 'Unauthorized'})
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request'})


def update_message_status(receiver_user, username):
    from django.utils import timezone
    timestamp = timezone.now()
    if get_connected_users().get(receiver_user):
        message = {
            'type': 'message_status_background',
            'timestamp': timestamp,
            'sender_username': username
        }
        new_signal_message.send(sender=username, receiver_username=receiver_user, message=message)
    else:
        message = {
            'type': 'message_status_background',
            'sender_username': username,
        }
        send_pusher_update(message_data=message, receiver_username=receiver_user)


@login_required(login_url='/account/login/')
def load_messages(request, receiver):
    if request.method == 'POST':
        user = request.user
        receiver_user = receiver

        data = json.loads(request.body)
        generate_keys = data.get('generate_keys')
        device_id = data.get('device_id')

        combined_usernames_set = frozenset([user.username, receiver_user])
        sorted_usernames = sorted(combined_usernames_set)

        room = hashlib.sha256(str(sorted_usernames).encode()).hexdigest()
        room = Room.objects.filter(room=room).first()
        if room:
            receiver = User.objects.get(username=receiver_user)
            public_keys = room.get_public_keys(receiver, device_id)
            public_key = PublicKey.get_latest_public_key(user=user, room=room,
                                                         device_id=UserDevice.get_device_by_id(device_id))
            if generate_keys or not public_key:
                generate_keys = True
                if public_key:
                    if public_key.key_type == PublicKey.SENDER:
                        private_keys = generate_sender_keys(room, user, device_id)
                    else:
                        private_keys = generate_receiver_keys(room, user, device_id)
                else:
                    if room.get_user_type(user.username) == 'Sender':
                        private_keys = generate_sender_keys(room, user, device_id)
                    else:
                        private_keys = generate_receiver_keys(room, user, device_id)
            else:
                private_keys = None

            messages_db = Message.objects.filter(room=room)
            messages = process_messages(messages_db, user, room, device_id)

            messages_db = Message.objects.filter(room=room, receiver=user, saved=False)

            for message in messages:
                if 'public_key' in message and isinstance(message['public_key'], bytes):
                    message['public_key'] = format_key(message['public_key'])

            if messages_db.exists():
                thread = threading.Thread(target=update_message_status, args=(receiver_user, user.username))
                thread.start()

        else:
            messages = []
            public_keys = None
            private_keys = None
        messages = json.dumps(messages, cls=DjangoJSONEncoder)
        return JsonResponse(
            {'status': 'success', 'data': messages, 'generate_keys': generate_keys, 'keys': {'public_keys': public_keys,
                                                                                             'private_keys': private_keys}})
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request'})


@login_required(login_url='/account/login/')
def process_temp_messages(request):
    if request.method == 'POST':
        user = request.user
        data = json.loads(request.body)
        device_id = data.get('device_id')
        receiver_username = data.get('receiver_username')

        room = generate_room_id(user.username, receiver_username)
        room = Room.objects.filter(room=room).first()
        if room:
            messages_db = Message.objects.filter(room=room)

            clear_temp_messages(messages_db, device_id)
            return JsonResponse({'status': 'success'})
        else:
            return JsonResponse({'status': 'error'})
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request'})


@login_required(login_url='/account/login/')
def get_user_public_keys(request):
    if request.method == 'POST':
        user = request.user
        data = json.loads(request.body)
        device_id = data.get('device_id')
        receiver_username = data.get('receiver_username')

        room = generate_room_id(user.username, receiver_username)
        room = Room.objects.filter(room=room).first()
        if room:
            receiver = User.objects.get(username=receiver_username)
            public_keys = room.get_public_keys(receiver, device_id)

            return JsonResponse({'status': 'success', 'public_keys': public_keys})
        else:
            return JsonResponse({'status': 'error'})
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request'})


@login_required(login_url='/account/login/')
def get_device_public_keys(request):
    if request.method == 'POST':
        user = request.user
        data = json.loads(request.body)
        device_id = data.get('self_device_id')
        receiver_device_id = data.get('receiver_device_id')
        receiver_username = data.get('receiver_username')

        room = generate_room_id(user.username, receiver_username)
        room = Room.objects.filter(room=room).first()
        if room:
            receiver = User.objects.get(username=receiver_username)
            public_keys = room.get_public_key(receiver, receiver_device_id, device_id)

            return JsonResponse({'status': 'success', 'public_keys': public_keys})
        else:
            return JsonResponse({'status': 'error'})
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
        device_type = data.get('device_type', 'web')
        device_id = data.get('device_id')

        # Check if the device is already registered for the user

        objects = FCMDevice.objects.filter(user=user, device_id=device_id)
        objects.delete()
        FCMDevice.objects.create(
            user=user,
            registration_id=registration_token,
            type=device_type,
            device_id=device_id
        )

        return JsonResponse({'status': 'success'})

    return JsonResponse({'status': 'error', 'error_message': 'Invalid request method'})


def showFirebaseJS(request):
    rendered_template = render_to_string('chat/firebase-messaging-sw.js', {'api_key': settings.FIREBASE_API_KEY})
    data = rendered_template
    return HttpResponse(data, content_type="text/javascript")


def add_chat(request):
    user = request.user
    users = User.objects.exclude(username=user.username)

    pending_received_requests = []
    users_with_no_requests = []

    for other_user in users:
        room = Room.getRoom(user.username, other_user.username)
        if room:
            continue

        received_friend_request = FriendRequest.objects.filter(sender=other_user, receiver=user).first()
        sent_friend_request = FriendRequest.objects.filter(sender=user, receiver=other_user).first()

        if received_friend_request and received_friend_request.status == FriendRequest.PENDING:
            pending_received_requests.append(other_user)

        elif sent_friend_request:
            if sent_friend_request.status == FriendRequest.PENDING:
                users_with_no_requests.append({'user': other_user, 'status': True})
            else:
                users_with_no_requests.append({'user': other_user, 'status': False})

        else:
            users_with_no_requests.append({'user': other_user, 'status': False})

    return render(request, "chat/contacts.html",
                  {
                      'requests': pending_received_requests,
                      'users': users_with_no_requests,
                      'pusher': settings.PUSHER_KEY,
                  })


@login_required
def send_friend_request(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        send_request = request.POST.get('send_request')
        device_id = request.POST.get('device_id')
        send_request = json.loads(send_request)
        try:
            friend_user = User.objects.get(username=username)
        except User.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'User not found'}, status=404)

        if send_request:
            # Check if a friend request already exists
            existing_request = FriendRequest.objects.filter(sender=request.user, receiver=friend_user)
            if existing_request.exists():
                existing_request.delete()
                return JsonResponse({'status': 'success', 'request_status': False,
                                     'room': generate_room_id(request.user.username, username)})
            else:
                return JsonResponse({'status': 'error', 'message': 'Request does not exist'})
        else:
            # Check if a friend request already exists
            existing_request = FriendRequest.objects.filter(sender=request.user, receiver=friend_user)
            if existing_request.exists():
                return JsonResponse({'status': 'error', 'message': 'Friend request already sent'}, status=400)

            ik_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            ek_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            dhratchet_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

            # Get the corresponding public keys as bytes
            ik_public_key_bytes = ik_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            ek_public_key_bytes = ek_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            dhratchet_public_key_bytes = dhratchet_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            try:
                device_id = UserDevice.objects.get(identifier=device_id)
            except UserDevice.DoesNotExist:
                pass

            friend_request = FriendRequest(sender=request.user,
                                           receiver=friend_user,
                                           status=FriendRequest.PENDING,
                                           sender_device_id=device_id)

            key_bundle = SenderKeyBundle(
                ik_public_key=ik_public_key_bytes,
                ek_public_key=ek_public_key_bytes,
                DHratchet=dhratchet_public_key_bytes,
                isNew=True,
            )
            friend_request.set_key_bundle(key_bundle=key_bundle)
            friend_request.save()

            # Serialize keys to PEM format
            ik_private_key_pem = ik_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            ek_private_key_pem = ek_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            dhratchet_private_key_pem = dhratchet_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            ik_key = jwk.JWK.from_pem(ik_private_key_pem)
            ik_jwk_key = ik_key.export()

            ek_key = jwk.JWK.from_pem(ek_private_key_pem)
            ek_jwk_key = ek_key.export()

            dhratchet_key = jwk.JWK.from_pem(dhratchet_private_key_pem)
            dhratchet_jwk_key = dhratchet_key.export()

            private_keys = {
                'ik_private_key': ik_jwk_key,
                'ek_private_key': ek_jwk_key,
                'dhratchet_private_key': dhratchet_jwk_key,
                'version': 1
            }

            return JsonResponse({'status': 'success', 'request_status': True, 'private_keys': private_keys,
                                 'room': generate_room_id(request.user.username, username)})

    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)


@login_required
def accept_friend_request(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        device_id = request.POST.get('device_id')

        # Check if the user with the specified username exists
        try:
            friend_user = User.objects.get(username=username)
        except User.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'User not found'}, status=404)

        # Check if a friend request exists
        friend_request = FriendRequest.objects.filter(sender=friend_user, receiver=request.user,
                                                      status=FriendRequest.PENDING).first()
        if not friend_request:
            return JsonResponse({'status': 'error', 'message': 'Friend request not found or already accepted'},
                                status=404)

        ik_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        spk_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        opk_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        dhratchet_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        # Get the corresponding public keys as bytes
        ik_public_key_bytes = ik_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        spk_public_key_bytes = spk_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        opk_public_key_bytes = opk_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        dhratchet_public_key_bytes = dhratchet_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        try:
            device_id = UserDevice.objects.get(identifier=device_id)
            friend_request.receiver_device_id = device_id
        except UserDevice.DoesNotExist:
            pass

        friend_request.status = FriendRequest.ACCEPTED

        key_bundle = ReceiverKeyBundle(
            IKb=ik_public_key_bytes,
            SPKb=spk_public_key_bytes,
            OPKb=opk_public_key_bytes,
            DHratchet=dhratchet_public_key_bytes,
            isNew=True,
        )
        friend_request.set_receiver_key_bundle(key_bundle=key_bundle)
        friend_request.save()

        # Serialize keys to PEM format
        ik_private_key_pem = ik_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        spk_private_key_pem = spk_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        opk_private_key_pem = opk_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        dhratchet_private_key_pem = dhratchet_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        ik_key = jwk.JWK.from_pem(ik_private_key_pem)
        ik_jwk_key = ik_key.export()

        spk_key = jwk.JWK.from_pem(spk_private_key_pem)
        spk_jwk_key = spk_key.export()

        opk_key = jwk.JWK.from_pem(opk_private_key_pem)
        opk_jwk_key = opk_key.export()

        ratchet_key = jwk.JWK.from_pem(dhratchet_private_key_pem)
        ratchet_jwk_key = ratchet_key.export()

        private_keys = {
            'ik_private_key': ik_jwk_key,
            'spk_private_key': spk_jwk_key,
            'opk_private_key': opk_jwk_key,
            'dhratchet_private_key': ratchet_jwk_key,
            'version': 1
        }

        return JsonResponse({'status': 'success', 'message': 'Friend request accepted', 'private_keys': private_keys,
                             'room': generate_room_id(request.user.username, username)})

    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)


@login_required
def generate_ratchet_keys(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        device_id = data.get('device_id')
        receiver_username = data.get('receiver_username')

        room = Room.getRoom(request.user.username, receiver_username)
        user = request.user
        if room:
            if room.get_user_type(user.username) == 'Sender':
                private_keys = generate_sender_keys(room, user, device_id)
            else:
                private_keys = generate_receiver_keys(room, user, device_id)
            return JsonResponse({'status': 'success', 'room': room.room, 'private_keys': private_keys})
        return JsonResponse({'status': 'error', 'message': 'Room not found'})
    else:
        return JsonResponse({'error': 'Invalid request'})


def clear_chat(request):
    if request.method == 'POST':
        user = request.user
        data = json.loads(request.body)
        username = data.get('username')
        if user is not None and username is not None:
            try:
                room = Room.getRoom(user.username, username)
                if room:
                    room.clear_chat()
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
                room = Room.getRoom(user.username, username)
                if room:
                    room.delete()
                    message_data = {
                        'type': 'remove_friend',
                        'username': user.username,
                    }
                    if get_connected_users().get(username):
                        new_signal_message.send(sender=user.username, receiver_username=username,
                                                message=message_data)
                    else:
                        send_pusher_update(message_data=message_data, receiver_username=username)
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
                                                         'auto_save': user.userprofile.auto_save,
                                                         'pusher': settings.PUSHER_KEY,
                                                         'user_devices': user.user_device.all()})
        else:
            user = User.objects.get(username=username)
            if user:
                room = Room.getRoom(request.user.username, username)
                count = Message.objects.filter(room=room, saved=True).count()
                messages = Message.objects.filter(room=room, saved=True).order_by('-timestamp')[:4]
                form = ImageUploadForm()
                if user.userprofile.image:
                    image = user.userprofile.image.url
                else:
                    image = None

                outgoing_request_exists = FriendRequest.objects.filter(sender=request.user, receiver=user).exists()
                incoming_request_exists = FriendRequest.objects.filter(sender=user, receiver=request.user).exists()

                if room:
                    status = -1
                elif outgoing_request_exists:
                    status = 1
                elif incoming_request_exists:
                    status = 2
                else:
                    status = 0

                return render(request, 'chat/profile.html', {'username': user.username,
                                                             'fullname': user.get_full_name(),
                                                             'profile_pic': image,
                                                             'messages': messages,
                                                             'message_count': count,
                                                             'form': form,
                                                             'user': user.pk,
                                                             'status': status,
                                                             'pusher': settings.PUSHER_KEY})
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


@login_required
def logout_device(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        device_id = data.get('device_id')
        device = UserDevice.get_device_by_id(device_id)

        if request.user.is_authenticated and device.user is not None:
            if device.user == request.user:
                device.delete()
                if request.COOKIES.get('device_id') == device_id:
                    logout(request)
                return JsonResponse({'status': 'success', 'message': 'Logout successful'})
        return JsonResponse({'status': 'error', 'message': 'Unauthorized'})
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request'})


def upload_image(request):
    if request.method == 'POST':
        image_data = request.FILES.get('image_data')

        message_id = request.POST.get('message_id')

        try:
            message = Message.objects.get(message_id=message_id)
            if message.image_url is None:
                timestamp = int(time.time())
                public_id = f'chat/uploaded_image_{timestamp}'
                result = uploader.upload(
                    image_data,
                    public_id=public_id,
                )
                cloudinary_url = result['secure_url']

                return JsonResponse({'success': True, 'image_url': cloudinary_url})
            else:
                return JsonResponse({'success': True, 'image_url': None})
        except Message.DoesNotExist:
            timestamp = int(time.time())
            public_id = f'chat/uploaded_image_{timestamp}'
            result = uploader.upload(
                image_data,
                public_id=public_id,
            )
            cloudinary_url = result['secure_url']

            return JsonResponse({'success': True, 'image_url': cloudinary_url})
    return JsonResponse({'success': False, 'error': 'Invalid request'})


def generate_message_id(request):
    if request.method == 'POST':
        message_id = int(time.time() * 1000)
        return JsonResponse({'status': 'success', 'message_id': message_id})
    return JsonResponse({'success': False, 'error': 'Invalid request'})
