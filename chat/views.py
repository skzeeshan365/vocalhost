import base64
import hashlib
import json
import threading
import time
from datetime import datetime, timezone

from cloudinary import uploader
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.serializers.json import DjangoJSONEncoder
from django.http import HttpResponse, JsonResponse, Http404
from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from fcm_django.models import FCMDevice
from jwcrypto import jwk

from ReiserX_Tunnel import settings
from chat.utils import format_key
from main.Utils import send_pusher_update
from chat.consumers import getRoom
from main.forms import ImageUploadForm
from chat.models import Message, Room, get_connected_users, new_signal_message, FriendRequest, SenderKeyBundle, \
    ReceiverKeyBundle


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

    received_friend_request = FriendRequest.objects.filter(receiver=user).count()

    return render(request, "chat/chat.html",
                  {'protocol': protocol,
                   'abcf': settings.FIREBASE_API_KEY,
                   'users': room_messages_info,
                   'storeMessage': user.userprofile.auto_save,
                   'pusher': settings.PUSHER_KEY,
                   'token_status': token,
                   'received_requests': received_friend_request})


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
        message_data = {
            'type': 'message_status_background',
            'timestamp': time,
            'sender_username': username,
        }
        send_pusher_update(message_data=message_data, receiver_username=receiver_user)


def extract_public_keys_from_bundle(key_bundle):
    ik_public_key = key_bundle.ik_public_key
    ek_public_key = key_bundle.ek_public_key
    spk_public_key = key_bundle.spk_public_key
    opk_public_key = key_bundle.opk_public_key
    dhratchet_public_key = key_bundle.dhratchet_public_key

    return ik_public_key, ek_public_key, spk_public_key, opk_public_key, dhratchet_public_key

def extract_public_keys_from_bundle_sender(key_bundle):
    ik_public_key = key_bundle.ik_public_key
    ek_public_key = key_bundle.ek_public_key

    return ik_public_key, ek_public_key


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
            bundle = room.get_bundle_key(username=receiver_user)
            keys = bundle.get_keys()

            messages_db = Message.objects.filter(room=room)
            messages = list(
                messages_db.values('message', 'sender__username', 'message_id', 'reply_id',
                                   'timestamp', 'temp__username', 'saved', 'image_url'))

            messages_db = Message.objects.filter(room=room, temp=user, saved=False).exists()
            Message.objects.filter(room=room, temp=user, saved=True).update(temp=None)

            if messages_db:
                thread = threading.Thread(target=update_message_status, args=(receiver_user, user.username))
                thread.start()
        else:
            messages = []
            keys = None
        messages = json.dumps(messages, cls=DjangoJSONEncoder)
        return JsonResponse({'status': 'success', 'data': messages, 'keys': format_key(keys)})
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


def add_chat(request):
    user = request.user
    users = User.objects.exclude(username=user.username)

    pending_received_requests = []
    users_with_no_requests = []

    for other_user in users:
        room = getRoom(user.username, other_user.username)
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
                return JsonResponse({'status': 'success', 'request_status': False})
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

            friend_request = FriendRequest(sender=request.user,
                                           receiver=friend_user,
                                           status=FriendRequest.PENDING)
            key_bundle = SenderKeyBundle(
                ik_public_key=ik_public_key_bytes,
                ek_public_key=ek_public_key_bytes,
                DHratchet= dhratchet_public_key_bytes,
                username=username,
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
                'dhratchet_private_key': dhratchet_jwk_key
            }

            return JsonResponse({'status': 'success', 'request_status': True, 'private_keys': private_keys})

    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)


@login_required
def accept_friend_request(request):
    if request.method == 'POST':
        username = request.POST.get('username')

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

        friend_request.status = FriendRequest.ACCEPTED

        key_bundle = ReceiverKeyBundle(
            IKb=ik_public_key_bytes,
            SPKb=spk_public_key_bytes,
            OPKb=opk_public_key_bytes,
            DHratchet=dhratchet_public_key_bytes,
            username=username,
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
            'dhratchet_private_key': ratchet_jwk_key
        }

        return JsonResponse({'status': 'success', 'message': 'Friend request accepted', 'private_keys': private_keys})

    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)


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
                                                         'pusher': settings.PUSHER_KEY})
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
