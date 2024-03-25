from django.utils import timezone

from chat.models import PublicKey, ChildMessage, UserDevice, SentMessage


def process_messages(messages, user, room, device_id):
    device_id = UserDevice.get_device_by_id(device_id)
    message_data = []
    for message in messages:
        child_message = ChildMessage.get_child_message(device_id=device_id, message=message)

        if child_message:
            base_public_key = PublicKey.get_public_key_by_version(message.sender, message.room,
                                                                  child_message.sender_device_id,
                                                                  child_message.key_version)
            if base_public_key:
                base_public_key = PublicKey.format_keys(base_public_key.get_bundle_key().get_keys())

            child_message = {'cipher': PublicKey.format_key(child_message.cipher) if child_message.cipher else None,
                             'bytes_cipher': PublicKey.format_key(
                                 child_message.bytes_cipher) if child_message.bytes_cipher else None,
                             'public_key': PublicKey.format_key(child_message.public_key),
                             'base_public_key': base_public_key if base_public_key else None,
                             'device_id': str(child_message.sender_device_id.identifier)}
        sent_message = SentMessage.get_sent_message(device_id, message)
        message_data.append({
            'message': message.message,
            'sender__username': message.sender.username,
            'message_id': message.message_id,
            'reply_id': message.reply_id.message_id if message.reply_id else None,
            'timestamp': message.timestamp,
            'saved': message.saved,
            'image_url': message.image_url,
            'child_message': child_message,
            'sent_message': {'cipher': PublicKey.format_key(sent_message.cipher),
                             'cipher_bytes': PublicKey.format_key(
                                 sent_message.bytes_cipher) if sent_message.bytes_cipher else None,
                             'AES': PublicKey.format_key(sent_message.AES)} if sent_message else None
        })
    return message_data


def clear_temp_messages(messages, device_id):
    device = UserDevice.get_device_by_id(device_id)
    for message in messages:
        child_message = ChildMessage.get_child_message(device_id=device.id, message=message)
        if child_message:
            child_message.delete()
            SentMessage.objects.filter(base_message=message).delete()
            if child_message.cipher or child_message.bytes_cipher:
                ChildMessage.nullify_all(message.message_id)

        if not ChildMessage.get_child_messages(message=message):
            if not message.saved:
                message.delete()


def get_browser_name(request):
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    if 'Chrome' in user_agent:
        return 'Chrome'
    elif 'Firefox' in user_agent:
        return 'Firefox'
    elif 'Safari' in user_agent:
        return 'Safari'
    elif 'Edge' in user_agent:
        return 'Edge'
    elif 'Opera' in user_agent:
        return 'Opera'
    else:
        return 'Unknown'


def get_ip(request):
    user_ip = request.META.get('HTTP_X_FORWARDED_FOR')
    if user_ip:
        user_ip = user_ip.split(',')[0].strip()
    else:
        user_ip = request.META.get('REMOTE_ADDR')

    if user_ip:
        return user_ip
    return None


def get_current_time():
    return timezone.now()
