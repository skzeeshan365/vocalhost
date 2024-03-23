import json
import time

from cloudinary import uploader
from django.core.serializers.json import DjangoJSONEncoder
from fcm_django.models import FCMDevice
from firebase_admin.messaging import Message
from pusher.errors import PusherError
from sendgrid import SendGridAPIClient, Mail

from ReiserX_Tunnel import settings
from ReiserX_Tunnel.settings import pusher_client


def send_email(subject, message, to_email):
    subject = subject
    message = message
    from_email = 'ReiserX <{}>'.format(settings.DEFAULT_FROM_EMAIL)

    mail = Mail(from_email=from_email, subject=subject, to_emails=to_email, html_content=message)
    try:
        sg = SendGridAPIClient(api_key=settings.SENDGRID_API_KEY)
        sg.send(mail)
    except Exception as e:
        pass


def send_message_to_device(user, title, message, device_id):
    try:
        device = FCMDevice.objects.get(user=user, device_id=device_id)
        message = Message(
            data={
                "title": title,
                "message": message,
            },
            token=device.registration_id,
        )

        device.send_message(message=message)
    except Exception as e:
        print(e)


def send_pusher_update(message_data, receiver_username):
    from django.utils import timezone
    timestamp = timezone.now()
    message_data['timestamp'] = timestamp
    message_data = json.dumps(message_data, cls=DjangoJSONEncoder)
    try:
        pusher_client.trigger(f'{receiver_username}-channel', f'{receiver_username}-new-message',
                              message_data)
    except PusherError:
        pass


def cloudinary_image_upload(image_data):
    timestamp = int(time.time())
    public_id = f'chat/uploaded_image_{timestamp}'
    result = uploader.upload(
        image_data,
        public_id=public_id,
    )
    return result.get('secure_url')


def cloudinary_image_delete(image_url):
    public_id = image_url.split('/')[-1].split('.')[0]
    result = uploader.destroy(f'chat/{public_id}')
    if result.get('result') == 'ok':
        return True
    else:
        return False


def get_image_public_id(image_url):
    public_id = image_url.split('/')[-1].split('.')[0]
    if public_id:
        return f'chat/{public_id}'
    else:
        return None