import json

from django.core.serializers.json import DjangoJSONEncoder
from fcm_django.models import FCMDevice
from firebase_admin.messaging import Message
from pusher.errors import PusherError
from sendgrid import SendGridAPIClient, Mail
from django.utils import timezone

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


def get_sender_receiver(sender_username, receiver_username):
    combined_usernames_set = frozenset([sender_username, receiver_username])
    sorted_usernames = sorted(combined_usernames_set)
    return sorted_usernames[0], sorted_usernames[1]


def send_message_to_device(user, title, message, timestamp=None):
    try:
        device = FCMDevice.objects.get(user=user)
        message = Message(
            data={
                "title": title,
                "message": message,
                "timestamp": "null"
            },
        )

        device.send_message(message=message)
    except Exception as e:
        if "DoesNotExist" in str(e):
            # Handle the case when the FCMDevice for the user does not exist
            pass
        else:
            pass


def send_pusher_update(message_data, receiver_username):
    message_data = json.dumps(message_data, cls=DjangoJSONEncoder)
    try:
        # Your Pusher API calls here
        pusher_client.trigger(f'{receiver_username}-channel', f'{receiver_username}-new-message',
                              message_data)
    except PusherError:
        pass