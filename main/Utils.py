from django.db import IntegrityError
from sendgrid import SendGridAPIClient, Mail

from ReiserX_Tunnel import settings
from main.models import Message


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


def save_message(chat_message, message_id, room, sender, receiver, reply_id=None):
    try:
        if reply_id:
            reply_message = Message.objects.get(message_id=reply_id)
        else:
            reply_message = None
    except Message.DoesNotExist:
        reply_message = None
    if chat_message is not None and chat_message != '' and message_id is not None:
        try:
            Message.objects.create(
                message=chat_message,
                room=room,
                sender=sender,
                receiver=receiver,
                message_id=message_id,
                reply_id=reply_message
            )
        except IntegrityError:
            pass