import hashlib

from django.db import IntegrityError
from sendgrid import SendGridAPIClient, Mail

from ReiserX_Tunnel import settings
from main.models import Message, Room


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


def getRoom(sender_username, receiver_username):
    combined_usernames_set = frozenset([sender_username, receiver_username])
    sorted_usernames = sorted(combined_usernames_set)

    room = hashlib.sha256(str(sorted_usernames).encode()).hexdigest()
    room = Room.objects.filter(room=room).first()
    return room


def get_sender_receiver(sender_username, receiver_username):
    combined_usernames_set = frozenset([sender_username, receiver_username])
    sorted_usernames = sorted(combined_usernames_set)
    return sorted_usernames[0], sorted_usernames[1]