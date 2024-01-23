from sendgrid import SendGridAPIClient, Mail

from ReiserX_Tunnel import settings


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