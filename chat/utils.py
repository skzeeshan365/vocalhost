import base64
import hashlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from django.utils import timezone
from jwcrypto import jwk

from chat.models import SenderKeyBundle, ReceiverKeyBundle, PublicKey, ChildMessage, UserDevice, SentMessage


def format_keys(keys):
    key = []
    for i in keys:
        key.append(base64.b64encode(i).decode('utf-8'))
    return key


def format_key(key):
    return base64.b64encode(key).decode('utf-8')


def generate_sender_keys(room, user, device_id):
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

    key_bundle = SenderKeyBundle(
        ik_public_key=ik_public_key_bytes,
        ek_public_key=ek_public_key_bytes,
        DHratchet=dhratchet_public_key_bytes,
        isNew=True,
    )
    public_key_obj = PublicKey.create_key(bundle=key_bundle, user=user, room=room, device_identifier=device_id)

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
        'type': 0,
        'version': public_key_obj.version
    }
    return private_keys


def generate_receiver_keys(room, user, device_id):
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

    key_bundle = ReceiverKeyBundle(
        IKb=ik_public_key_bytes,
        SPKb=spk_public_key_bytes,
        OPKb=opk_public_key_bytes,
        DHratchet=dhratchet_public_key_bytes,
        isNew=True,
    )
    public_key_object = PublicKey.create_key(bundle=key_bundle, user=user, room=room, device_identifier=device_id)

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
        'type': 1,
        'version': public_key_object.version
    }
    return private_keys


def generate_room_id(sender_username, receiver_username):
    combined_usernames_set = frozenset([sender_username, receiver_username])
    sorted_usernames = sorted(combined_usernames_set)
    return hashlib.sha256(str(sorted_usernames).encode()).hexdigest()


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

            child_message = {'cipher': child_message.cipher if child_message.cipher else None,
                             'bytes_cipher': PublicKey.format_key(child_message.bytes_cipher) if child_message.bytes_cipher else None,
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
            'sent_message': {'cipher': sent_message.cipher,
                             'cipher_bytes': PublicKey.format_key(sent_message.bytes_cipher) if sent_message.bytes_cipher else None,
                             'AES': sent_message.AES} if sent_message else None
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


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_key_jwk = jwk.JWK.from_pem(private_key_pem)
    private_key_jwk_key = private_key_jwk.export()

    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key_jwk_key, public_key_bytes


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
