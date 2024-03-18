import base64
import hashlib

from Cryptodome.PublicKey import RSA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwcrypto import jwk

from chat.models import SenderKeyBundle, ReceiverKeyBundle, PublicKey, Message, ChildMessage, UserDevice, SentMessage


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
    PublicKey.update_keys(bundle=key_bundle, user=user, room=room, device_identifier=device_id,
                          ratchet_key=dhratchet_public_key_bytes)

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
        'type': 0
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
    PublicKey.update_keys(bundle=key_bundle, user=user, room=room, device_identifier=device_id,
                          ratchet_key=dhratchet_public_key_bytes)

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
        'type': 1
    }
    return private_keys


def generate_room_id(sender_username, receiver_username):
    combined_usernames_set = frozenset([sender_username, receiver_username])
    sorted_usernames = sorted(combined_usernames_set)
    return hashlib.sha256(str(sorted_usernames).encode()).hexdigest()


def process_messages(messages, device_id):
    device_id = UserDevice.get_device_by_id(device_id)
    message_data = []
    for message in messages:
        child_message = ChildMessage.get_child_message(device_id=device_id, message=message)
        if child_message:
            child_message = {'cipher': child_message.cipher, 'public_key': PublicKey.format_key(child_message.public_key), 'device_id': str(child_message.sender_device_id.identifier)}
        sent_message = SentMessage.get_sent_message(device_id, message)
        message_data.append({
            'message': message.message,
            'sender__username': message.sender.username,
            'message_id': message.message_id,
            'reply_id': message.reply_id.message_id if message.reply_id else None,
            'timestamp': message.timestamp,
            'saved': message.saved,
            'image_url': message.image_url,
            'public_key': message.public_key,
            'child_message': child_message,
            'sent_message': {'cipher': sent_message.cipher, 'AES': sent_message.AES} if sent_message else None
        })
    return message_data


def clear_temp_messages(messages, device_id):
    device = UserDevice.get_device_by_id(device_id)
    for message in messages:
        child_message = ChildMessage.get_child_message(device_id=device.id, message=message)
        if child_message:
            child_message.delete()
            SentMessage.objects.filter(base_message=message).delete()
            if child_message.cipher:

                other_child_message = ChildMessage.get_base_child_message(message=message)
                if other_child_message:
                    other_child_message.cipher = None
                    other_child_message.save()

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


