import base64
import pickle

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto import jwk

from chat.models import SenderKeyBundle, ReceiverKeyBundle, Room


def format_keys(keys):
    key = []
    for i in keys:
        key.append(base64.b64encode(i).decode('utf-8'))
    return key


def format_key(key):
    return base64.b64encode(key).decode('utf-8')


def generate_sender_keys(room, username):
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

    # Convert bytes to base64-encoded strings
    ik_public_key_base64 = base64.b64encode(ik_public_key_bytes).decode('utf-8')
    ek_public_key_base64 = base64.b64encode(ek_public_key_bytes).decode('utf-8')
    dhratchet_public_key_base64 = base64.b64encode(dhratchet_public_key_bytes).decode('utf-8')

    key_bundle = SenderKeyBundle(
        ik_public_key=ik_public_key_base64,
        ek_public_key=ek_public_key_base64,
        DHratchet=dhratchet_public_key_base64,
        isNew=True,
        username=username,
    )
    if room.sender_username == username:
        room.set_sender_key_bundle(key_bundle)
        room.sender_ratchet = dhratchet_public_key_bytes
        room.save()
    else:
        room.set_receiver_key_bundle(key_bundle)
        room.receiver_ratchet = dhratchet_public_key_bytes
        room.save()
        print('2')

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


def generate_receiver_keys(room, username):
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

    ik_public_key_base64 = base64.b64encode(ik_public_key_bytes).decode('utf-8')
    spk_public_key_base64 = base64.b64encode(spk_public_key_bytes).decode('utf-8')
    opk_public_key_base64 = base64.b64encode(opk_public_key_bytes).decode('utf-8')
    dhratchet_public_key_base64 = base64.b64encode(dhratchet_public_key_bytes).decode('utf-8')

    key_bundle = ReceiverKeyBundle(
        IKb=ik_public_key_base64,
        SPKb=spk_public_key_base64,
        OPKb=opk_public_key_base64,
        DHratchet=dhratchet_public_key_base64,
        isNew=True,
        username=username,
    )
    if room.sender_username == username:
        room.set_sender_key_bundle(key_bundle)
        room.sender_ratchet = dhratchet_public_key_bytes
        room.save()
        print('3')
    else:
        room.set_receiver_key_bundle(key_bundle)
        room.receiver_ratchet = dhratchet_public_key_bytes
        room.save()
        print('4')

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