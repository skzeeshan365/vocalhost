import base64
import hashlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto import jwk

from chat.models import SenderKeyBundle, ReceiverKeyBundle, PublicKey


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
