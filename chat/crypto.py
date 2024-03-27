import base64
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from chat.models import SenderKeyBundle, ReceiverKeyBundle, PublicKey, UserSecure, UserDevice


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

    ik_private_key = ik_private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    ek_private_key = ek_private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    dhratchet_private_key = dhratchet_private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    device = UserDevice.get_device_by_id(device_id)
    ik_private_key = encrypt_with_rsa(ik_private_key, device.device_public_key)
    ek_private_key = encrypt_with_rsa(ek_private_key, device.device_public_key)
    dhratchet_private_key = encrypt_with_rsa(dhratchet_private_key, device.device_public_key)

    private_keys = {
        'ik_private_key': format_key(ik_private_key),
        'ek_private_key': format_key(ek_private_key),
        'dhratchet_private_key': format_key(dhratchet_private_key),
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
    ik_private_key = ik_private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    spk_private_key = spk_private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    opk_private_key = opk_private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    dhratchet_private_key = dhratchet_private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    device = UserDevice.get_device_by_id(device_id)
    ik_private_key = encrypt_with_rsa(ik_private_key, device.device_public_key)
    spk_private_key = encrypt_with_rsa(spk_private_key, device.device_public_key)
    opk_private_key = encrypt_with_rsa(opk_private_key, device.device_public_key)
    dhratchet_private_key = encrypt_with_rsa(dhratchet_private_key, device.device_public_key)

    private_keys = {
        'ik_private_key': format_key(ik_private_key),
        'spk_private_key': format_key(spk_private_key),
        'opk_private_key': format_key(opk_private_key),
        'dhratchet_private_key': format_key(dhratchet_private_key),
        'type': 1,
        'version': public_key_object.version
    }
    return private_keys


def generate_aes_key():
    aes_key = os.urandom(32)
    return aes_key


def split_aes_key(aes_key, num_parts):
    part_length = len(aes_key) // num_parts

    aes_key_parts = [aes_key[i * part_length: (i + 1) * part_length] for i in range(num_parts)]

    return tuple(aes_key_parts)


def encrypt_aes(data, aes_key):
    # Pad data to match AES block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Generate initialization vector (IV)
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())

    # Encrypt data
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Return IV and ciphertext
    return iv + ciphertext


def generate_key_pair(user, device_id):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    AES = generate_aes_key()
    encrypted_private_key_jwk = encrypt_aes(private_key_pem, AES)

    one, two = split_aes_key(AES, 2)
    UserSecure.create_or_update(user=user, device=device_id, aes_key=one)
    return encrypted_private_key_jwk, public_key_bytes, two


def encrypt_with_rsa(data, rsa_public_key):
    from cryptography.hazmat.primitives.asymmetric import padding
    rsa_public_key = serialization.load_der_public_key(rsa_public_key, backend=default_backend())
    ciphertext = rsa_public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext
