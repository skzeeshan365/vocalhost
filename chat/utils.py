import base64


def format_key(keys):
    key = []
    for i in keys:
        key.append(base64.b64encode(i).decode('utf-8'))
    return key