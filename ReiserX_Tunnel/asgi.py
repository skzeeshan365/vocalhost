import os

import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ReiserX_Tunnel.settings')
django.setup()

from channels.routing import ProtocolTypeRouter, URLRouter
from main.routing import websocket_urlpatterns
from django.core.asgi import get_asgi_application

application = ProtocolTypeRouter({
    'http': get_asgi_application(),
    'websocket': URLRouter(websocket_urlpatterns),
})
