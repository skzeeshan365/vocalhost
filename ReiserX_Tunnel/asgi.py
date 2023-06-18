import os

from channels.auth import AuthMiddlewareStack
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from main.routing import websocket_urlpatterns
from .middleware import WebSocketTimeoutMiddleware

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ReiserX_Tunnel.settings')

application = ProtocolTypeRouter({
    'http': get_asgi_application(),
    'websocket': WebSocketTimeoutMiddleware(
            AuthMiddlewareStack(
                URLRouter(
                    websocket_urlpatterns,
                )
            ),
            timeout=120,  # Set the timeout to 60 seconds (adjust as needed)
        ),
})