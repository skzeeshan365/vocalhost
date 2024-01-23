from django.urls import re_path, path

from . import consumers
from .consumers import ChatConsumer

websocket_urlpatterns = [
    path("ws/chat/", ChatConsumer.as_asgi()),
    re_path('ws/', consumers.MyWebSocketConsumer.as_asgi(), name='test'),
]