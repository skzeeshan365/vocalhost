from django.urls import re_path, path

from main import consumers
from chat.consumers import ChatConsumer

websocket_urlpatterns = [
    path("ws/chat/", ChatConsumer.as_asgi()),
    re_path('ws/', consumers.MyWebSocketConsumer.as_asgi(), name='test'),
]