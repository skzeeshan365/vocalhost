import asyncio
from channels.middleware import BaseMiddleware
from channels.exceptions import StopConsumer


class WebSocketTimeoutMiddleware(BaseMiddleware):
    def __init__(self, application, timeout=60):
        super().__init__(application)
        self.timeout = timeout

    async def __call__(self, scope, receive, send):
        async def receive_timeout():
            try:
                return await asyncio.wait_for(receive(), timeout=self.timeout)
            except asyncio.TimeoutError:
                raise StopConsumer("WebSocket connection timed out.")

        scope['receive'] = receive_timeout
        return await super().__call__(scope, receive, send)
