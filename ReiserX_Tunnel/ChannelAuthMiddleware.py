from urllib.parse import parse_qs

from channels.db import database_sync_to_async
from channels.middleware import BaseMiddleware

from .AuthBackend import CustomAuthBackend


class AuthMiddleware(BaseMiddleware):
    async def __call__(self, scope, receive, send):
        # Retrieve the query parameters from the scope
        query_string = scope['query_string'].decode('utf-8')
        query_params = parse_qs(query_string)

        api_key = query_params.get('api_key', [''])[0]

        # Authenticate the user based on the provided client_id and api_key
        user = await self.authenticate(api_key)

        if user is None:
            # Reject the connection if authentication fails
            return

            # Add the authenticated user to the scope
        scope['user'] = user

        # Call the next middleware or application
        return await super().__call__(scope, receive, send)

    @database_sync_to_async
    def authenticate(self, api_key):
        # Call your custom authentication backend's authenticate method
        return CustomAuthBackend().authenticate(request=None, api_key=api_key)