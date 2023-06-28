from django.contrib.auth.backends import BaseBackend

from main.models import UserProfile

MAX_CLIENTS_LIMIT = 1


class CustomAuthBackend(BaseBackend):
    def authenticate(self, request, api_key=None, client_id=None):
        # Perform API key verification and authentication logic
        # Return the authenticated user object or None

        # Example code:
        try:
            user_profile = UserProfile.objects.get(api=api_key)

            # Check if the user has reached the maximum number of clients
            if user_profile.connected_clients.count() >= MAX_CLIENTS_LIMIT:
                return None

            # Add the client to the user's connected clients
            user_profile.connected_clients.create(client_id=client_id)

            return user_profile.user
        except UserProfile.DoesNotExist:
            return None
