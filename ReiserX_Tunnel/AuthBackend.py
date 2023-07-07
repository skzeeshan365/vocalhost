from django.contrib.auth.backends import BaseBackend
from django.db import IntegrityError

from main.models import UserProfile

MAX_CLIENTS_LIMIT = 2


class CustomAuthBackend(BaseBackend):
    def authenticate(self, request, api_key=None, client_id=None):
        try:
            user_profile = UserProfile.objects.get(api=api_key)

            # Check if the user has reached the maximum number of clients
            if user_profile.connected_clients.count() >= MAX_CLIENTS_LIMIT:
                return user_profile.user, False
            else:
                user_profile.connected_clients.get_or_create(client_id=client_id)

            return user_profile.user, True
        except UserProfile.DoesNotExist:
            return None, None
