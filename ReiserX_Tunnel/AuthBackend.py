from django.contrib.auth.backends import BaseBackend

from main.models import UserProfile, Client


class CustomAuthBackend(BaseBackend):
    def authenticate(self, request, api_key=None, client_id=None):
        try:
            user_profile = UserProfile.objects.get(api=api_key)

            # Check if the user has reached the maximum number of clients
            if user_profile.add_connected_client(client_id):
                return user_profile.user, True
            else:
                return user_profile.user, False

        except UserProfile.DoesNotExist:
            return None, None
