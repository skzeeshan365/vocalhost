from django.contrib.auth.backends import BaseBackend

from main.models import UserProfile


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

    def authenticate_api(self, api_key=None):
        try:
            user_profile = UserProfile.objects.get(api=api_key)

            # Check if the user has reached the maximum number of clients
            if user_profile is not None:
                return user_profile.user
            else:
                return None

        except UserProfile.DoesNotExist:
            return None
