from django.urls import path

from chat import views
from chat.views import chat_box

urlpatterns = [
    path('account/profile/update/profile-pic', views.update_profile, name='update_profile'),
    path('account/profile/update/info', views.update_profile_info, name='update_profile_info'),

    path('', chat_box, name="chat"),
    path('profile/<str:username>/', views.chat_profile, name='chat_profile'),
    path("delete/<str:receiver>/", views.delete_messages, name="delete_messages"),
    path("load/messages/<str:receiver>/", views.load_messages, name="load_messages"),
    path('process/temp/messages/', views.process_temp_messages, name='process_temp_messages'),

    path('get/public-keys/', views.get_user_public_keys, name='get_user_public_keys'),
    path('get/private-keys/secondary/', views.generate_secondary_key_pair, name='get_user_private_key_secondary'),
    path('get/private-keys/ratchet/', views.generate_ratchet_keys, name='get_user_private_key_ratchet'),

    path("push/register_device/", views.register_device, name='register_device'),
    path('add/chat/', views.add_chat, name='add_chat'),
    path('clear/chat/', views.clear_chat, name='clear_chat'),
    path('remove/chat/', views.remove_chat, name='remove_chat'),
    path('upload/image/', views.upload_image, name='upload_image'),
    path('request/send/', views.send_friend_request, name='send_friend_request'),
    path('request/accept/', views.accept_friend_request, name='accept_friend_request'),

]
