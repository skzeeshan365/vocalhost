from django.urls import path
from django.views.generic import RedirectView
from django.views.static import serve

from ReiserX_Tunnel import settings
from main import views
from main.views import chat_box

urlpatterns = [
    path('', views.home, name='home'),
    path('connect/<str:client_id>/', views.connect, name='connect'),
    path('clients/connected/', views.connected_clients, name='connect_clients'),
    path('clients/idle/', views.idle_clients, name='idle_clients'),
    path('clients/busy/', views.busy_clients, name='busy_clients'),
    path('docs/', views.docs, name='vocalhost_docs'),
    path('account/register/', views.register, name='register'),
    path('account/login/', views.login_view, name='login'),
    path('account/api/get/', views.get_api, name='get_api'),
    path('account/api/generate/', views.regenerate_api, name='regenerate_api'),
    path('account/logout/', views.logout, name='logout'),
    path('account/profile/', views.profile, name='profile'),
    path('account/client/delete/<str:client_id>/', views.delete_client, name='delete_client'),

    path('accounts/', views.user_accounts, name='user_accounts'),
    path('accounts/<str:username>/', views.increase_limit, name='increase_limit'),

    path('chat/firebase-messaging-sw.js', serve,
         {'document_root': 'static', 'path': 'chat/js/firebase-messaging-sw.js', 'show_indexes': True}),

    path("chat/", chat_box, name="chat"),
    path("chat/delete/<str:receiver>/", views.delete_messages, name="delete_messages"),
    path("chat/load/messages/<str:receiver>/", views.load_messages, name="load_messages"),
    path("push/register_device/", views.register_device, name='register_device'),
    path('add/chat/', views.add_chat, name='add_chat'),

    # Favicons
    path('android-icon-36x36.png',
         RedirectView.as_view(url=settings.STATIC_URL + 'favicon/android-icon-36x36.png', permanent=True)),
    path('android-icon-48x48.png',
         RedirectView.as_view(url=settings.STATIC_URL + 'favicon/android-icon-48x48.png', permanent=True)),
    path('android-icon-72x72.png',
         RedirectView.as_view(url=settings.STATIC_URL + 'favicon/android-icon-72x72.png', permanent=True)),
    path('android-icon-96x96.png',
         RedirectView.as_view(url=settings.STATIC_URL + 'favicon/android-icon-96x96.png', permanent=True)),
    path('android-icon-144x144.png',
         RedirectView.as_view(url=settings.STATIC_URL + 'favicon/android-icon-144x144.png', permanent=True)),
    path('android-icon-192x192.png',
         RedirectView.as_view(url=settings.STATIC_URL + 'favicon/android-icon-192x192.png', permanent=True)),
    path('android-icon-192x192.png',
         RedirectView.as_view(url=settings.STATIC_URL + 'favicon/browserconfig.xml', permanent=True)),
    # Favicons
]
