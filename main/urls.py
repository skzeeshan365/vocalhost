from django.urls import path

from main import views

urlpatterns = {
    path('', views.home, name='home'),
    path('connect/<str:client_id>/', views.connect, name='connect'),
    path('clients/connected/', views.connected_clients, name='connect_clients'),
    path('clients/idle/', views.idle_clients, name='idle_clients'),
    path('clients/busy/', views.busy_clients, name='busy_clients'),
}