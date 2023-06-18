from django.contrib import admin
from django.urls import path, include, re_path

from main import routing, views

urlpatterns = {
    path('', views.home, name='home'),
    path('connect/<str:client_id>/', views.connect, name='connect'),
    path('clients/connected/', views.connected_clients, name='connect_clients'),
    path('clients/idle/', views.idle_clients, name='idle_clients'),
    path('clients/busy/', views.busy_clients, name='busy_clients'),
}