from django.contrib import admin
from django.urls import path, include, re_path

from main import routing, views

urlpatterns = {
    path('', views.home, name='home'),
    path('connect/<str:client_id>/', views.connect, name='connect'),
}