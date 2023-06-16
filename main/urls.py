from django.contrib import admin
from django.urls import path, include, re_path

from main import routing, views

urlpatterns = [
    path('', views.my_api_view, name='home'),
]