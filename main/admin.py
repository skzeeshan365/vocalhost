# Register your models here.
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User

from main.models import Client, UserProfile
from chat.models import Room, Message, FriendRequest, Devices, DeviceIdentifier, PublicKey, RatchetPublicKey


class UserProfileInline(admin.StackedInline):
    model = UserProfile


class CustomUserAdmin(UserAdmin):
    inlines = [UserProfileInline]


admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)

admin.site.register(Client)
admin.site.register(Room)

admin.site.register(Message)
admin.site.register(FriendRequest)
admin.site.register(Devices)
admin.site.register(DeviceIdentifier)
admin.site.register(PublicKey)
admin.site.register(RatchetPublicKey)