# Register your models here.
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User

from main.models import Client, UserProfile
from chat.models import Room, Message, FriendRequest, UserDevice, PublicKey, RatchetPublicKey, ChildMessage, SentMessage


class UserProfileInline(admin.StackedInline):
    model = UserProfile


class CustomUserAdmin(UserAdmin):
    inlines = [UserProfileInline]


class UserDeviceAdmin(admin.ModelAdmin):
    list_display = ('user', 'identifier', 'device_public_key_preview')
    search_fields = ('user__username', 'identifier')

    def device_public_key_preview(self, obj):
        if obj.device_public_key:
            return obj.device_public_key[:30]  # Display first 30 characters of device_public_key
        return '-'


class RoomAdmin(admin.ModelAdmin):
    list_display = ('room', 'sender_username', 'receiver_username', 'sender_channel', 'receiver_channel')


class FriendRequestAdmin(admin.ModelAdmin):
    list_display = ('sender', 'receiver', 'status', 'sender_device_id', 'receiver_device_id')
    list_display_links = ('sender', 'receiver', 'sender_device_id', 'receiver_device_id')


class PublicKeyAdmin(admin.ModelAdmin):
    list_display = ('user', 'key_type', 'device_identifier', 'room')
    list_display_links = ('user', 'device_identifier', 'room')


class RatchetPublicKeyAdmin(admin.ModelAdmin):
    list_display = ('device_id', 'public_keys')
    list_display_links = ('device_id', 'public_keys')


admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)

admin.site.register(Client)
admin.site.register(Room, RoomAdmin)

admin.site.register(Message)
admin.site.register(ChildMessage)
admin.site.register(SentMessage)

admin.site.register(FriendRequest, FriendRequestAdmin)
admin.site.register(UserDevice, UserDeviceAdmin)
admin.site.register(PublicKey, PublicKeyAdmin)
admin.site.register(RatchetPublicKey, RatchetPublicKeyAdmin)