# Register your models here.
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User

from main.models import Client, UserProfile
from chat.models import Room, Message, FriendRequest, UserDevice, PublicKey, ChildMessage, SentMessage, UserSecure


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


class UserSecureAdmin(admin.ModelAdmin):
    list_display = ('User', 'Device', 'AES_preview')

    def AES_preview(self, obj):
        if obj.AES:
            return obj.AES[:30]  # Display first 30 characters of device_public_key
        return '-'


class RoomAdmin(admin.ModelAdmin):
    list_display = ('room', 'sender', 'receiver', 'sender_message_status', 'receiver_message_status')


class FriendRequestAdmin(admin.ModelAdmin):
    list_display = ('sender', 'receiver', 'status', 'sender_device_id', 'receiver_device_id')
    list_display_links = ('sender', 'receiver', 'sender_device_id', 'receiver_device_id')


class PublicKeyAdmin(admin.ModelAdmin):
    list_display = ('version', 'timestamp', 'user', 'key_type', 'device_identifier', 'room', 'ratchet_key_overview')
    list_display_links = ('version',)
    list_filter = ('version', 'user', 'key_type', 'device_identifier', 'room')

    fieldsets = (
        ('Main Information', {
            'fields': ('version', 'user', 'key_type'),
        }),
        ('Device Information', {
            'fields': ('device_identifier',),
        }),
        ('Room Information', {
            'fields': ('room',),
        }),
    )

    def ratchet_key_overview(self, obj):
        if obj.ratchet_key:
            return obj.ratchet_key[:20]
        return '-'

    def timestamp(self, obj):
        return obj.timestamp()


class ChildMessageAdmin(admin.ModelAdmin):
    list_display = ('cipher_preview', 'bytes_cipher_preview', 'key_version', 'sender_device_id', 'receiver_device_id', 'base_message')
    list_display_links = ('cipher_preview',)

    def cipher_preview(self, obj):
        if obj.cipher:
            return obj.cipher[:20]  # Display first 30 characters of device_public_key
        return '-'

    def bytes_cipher_preview(self, obj):
        if obj.bytes_cipher:
            return obj.bytes_cipher[:20]  # Display first 30 characters of device_public_key
        return '-'


class SentMessageAdmin(admin.ModelAdmin):
    list_display = ('device_id', 'base_message', 'public_key_preview')
    list_display_links = ('device_id', 'base_message')

    def public_key_preview(self, obj):
        if obj.AES:
            return obj.AES[:30]  # Display first 30 characters of device_public_key
        return '-'


class MessageAdmin(admin.ModelAdmin):
    list_display = (
    'message_id', 'message', 'timestamp', 'room', 'sender', 'receiver', 'reply_id', 'saved', 'image_url')
    list_display_links = ('message_id', 'room', 'sender', 'receiver', 'reply_id')


admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)

admin.site.register(Client)
admin.site.register(Room, RoomAdmin)

admin.site.register(Message, MessageAdmin)
admin.site.register(ChildMessage, ChildMessageAdmin)
admin.site.register(SentMessage, SentMessageAdmin)

admin.site.register(FriendRequest, FriendRequestAdmin)
admin.site.register(UserDevice, UserDeviceAdmin)
admin.site.register(UserSecure, UserSecureAdmin)

admin.site.register(PublicKey, PublicKeyAdmin)
