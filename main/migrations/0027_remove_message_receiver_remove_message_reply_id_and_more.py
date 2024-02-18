# Generated by Django 5.0.1 on 2024-02-18 11:00

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("main", "0026_friendrequest"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="message",
            name="receiver",
        ),
        migrations.RemoveField(
            model_name="message",
            name="reply_id",
        ),
        migrations.RemoveField(
            model_name="message",
            name="room",
        ),
        migrations.RemoveField(
            model_name="message",
            name="sender",
        ),
        migrations.RemoveField(
            model_name="message",
            name="temp",
        ),
        migrations.DeleteModel(
            name="FriendRequest",
        ),
        migrations.DeleteModel(
            name="Room",
        ),
        migrations.DeleteModel(
            name="Message",
        ),
    ]
