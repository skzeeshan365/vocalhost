# Generated by Django 5.0.1 on 2024-03-23 20:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("chat", "0039_alter_room_receiver_alter_room_sender"),
    ]

    operations = [
        migrations.AlterField(
            model_name="room",
            name="receiver_message_status",
            field=models.SmallIntegerField(default=-1),
        ),
    ]