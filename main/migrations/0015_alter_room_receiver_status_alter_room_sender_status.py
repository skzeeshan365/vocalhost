# Generated by Django 5.0.1 on 2024-02-09 13:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("main", "0014_room_receiver_status_room_sender_status"),
    ]

    operations = [
        migrations.AlterField(
            model_name="room",
            name="receiver_status",
            field=models.BooleanField(default=False, null=True),
        ),
        migrations.AlterField(
            model_name="room",
            name="sender_status",
            field=models.BooleanField(default=False, null=True),
        ),
    ]
