# Generated by Django 5.0.1 on 2024-03-09 18:34

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("chat", "0009_remove_room_receiver_key_bundle_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="friendrequest",
            name="receiver_device_id",
            field=models.ForeignKey(
                blank=True,
                default=None,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="receiver_device_id",
                to="chat.deviceidentifier",
            ),
        ),
        migrations.AlterField(
            model_name="friendrequest",
            name="sender_device_id",
            field=models.ForeignKey(
                blank=True,
                default=None,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="sender_device_id",
                to="chat.deviceidentifier",
            ),
        ),
    ]
