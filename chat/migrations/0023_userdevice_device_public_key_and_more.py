# Generated by Django 5.0.1 on 2024-03-17 21:42

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("chat", "0022_delete_device"),
    ]

    operations = [
        migrations.AddField(
            model_name="userdevice",
            name="device_public_key",
            field=models.BinaryField(blank=True, default=None, null=True),
        ),
        migrations.AlterField(
            model_name="childmessage",
            name="cipher",
            field=models.TextField(blank=True, null=True),
        ),
        migrations.CreateModel(
            name="SentMessage",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("cipher", models.TextField(blank=True, null=True)),
                (
                    "base_message",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="sent_base_message",
                        to="chat.message",
                    ),
                ),
                (
                    "device_id",
                    models.ForeignKey(
                        blank=True,
                        default=None,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="sent_receiver_device_id",
                        to="chat.userdevice",
                    ),
                ),
            ],
        ),
    ]
