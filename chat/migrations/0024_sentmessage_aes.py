# Generated by Django 5.0.1 on 2024-03-18 15:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("chat", "0023_userdevice_device_public_key_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="sentmessage",
            name="AES",
            field=models.TextField(blank=True, null=True),
        ),
    ]
