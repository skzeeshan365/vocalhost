# Generated by Django 5.0.1 on 2024-03-18 21:09

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("chat", "0025_remove_message_temp"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="message",
            name="public_key",
        ),
    ]
