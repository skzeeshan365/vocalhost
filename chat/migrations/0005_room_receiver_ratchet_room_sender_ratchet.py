# Generated by Django 5.0.1 on 2024-02-29 13:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("chat", "0004_friendrequest_receiver_key_bundle_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="room",
            name="receiver_ratchet",
            field=models.BinaryField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name="room",
            name="sender_ratchet",
            field=models.BinaryField(blank=True, default=None, null=True),
        ),
    ]
