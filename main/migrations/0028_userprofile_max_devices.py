# Generated by Django 5.0.1 on 2024-03-22 16:44

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("main", "0027_remove_message_receiver_remove_message_reply_id_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="userprofile",
            name="max_devices",
            field=models.IntegerField(
                default=1, validators=[django.core.validators.MaxValueValidator(10)]
            ),
        ),
    ]