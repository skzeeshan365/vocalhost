# Generated by Django 4.2.2 on 2023-07-12 14:07

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("main", "0003_remove_client_connected_client_client_id_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="userprofile",
            name="max_receiver",
            field=models.IntegerField(
                default=1, validators=[django.core.validators.MaxValueValidator(10)]
            ),
        ),
    ]
