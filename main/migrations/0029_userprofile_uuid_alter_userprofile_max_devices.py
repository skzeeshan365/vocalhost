# Generated by Django 5.0.1 on 2024-03-23 19:47

import django.core.validators
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("main", "0028_userprofile_max_devices"),
    ]

    operations = [
        migrations.AddField(
            model_name="userprofile",
            name="UUID",
            field=models.UUIDField(default=uuid.uuid4, editable=False),
        ),
        migrations.AlterField(
            model_name="userprofile",
            name="max_devices",
            field=models.IntegerField(
                default=4, validators=[django.core.validators.MaxValueValidator(10)]
            ),
        ),
    ]
