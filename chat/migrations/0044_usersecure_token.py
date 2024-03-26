# Generated by Django 5.0.1 on 2024-03-26 19:02

import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("chat", "0043_usersecure"),
    ]

    operations = [
        migrations.AddField(
            model_name="usersecure",
            name="Token",
            field=models.UUIDField(default=uuid.uuid4, editable=False, unique=True),
        ),
    ]
