# Generated by Django 5.0.1 on 2024-03-20 16:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("chat", "0028_alter_publickey_device_identifier"),
    ]

    operations = [
        migrations.AddField(
            model_name="publickey",
            name="version",
            field=models.PositiveIntegerField(default=1),
        ),
    ]
