# Generated by Django 5.0.1 on 2024-03-20 20:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("chat", "0030_childmessage_public_key_version"),
    ]

    operations = [
        migrations.AddField(
            model_name="childmessage",
            name="private_key_version",
            field=models.PositiveIntegerField(default=1),
        ),
    ]