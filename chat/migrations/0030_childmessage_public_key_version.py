# Generated by Django 5.0.1 on 2024-03-20 19:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("chat", "0029_publickey_version"),
    ]

    operations = [
        migrations.AddField(
            model_name="childmessage",
            name="public_key_version",
            field=models.PositiveIntegerField(default=1),
        ),
    ]