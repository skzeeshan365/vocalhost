# Generated by Django 5.0.1 on 2024-03-21 20:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("chat", "0032_remove_childmessage_private_key_version_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="userdevice",
            name="device_type",
            field=models.CharField(
                choices=[("android", "android"), ("ios", "ios"), ("web", "web")],
                default="web",
                max_length=10,
            ),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="userdevice",
            name="name",
            field=models.CharField(blank=True, max_length=20, null=True),
        ),
    ]