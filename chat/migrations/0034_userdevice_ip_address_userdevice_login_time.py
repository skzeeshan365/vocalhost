# Generated by Django 5.0.1 on 2024-03-21 20:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("chat", "0033_userdevice_device_type_userdevice_name"),
    ]

    operations = [
        migrations.AddField(
            model_name="userdevice",
            name="ip_address",
            field=models.GenericIPAddressField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="userdevice",
            name="login_time",
            field=models.DateTimeField(auto_now=True),
        ),
    ]
