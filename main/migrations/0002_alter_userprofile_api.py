# Generated by Django 4.2.2 on 2023-06-26 10:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("main", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="userprofile",
            name="api",
            field=models.CharField(blank=True, max_length=255),
        ),
    ]
