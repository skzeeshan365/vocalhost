# Generated by Django 5.0.1 on 2024-02-15 12:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("main", "0023_message_saved"),
    ]

    operations = [
        migrations.AddField(
            model_name="message",
            name="image_url",
            field=models.URLField(blank=True, default=None, null=True),
        ),
        migrations.AlterField(
            model_name="message",
            name="message",
            field=models.TextField(blank=True, max_length=10000, null=True),
        ),
    ]
