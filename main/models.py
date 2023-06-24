# Create your models here.
from django.db import models


class Client(models.Model):
    id = models.CharField(max_length=255)
    connected = models.BooleanField(default=False)