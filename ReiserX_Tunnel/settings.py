import os
from pathlib import Path

import cloudinary
import firebase_admin
import pusher
from dotenv import load_dotenv
from firebase_admin import initialize_app, credentials

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

load_dotenv('.env')

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv('SECRET_KEY')
CONNECT_KEY = os.getenv('CONNECT_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

ALLOWED_HOSTS = ['localhost', '3.109.62.111', 'vocalhost.reiserx.com', '127.0.0.1', '192.168.0.100']

if DEBUG:
    ROOT_DOMAIN = 'localhost'
else:
    ROOT_DOMAIN = 'vocalhost.reiserx.com'

# Application definition

INSTALLED_APPS = [
    "daphne",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "channels",
    "main.apps.MainConfig",
    'chat.apps.ChatConfig',
    "django.contrib.sitemaps",
    "fcm_django",
    'cloudinary_storage',
    'cloudinary',
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "ReiserX_Tunnel.urls"

ASSET_VERSION = '2'
ASSET_VERSION_RATCHET = '1'

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / 'templates'],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                'ReiserX_Tunnel.context_processors.asset_version'
            ],
        },
    },
]

ASGI_APPLICATION = 'ReiserX_Tunnel.asgi.application'

# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}

CLOUDINARY_STORAGE = {
    'CLOUD_NAME': os.getenv('CLOUD_NAME'),
    'API_KEY': os.getenv('API_KEY'),
    'API_SECRET': os.getenv('API_SECRET'),
    'FOLDER': 'vocalhost'
}
DEFAULT_FILE_STORAGE = 'cloudinary_storage.storage.MediaCloudinaryStorage'

cloudinary.config(
    cloud_name=CLOUDINARY_STORAGE['CLOUD_NAME'],
    api_key=CLOUDINARY_STORAGE['API_KEY'],
    api_secret=CLOUDINARY_STORAGE['API_SECRET'],
)

CHANNELS_AUTH_BACKEND = 'ReiserX_Tunnel.AuthBackend.CustomAuthBackend'

# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

STATIC_URL = '/static/'
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static')
]
STATIC_ROOT = os.path.join(BASE_DIR, 'assets')

if DEBUG:
    STATICFILES_STORAGE = 'django.contrib.staticfiles.storage.StaticFilesStorage'

DEFAULT_FROM_EMAIL = "support@reiserx.com"
SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')

# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "Asia/Kolkata"

USE_I18N = True

USE_TZ = True

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels.layers.InMemoryChannelLayer",
        'CHANNEL_MIDDLEWARE': [
            'django.http.CookieMiddleware'],
    }
}

credentials_path = os.path.join(BASE_DIR, 'ReiserX_Tunnel/credentials_backup.json')

# Initialize the Firebase app
FIREBASE_APP = initialize_app(credentials.Certificate(credentials_path))

FCM_DJANGO_SETTINGS = {
    "ONE_DEVICE_PER_USER": True,
    # devices to which notifications cannot be sent,
    # are deleted upon receiving error response from FCM
    # default: False
    "DELETE_INACTIVE_DEVICES": True,
}

PUSHER_KEY = os.getenv('PUSHER_KEY')
pusher_client = pusher.Pusher(
    app_id=os.getenv('PUSHER_APP_ID'),
    key=PUSHER_KEY,
    secret=os.getenv('PUSHER_SECRET'),
    cluster='ap2',
    ssl=True
)

FIREBASE_API_KEY = os.getenv('FIREBASE_API_KEY')
