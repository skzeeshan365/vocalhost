from io import BytesIO

from PIL import Image
from cloudinary import uploader
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile

from main.models import UserProfile


class RegistrationForm(UserCreationForm):
    email = forms.EmailField(widget=forms.EmailInput(
        attrs={
            'class': 'form-control form-control-lg',
            'placeholder': 'Email'
        }
    ))
    password1 = forms.CharField(widget=forms.PasswordInput(
        attrs={
            'class': 'form-control form-control-lg',
            'placeholder': 'Password'
        }
    ))
    password2 = forms.CharField(widget=forms.PasswordInput(
        attrs={
            'class': 'form-control form-control-lg',
            'placeholder': 'Confirm Password'
        }
    ))

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].widget.attrs.update({
            'class': 'form-control form-control-lg',
            'placeholder': 'Username'
        })
        self.fields['username'].label = ''
        self.fields['username'].help_text = None
        self.fields['email'].label = ''
        self.fields['password1'].label = ''
        self.fields['password2'].label = ''

    def email_exists(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            return True
        return False


class LoginForm(forms.Form):
    username_or_email = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput(
        attrs={
            'class': 'form-control form-control-lg',
            'placeholder': 'Password'
        }
    ))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username_or_email'].widget.attrs.update({
            'class': 'form-control form-control-lg',
            'placeholder': 'Username or email'
        })
        self.fields['username_or_email'].label = ''
        self.fields['username_or_email'].help_text = None
        self.fields['password'].label = ''


class EditForm(forms.Form):
    limit = forms.IntegerField()


class ImageUploadForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['image']

    image = forms.ImageField(
        widget=forms.ClearableFileInput(attrs={
            'id': 'imageInput',
            'accept': 'image/*',
            'class': 'form-control-file',
            'onchange': 'updateImageLabelIcon(this)',
            'style': 'display: none;'
        })
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        instance = kwargs.get('instance')
        if instance:
            if instance.image:
                self.fields['image'].initial = instance.image
            else:
                self.fields['image'].initial = None

    def save(self, commit=True):
        instance = super().save(commit=False)

        # Process image compression
        images = self.cleaned_data.get('image')
        if images:
            with images.open() as img_file:
                img = Image.open(img_file)
                # Resize the image if necessary
                if img.height > 300 or img.width > 300:
                    output_size = (300, 300)
                    img.thumbnail(output_size)

                # Create a new temporary in-memory file
                tmp_buffer = BytesIO()
                img.save(tmp_buffer, format='WEBP', quality=70)

                # Create a new SimpleUploadedFile from the buffer
                tmp_file = SimpleUploadedFile('resized_image.webp', tmp_buffer.getvalue())

                if instance.image:
                    user_profile = UserProfile.objects.get(user=instance.user)
                    user_profile.image.delete()

                instance.image.save(tmp_file.name, tmp_file, save=True)

        if commit:
            instance.save()

        return instance
