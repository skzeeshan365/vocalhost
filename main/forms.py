from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User


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
