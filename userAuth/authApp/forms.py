# forms.py
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

class SignUpForm(UserCreationForm):
    email = forms.EmailField(max_length=254, help_text='Required. Inform a valid email address.')

    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2')



from django import forms
from django.contrib.auth.forms import AuthenticationForm

# forms.py
from django import forms

# forms.py
from django import forms

class UserLoginForm(forms.Form):
    username = forms.CharField(label='Username')
    password = forms.CharField(label='Password', widget=forms.PasswordInput)

class OTPForm(forms.Form):
    otp = forms.CharField(label='OTP', max_length=6)