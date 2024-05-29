from django.shortcuts import render
from django.contrib.auth import logout
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
from .forms import UserLoginForm
from .models import AppUser
from django.shortcuts import render, redirect
from .forms import SignUpForm
from django.shortcuts import render, redirect
from django.contrib.auth import login
from .forms import OTPForm
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import AppUser
import pyotp

import qrcode
import base64
from django.http import HttpResponse
from django.shortcuts import render
from .models import AppUser
from io import BytesIO

#--------------------------------------------------------------------------------------------------#
#simple views                                                                                      #
#--------------------------------------------------------------------------------------------------#
def index(request):
    return render(request, 'userAuth/index.html')

def success_view(request):
    return render(request, 'userAuth/success.html')

def logout_view(request):
    request.session.flush()
    return render(request, 'userAuth/logout.html')

def signup(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save()
            AppUser.objects.create(user=user)
            return redirect('login')
    else:
        form = SignUpForm()
    return render(request, 'userAuth/signup.html', {'form': form})


#--------------------------------------------------------------------------------------------------#
#2FA: one time passwords                                                                           #
#--------------------------------------------------------------------------------------------------#
#user login and up using 2fa also (django-otp) if enabled                                          #
def user_login(request):
    enable_2fa = False
    if request.method == 'POST':
        form = UserLoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            if user is not None:
                if hasattr(user, 'appuser') and user.appuser.is_2fa_enabled:
                    enable_2fa = True
                    request.session['user_id'] = user.id
                    return redirect('verify_2fa')
                else:
                    login(request, user)
                    return redirect('index')
    else:
        form = UserLoginForm()

    return render(request, 'userAuth/login.html', {'form': form, 'enable_2fa': enable_2fa})

#2FA verification
def verify_2fa(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')
    
    user = User.objects.get(pk=user_id)

    if request.method == 'POST':
        form = OTPForm(request.POST)
        if form.is_valid():
            otp = form.cleaned_data['otp']
            if user.appuser.verify_otp(otp):
                user.backend = 'django.contrib.auth.backends.ModelBackend'
                login(request, user)
                del request.session['user_id']
                return redirect('index')
            else:
                form.add_error('otp', 'Invalid OTP. Please try again.')
    else:
        form = OTPForm()

    return render(request, 'userAuth/verify_2fa.html', {'form': form})

#2FA enable
@login_required
def enable_2fa(request):
    app_user = request.user.appuser
    if request.method == 'POST':
        app_user.is_2fa_enabled = True
        app_user.save()
        messages.success(request, 'Two-factor authentication has been enabled successfully.')
        return redirect('setup_otp')
    return render(request, 'userAuth/enable_2fa.html')

#2FA disable
@login_required
def disable_2fa(request):
    app_user = request.user.appuser
    if request.method == 'POST':
        app_user.is_2fa_enabled = False #update flag
        app_user.totp_secret_key = None #clear
        app_user.save() #save
        messages.success(request, 'Two-factor authentication has been disabled successfully.')
        return redirect('index') 
    return render(request, 'userAuth/disable_2fa.html')

#2FA settings up mobile authenticator application
@login_required
def setup_otp(request):
    user = request.user
    app_user = AppUser.objects.get(user=user)
    secret_key = pyotp.random_base32()
    app_user.totp_secret_key = secret_key
    app_user.save()
    totp = pyotp.TOTP(secret_key)
    provisioning_uri = totp.provisioning_uri(user.username, issuer_name=request.META['HTTP_HOST'])
    qr_code = generate_qr_code(provisioning_uri)

    return render(request, 'userAuth/setup_otp.html', {'qr_code': qr_code})

#2FA QR code generator
def generate_qr_code(data):
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    qr_image = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    qr_image.save(buffer)
    qr_code = base64.b64encode(buffer.getvalue()).decode()
    return qr_code

#-----------------------------------------------------------------------#
#MitID                                                                  #
#scripts located on templates in testing version                        #
#-----------------------------------------------------------------------#
def mitid_login(request):
    return render(request, 'userAuth/mitid.html')

def mitid_success(request):
    return render(request, 'userAuth/mitid_success.html')