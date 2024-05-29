from django.urls import path
from .views import *

urlpatterns = [
    path('', index, name='index'),
    path('success/', success_view, name='success'),
    path('logout/', logout_view, name='logout'),
    path('signup/', signup, name='signup'),
    path('login/', user_login, name='login'),

    #2fa
    path('enable-2fa/', enable_2fa, name='enable_2fa'),
    path('disable-2fa/', disable_2fa, name='disable_2fa'),
    path('setup-otp/', setup_otp, name='setup_otp'),
    path('verify-2fa/', verify_2fa, name='verify_2fa'), 

    #mitid
    path('mitid-login/', mitid_login, name='mitid_login'),
    path('mitid-success/', mitid_success, name='mitid_success'),

]
