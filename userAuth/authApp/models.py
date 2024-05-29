from django.db import models
from django.contrib.auth.models import User
import pyotp


class AppUser(models.Model):
    #profile fields
    totp_secret_key = models.CharField(max_length=64, blank=True, null=True)
    is_2fa_enabled = models.BooleanField(default=False)
    user = models.OneToOneField(User, on_delete=models.CASCADE)  #username
    email = models.EmailField() #e-mail adress

    def verify_otp(self, otp):
        if self.totp_secret_key:
            totp = pyotp.TOTP(self.totp_secret_key) #TOTP object with the secret key
            return totp.verify(otp) #verity totp
        return False

    def __str__(self):
        return self.user.username