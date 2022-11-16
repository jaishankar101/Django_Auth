from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.tokens import PasswordResetTokenGenerator
import six
# Create your models here.


class User(AbstractUser):
    USERNAME_FIELD = 'email'
    email = models.EmailField(('email address'), unique=True)
    REQUIRED_FIELDS = []
    is_email_verified = models.BooleanField(default=False)
    def __str__(self):
        return self.email

class TokenGenerator(PasswordResetTokenGenerator):

    def _make_hash_value(self, user, timestamp):
        return (six.text_type(user.pk)+six.text_type(timestamp)+six.text_type(user.is_email_verified))

generate_token = TokenGenerator()