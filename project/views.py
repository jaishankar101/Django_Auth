import threading

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.hashers import make_password
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.shortcuts import HttpResponse, redirect, render
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.encoding import (DjangoUnicodeDecodeError, force_bytes,
                                   force_str)
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode

from .models import User, generate_token


def index(request):
    return render(request,'index.html')


def registeration(request):
    if request.method == "POST":
        email = request.POST.get('email')
        username = request.POST.get('username')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')

        if password != password2:
            messages.add_message(request, messages.ERROR,
                                 'Password mismatch')


        if User.objects.filter(email=email).exists():
            messages.add_message(request, messages.ERROR,
                                 'Email is taken, choose another one')

            return render(request, 'registeration.html',  status=409)

        user = User.objects.create_user(username=username, email=email)
        user.set_password(password)
        user.save()

        # send_activation_email(user, request)
        current_site = get_current_site(request)
        email_subject = 'Activate your account'
        email_body = render_to_string('activate.html', {
        'user': user,
        'domain': current_site,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': generate_token.make_token(user)
        })

        email = send_mail(email_subject, email_body,settings.EMAIL_HOST_USER,[user.email])

        messages.add_message(request, messages.SUCCESS,
                                'We sent you an email to verify your account')
        return redirect('user_login')

    return render(request, 'registeration.html')


def user_login(request):

    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        user = authenticate(request, email=email, password=password)

        if user and not user.is_email_verified:
            messages.add_message(request, messages.ERROR,
                                 'Email is not verified, please check your email inbox')
            return render(request, 'user_login.html',  status=401)

        if not user:
            messages.add_message(request, messages.ERROR,
                                 'Invalid credentials, try again')
            return render(request, 'user_login.html',  status=401)

        login(request, user)

        messages.add_message(request, messages.SUCCESS,
                             'Welcome {}'.format(user.username))

        return redirect(reverse('index'))

    return render(request, 'user_login.html')

def forgotPassword(request):
    if request.method == "POST":
        email = request.POST['email']
        user=User.objects.get(email=email)
        if User.objects.filter(email=email).exists():
            current_site = get_current_site(request)
            email_subject = 'Reset your password'
            email_body = render_to_string('reset_password.html', {
            'domain': current_site,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': generate_token.make_token(user)
            })
            send_mail(email_subject, email_body,settings.EMAIL_HOST_USER,[email])
            messages.add_message(request, messages.SUCCESS,'Mail has been sent to your Registered Email address {}'.format(email))
            return redirect('forgotPassword')
        else:
            messages.error(request,'Email address does not exist')
    
    return render(request,'forgotPassword.html')

def resetPassword(request,uidb64,token):
    try:
        userpk = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=userpk)
        if user and generate_token.check_token(user, token):
            if request.method == "POST":
                password1 = request.POST['new_password']
                password2 = request.POST['new_password2']
                if password1 == password2:
                    user.password = make_password(password1)
                    user.save()
                    messages.success(request,'Password has been reset successfully')
                    return redirect(reverse('user_login'))
                else:
                    return HttpResponse('Two Password did not match')
                
        else:
            return HttpResponse('Wrong URL')
    except:
        return HttpResponse('Wrong URL')
    return render(request,'resetPassword.html')

# def setNewPassword(request):
#     if request.method == "POST":
#         password1 = request.POST['new_password']
#         password2 = request.POST['new_password2']
#         if password1 == password2:
#             user.password = make_password(password1)
#             user.save()
#             messages.success(request,'Password has been reset successfully')
#             return redirect(reverse('user_login'))
#         else:
#             return HttpResponse('Two Password did not match')
#     return render(request,'resetPassword.html')

def user_logout(request):

    logout(request)

    messages.add_message(request, messages.SUCCESS,
                         'Successfully logged out')

    return redirect(reverse('index'))


def activate_user(request, uidb64, token):

    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except Exception as e:
        user = None

    if user and generate_token.check_token(user, token):
        user.is_email_verified = True
        user.save()

        messages.add_message(request, messages.SUCCESS,'Email verified, you can now Login')
        return redirect(reverse('user_login'))
    messages.add_message(request, messages.ERROR,'error with link')
    return render(request, 'user_login.html',  status=401)
    # return render(request, 'activate-failed.html', {"user": user})