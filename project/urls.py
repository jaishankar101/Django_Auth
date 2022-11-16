from django.urls import path
from . import views
from django.contrib.auth import  views as auth_views
urlpatterns = [
    path("", views.index,name="index"),
    path('activate/<uidb64>/<token>',views.activate_user,name="activate"),
    path("user_login", views.user_login,name="user_login"),
    path("user_logout", views.user_logout,name="user_logout"),
    path("registeration", views.registeration,name="registeration"),
    path("forgotPassword", views.forgotPassword,name="forgotPassword"),
    path('resetPassword/<uidb64>/<token>',views.resetPassword,name="resetPassword"),
    path("password_reset/", auth_views.PasswordResetView.as_view(template_name="password_reset.html"), name="password_reset"),
    path(
        "password_reset/done/",
        auth_views.PasswordResetDoneView.as_view(template_name="password_reset_done.html"),
        name="password_reset_done",
    ),
    path(
        "reset/<uidb64>/<token>/",
        auth_views.PasswordResetConfirmView.as_view(template_name="password_reset_confirm.html"),
        name="password_reset_confirm",
    ),
    path(
        "reset/done/",
        auth_views.PasswordResetCompleteView.as_view(template_name="password_reset_complete.html"),
        name="password_reset_complete",
    ),
]
