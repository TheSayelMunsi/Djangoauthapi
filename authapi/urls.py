from django.contrib import admin
from django.urls import path,include
from authapi.views import UserLoginView
from authapi.views import UserRegistrationView,UserProfileView,UserChangePasswordView,SendPasswordResetEmailView,UserResetPasswordView

urlpatterns = [
    path('register/',UserRegistrationView.as_view(),name='register'),
    path('Login/',UserLoginView.as_view(),name='Login'),
    path('profile/',UserProfileView.as_view(),name='profile'),
    path('change/',UserChangePasswordView.as_view(),name='change'),
    path('resetpass/',SendPasswordResetEmailView.as_view(),name='resetpass'),
    path('linkreset/<uid>/<token>/',UserResetPasswordView.as_view(),name='linkreset')

    
]
