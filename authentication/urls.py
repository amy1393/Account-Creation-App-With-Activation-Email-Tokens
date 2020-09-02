from django.contrib import admin
from django.urls import path
from . import views

urlpatterns = [
    path('signupuser/',views.signupuser,name='signupuser'),
    path('loginuser/',views.loginnew,name='loginuser'),
    path('activate/<uidb64>/<token>/', views.activate, name='activate'),]