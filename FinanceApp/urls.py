from django.shortcuts import redirect
from django.urls import path, include
from rest_framework import routers
from . import views, admin

r = routers.DefaultRouter()
r.register('register', views.RegisterViewSet, 'register')
r.register('login', views.LoginViewSet, 'login')
r.register('logout', views.LogoutViewSet, 'logout')
r.register('user', views.UserViewSet, 'user')
r.register('category', views.CategoryViewSet, 'category')

urlpatterns = [
    path('', include(r.urls))
]
