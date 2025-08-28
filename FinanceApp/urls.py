from django.shortcuts import redirect
from django.urls import path, include
from rest_framework import routers
from . import views, admin
from rest_framework_simplejwt.views import TokenRefreshView

r = routers.DefaultRouter()
r.register('register', views.RegisterViewSet, 'register')
r.register('login', views.LoginViewSet, 'login')
r.register('logout', views.LogoutViewSet, 'logout')
r.register('user', views.UserViewSet, 'user')
r.register('category', views.CategoryViewSet, 'category')
r.register('transaction', views.TransactionsViewSet, 'transaction')
r.register('recurring-transaction', views.RecurringTransactionsViewSet, 'recurring-transaction')
r.register('setting', views.SettingsViewSet, 'setting')

urlpatterns = [
    path('', include(r.urls)),
    path('token/refresh/', TokenRefreshView.as_view()),
    path('transaction/<path:path>', views.serve_protected_media, name='serve-protected-media'),
]

