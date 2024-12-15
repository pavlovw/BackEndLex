from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('register/', views.register, name='register'),
    path('register/complete/', views.registration_complete, name='registration_complete'),
    path('logout/', views.logout_view, name='logout'),
    # path('account/', views.account, name='account'),
]

