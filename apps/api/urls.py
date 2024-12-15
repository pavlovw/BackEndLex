# apps/api/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('', views.api_view, name='api_view'),  # Aquí puedes poner el endpoint específico
]