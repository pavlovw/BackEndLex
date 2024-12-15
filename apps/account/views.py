from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate, login, logout
from .forms import CustomUserCreationForm, CustomAuthenticationForm
from rest_framework.permissions import AllowAny
import jwt
import datetime
from django.conf import settings

class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        form = CustomUserCreationForm(request.data)
        if form.is_valid():
            user = form.save()
            return Response({
                'message': '¡Registro exitoso!',
                'user_id': user.id
            }, status=status.HTTP_201_CREATED)
        else:
            # Formatear errores de forma más API-friendly
            errors = {}
            for field, error_list in form.errors.items():
                errors[field] = list(error_list)
            
            return Response({
                'message': 'Error en el registro',
                'errors': errors
            }, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        form = CustomAuthenticationForm(request, data=request.data)
        if form.is_valid():
            email = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, email=email, password=password)
            
            if user is not None:
                login(request, user)
                
                # Generar token JWT
                payload = {
                    'user_id': user.id,
                    'email': user.email,
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
                }
                token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
                
                return Response({
                    'message': 'Inicio de sesión exitoso',
                    'token': token,
                    'user_id': user.id,
                    'email': user.email
                }, status=status.HTTP_200_OK)
            
            return Response({
                'message': 'Credenciales inválidas'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        return Response({
            'message': 'Formulario inválido',
            'errors': form.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    def post(self, request):
        logout(request)
        return Response({
            'message': 'Sesión cerrada exitosamente'
        }, status=status.HTTP_200_OK)