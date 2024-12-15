# apps/api/views.py
from django.http import JsonResponse

def api_view(request):
    data = {
        "message": "API is working"
    }
    return JsonResponse(data)

