from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json

from app.views.user.bussiness import jwt_required
from . import business
from django.http.multipartparser import MultiPartParser


@csrf_exempt
@jwt_required
def create_post(request):
    if not request.method == 'POST':
        return JsonResponse({"message": "Method not allowed"}, status=400)
    try:
        breakpoint()
        message, status = business.handle_create_post(request.POST)
        return JsonResponse(message, status=status)
    except:
        return JsonResponse({'message': 'Server Error'}, status=500)


@csrf_exempt
@jwt_required
def update_post(request, id):
    if not request.method == 'PATCH':
        return JsonResponse({"message": "Method not allowed"}, status=400)
    # https://stackoverflow.com/a/64022212
    query_dict, multi_value_dict = MultiPartParser(
        request.META, request, request.upload_handlers
    ).parse()
    try:
        message, status = business.handle_update_post(query_dict, multi_value_dict, id)
        return JsonResponse(message, status=status)
    except:
        return JsonResponse({'message': 'Server Error'}, status=500)


@csrf_exempt
@jwt_required
def get_all_posts(request):
    if not request.method == 'GET':
        return JsonResponse({"message": "Method not allowed"}, status=400)
    try:
        message, status = business.handle_get_all_posts()
        return JsonResponse(message, status=status, safe=False)
    except:
        return JsonResponse({'message': 'Server Error'}, status=500)


@csrf_exempt
@jwt_required
def get_post_by_id(request, id):
    if not request.method == 'GET':
        return JsonResponse({"message": "Method not allowed"}, status=400)
    try:
        message, status = business.handle_get_post(id)
        return JsonResponse(message, status=status)
    except:
        return JsonResponse({'message': 'Server Error'}, status=500)


@csrf_exempt
@jwt_required
def get_posts_by_username(request, username):
    if not request.method == 'GET':
        return JsonResponse({"message": "Method not allowed"}, status=400)
    try:
        message, status = business.handle_get_users_post(username)
        return JsonResponse(message, status=status, safe=False)
    except:
        return JsonResponse({'message': 'Server Error'}, status=500)


@csrf_exempt
@jwt_required
def delete_post(request, id):
    if not request.method == 'DELETE':
        return JsonResponse({"message": "Method not allowed"}, status=400)
    try:
        message, status = business.handle_delete(id)
        return JsonResponse(message, status=status)
    except:
        return JsonResponse({'message': 'Server Error'}, status=500)


@csrf_exempt
@jwt_required
def like_post(request, id):
    if not request.method == 'POST':
        return JsonResponse({"message": "Method not allowed"}, status=400)
    try:
        data = json.loads(request.body)
        message, status = business.handle_like_post(id, data)
        return JsonResponse(message, status=status)
    except:
        return JsonResponse({'message': 'Server Error'}, status=500)


@csrf_exempt
@jwt_required
def comment_post(request, id):
    if not request.method == 'POST':
        return JsonResponse({"message": "Method not allowed"}, status=400)
    try:
        data = json.loads(request.body)
        message, status = business.handle_comment_post(id, data)
        return JsonResponse(message, status=status)
    except:
        return JsonResponse({'message': 'Server Error'}, status=500)
