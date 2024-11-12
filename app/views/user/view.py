from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json
from . import bussiness


@csrf_exempt
def signup(request):
    if not request.method == 'POST':
        return JsonResponse({"message": "Method not allowed"}, status=400)
    try:
        data = json.loads(request.body)
        if not data:
            return JsonResponse({"message": "Validation error"}, status=400)
        validated_data = bussiness.validate_data_signup(data=data)
        if not validated_data:
            return JsonResponse({"message": "Validation error"}, status=400)
        user = bussiness.create_user_profile(data=validated_data)
        return JsonResponse(user, status=201)
    except:
        return JsonResponse({'message': 'Server Error'}, status=500)


@csrf_exempt
@bussiness.jwt_required
def update_profile(request, id):
    if not request.method == 'PATCH':
        return JsonResponse({"message": "Method not allowed"}, status=400)
    try:
        data = json.loads(request.body)
        validated_data = bussiness.validate_data_update(data=data, id=id)
        if not validated_data:
            return JsonResponse({"message": "User doesnot exists"}, status=400)
        updated_user = bussiness.update_user_profile(validated_data, id)
        return JsonResponse(updated_user, status=201)
    except:
        return JsonResponse({'message': 'Server Error'}, status=500)


@csrf_exempt
@bussiness.jwt_required
def get_user_profile_by_id(request, id):
    if not request.method == 'GET':
        return JsonResponse({"message": "Method not allowed"}, status=400)
    try:
        user = bussiness.fetch_user(id=id)
        if not user:
            return JsonResponse({"message": "User doesnot exists"}, status=404)
        return JsonResponse(user, status=200)
    except:
        return JsonResponse({'message': 'Server Error'}, status=500)


@csrf_exempt
@bussiness.jwt_required
def get_user_profile_by_username(request, username):
    if not request.method == 'GET':
        return JsonResponse({"message": "Method not allowed"}, status=400)
    try:
        user = bussiness.fetch_user(username=username)
        if not user:
            return JsonResponse({"message": "User doesnot exists"}, status=404)
        return JsonResponse(user, status=200)
    except:
        return JsonResponse({'message': 'Server Error'}, status=500)


@csrf_exempt
@bussiness.jwt_required
def delete_user(request, id):
    if not request.method == 'DELETE':
        return JsonResponse({"message": "Method not allowed"}, status=400)
    try:
        deleted = bussiness.try_delete(id)
        if not deleted:
            return JsonResponse({"message": "User doesnot exists"}, status=404)
        return JsonResponse({'message': 'User deleted'}, status=204)
    except:
        return JsonResponse({'message': 'Server Error'}, status=500)


@csrf_exempt
def login(request):
    if not request.method == 'POST':
        return JsonResponse({"message": "Method not allowed"}, status=400)
    try:
        data = json.loads(request.body)
        validated_data = bussiness.validate_data_login(data=data)
        if not validated_data:
            return JsonResponse({"message": "Validation error"}, status=400)
        user = bussiness.authenticate_user(data=validated_data)
        if not user:
            return JsonResponse({"message": "Invalid credentials"}, status=401)
        return JsonResponse({"message": "Login successful", "user": user}, status=200)
    except Exception as e:
        print(e)
        return JsonResponse({'message': 'Server Error'}, status=500)
