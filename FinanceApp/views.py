import os
import pytz
from decimal import Decimal, InvalidOperation
from datetime import datetime, timezone as dt_timezone

from urllib.parse import unquote

from django.conf import settings
from django.shortcuts import redirect
from django.http import FileResponse, Http404
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.contrib.auth import logout
from django.contrib.auth.hashers import make_password, check_password

from rest_framework import viewsets, status, parsers
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.decorators import (
    action, api_view, authentication_classes, permission_classes
)
from rest_framework.authentication import SessionAuthentication

from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import TokenError

import cloudinary.uploader

from FinanceApp.serializers import RegisterSerializer, LoginUserSerializer, UserSerializer, CategorySerializer, \
    TransactionsSerializer, ChangePasswordSerializer, RecurringTransactionsSerializer, SettingsSerializer
from FinanceApp.models import Users, Categories, Transactions, RevokedAccessToken, RecurringTransactions, Settings


def logout_then_redirect(request):
    logout(request)
    return redirect('/api/')


# ViewSet xử lý đăng ký tài khoản người dùng mới
class RegisterViewSet(viewsets.ViewSet):
    permission_classes = [AllowAny]

    def create(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Regiter successful."}, status=status.HTTP_201_CREATED)

        return Response({
            "errorCode": "400_INVALID_INPUT",
            "errorMessage": "Invalid data field in User.",
            "errorData": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


# ViewSet xử lý đăng nhập, trả về access/refresh token
class LoginViewSet(viewsets.ViewSet):
    permission_classes = [AllowAny]

    def create(self, request):
        if request.user.is_authenticated:
            return Response({
                "errorCode": "403_ALREADY_AUTHENTICATED",
                "errorMessage": "You are already logged in. Cannot login again.",
                "errorData": None
            }, status=status.HTTP_403_FORBIDDEN)

        serializer = LoginUserSerializer(data=request.data)
        if serializer.is_valid():
            return Response(serializer.validated_data, status=status.HTTP_200_OK)
        return Response({
            'errorCode': "400_INVALID_INPUT",
            'errorMessage': "Invalid login credentials.",
            'errorData': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


# ViewSet xử lý đăng xuất người dùng, vô hiệu hóa refresh token
class LogoutViewSet(viewsets.ViewSet):

    def create(self, request):
        try:
            # Lấy access token từ Authorization header
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return Response(
                    {"detail": "Missing or invalid Authorization header."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            access_token = auth_header.split(' ')[1]  # Lấy token từ "Bearer xxx"
            refresh_token = request.data.get("refresh")

            if not refresh_token:
                return Response(
                    {"detail": "Missing refresh token."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Thu hồi refresh token
            refresh = RefreshToken(refresh_token)
            refresh.blacklist()

            # Thu hồi access token (lưu jti vào DB)
            access = AccessToken(access_token)
            jti = access['jti']
            exp = access['exp']
            expires_at = datetime.fromtimestamp(exp, tz=dt_timezone.utc)

            RevokedAccessToken.objects.create(
                jti=jti,
                expires_at=expires_at
            )

            return Response({"detail": "Logout successful."}, status=status.HTTP_200_OK)

        except TokenError:
            return Response({
                "errorCode": "400_INVALID_REFRESH_TOKEN",
                "errorMessage": "Invalid or expired refresh token.",
                "errorData": None
            }, status=status.HTTP_400_BAD_REQUEST)


# ViewSet xử lý thông tin tài khoản người dùng đã đăng nhập
class UserViewSet(viewsets.ViewSet):

    @action(detail=False, methods=['put'], url_path='change-password')
    def change_password(self, request):
        serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            user = request.user
            new_password = serializer.validated_data['new_password']
            user.password_hash = make_password(new_password)
            user.save()
            return Response({'detail': 'Password changed successfully.'}, status=status.HTTP_200_OK)

        return Response({
            "errorCode": "400_INVALID_INPUT",
            "errorMessage": "Invalid password change request.",
            "errorData": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['get', 'put'], url_path='profile')
    def profile(self, request):
        user = request.user

        if request.method == 'GET':
            serializer = UserSerializer(user)
            return Response(serializer.data, status=status.HTTP_200_OK)

        elif request.method == 'PUT':
            serializer = UserSerializer(user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({'detail': 'Profile updated successfully.'}, status=status.HTTP_200_OK)

            return Response({
                "errorCode": "400_INVALID_INPUT",
                "errorMessage": "Invalid input data.",
                "errorData": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)


class CategoryViewSet(viewsets.ViewSet):
    serializer = CategorySerializer(Categories)

    def list(self, request):
        queryset = Categories.objects.filter(user_id=request.user, active=True)

        # Filter by parent_category_id
        parent_id = request.query_params.get('parent_id')
        if parent_id is not None:
            queryset = queryset.filter(parent_category_id=parent_id)

        # Filter by keyword in name
        keyword = request.query_params.get('keyword')
        if keyword:
            queryset = queryset.filter(name__icontains=keyword)
        print(Categories.objects.all().values("id", "user_id", "active"))
        serializer = CategorySerializer(queryset, many=True)
        return Response(serializer.data)

    def create(self, request):
        data = request.data.copy()
        data['user_id'] = request.user.id
        serializer = CategorySerializer(data=data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({'detail': 'Create Successful!'}, status.HTTP_201_CREATED)
        return Response({
            "errorCode": "400_INVALID_CATEGORY",
            "errorMessage": "Category creation failed.",
            "errorData": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        try:
            category = Categories.objects.get(pk=pk, user_id=request.user.id)
            serializer = CategorySerializer(category)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Categories.DoesNotExist:
            return Response({
                "errorCode": "404_CATEGORY_NOT_FOUND",
                "errorMessage": "Category not found or does not belong to the current user.",
                "errorData": {"pk": pk}
            }, status=status.HTTP_404_NOT_FOUND)

    # update category
    def update(self, request, pk=None):
        try:
            category = Categories.objects.get(pk=pk, user_id=request.user.id)
        except Categories.DoesNotExist:
            return Response(
                {"detail": "Category not found or does not belong to the current user."},
                status=status.HTTP_404_NOT_FOUND
            )

        serializer = CategorySerializer(category, data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({'detail': 'Update Successful!'}, status=status.HTTP_200_OK)

        return Response({
            "errorCode": "400_INVALID_CATEGORY_UPDATE",
            "errorMessage": "Update failed due to invalid data.",
            "errorData": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    # delete category
    def destroy(self, request, pk=None):
        try:
            category = Categories.objects.get(pk=pk, user_id=request.user.id)
        except Categories.DoesNotExist:
            return Response({
                "errorCode": "404_CATEGORY_NOT_FOUND",
                "errorMessage": "Category not found or does not belong to the current user.",
                "errorData": {"pk": pk}
            }, status=status.HTTP_404_NOT_FOUND)
        # update category_id = NULL
        category.transactions_set.update(category_id=None)
        category.recurringtransactions_set.update(category_id=None)

        category.delete()

        return Response({"detail": "Category deleted successfully."}, status=status.HTTP_204_NO_CONTENT)


# Transactions ViewSet
class TransactionsViewSet(viewsets.ViewSet):
    serializer = TransactionsSerializer(Transactions)

    # Get all list Transactions
    def list(self, request):
        queryset = Transactions.objects.filter(user_id=request.user.id)

        type_trans = request.query_params.get('type_trans')
        if type_trans is not None:
            queryset = queryset.filter(type=type_trans)

        cate_id = request.query_params.get('cate_id')
        if cate_id is not None:
            queryset = queryset.filter(category_id=cate_id)

        amount_min = request.query_params.get('amount_min')
        amount_max = request.query_params.get('amount_max')
        if amount_min is not None and amount_max is not None:
            # Invalid format
            try:
                amount_min = Decimal(amount_min)
                amount_max = Decimal(amount_max)
                if amount_min <= amount_max:
                    queryset = queryset.filter(amount__gte=amount_min, amount__lte=amount_max)
            except InvalidOperation:
                return Response({
                    "errorCode": "400_INVALID_DECIMAL",
                    "errorMessage": "Invalid amount format.",
                    "errorData": {
                        "amount_min": amount_min,
                        "amount_max": amount_max
                    }
                }, status=status.HTTP_400_BAD_REQUEST)
        serializer = TransactionsSerializer(queryset, many=True)
        return Response(serializer.data)

    def create(self, request):
        data = request.data.copy()
        uploaded_file = request.FILES.get('attachment_url')

        if uploaded_file:
            try:
                user_id = request.user.id
                user_directory = f'attachments/user_{user_id}'
                if not default_storage.exists(user_directory):
                    os.makedirs(os.path.join(settings.MEDIA_ROOT, user_directory))

                file_name = default_storage.save(
                    os.path.join(user_directory, uploaded_file.name),
                    ContentFile(uploaded_file.read())
                )

                file_url = os.path.join(settings.MEDIA_URL, file_name)
                data['attachment_url'] = file_url
            except Exception as e:
                return Response({
                    "errorCode": "400_UPLOAD_ERROR",
                    "errorMessage": "Failed to upload file.",
                    "errorData": str(e)
                }, status=status.HTTP_400_BAD_REQUEST)

        serializer = TransactionsSerializer(data=data, context={'request': request})
        if serializer.is_valid():
            serializer.save(user_id=request.user)
            return Response({'detail': 'Created successfully!'}, status=status.HTTP_201_CREATED)

        return Response({
            "errorCode": "400_INVALID_TRANSACTION",
            "errorMessage": "Transaction creation failed due to invalid data.",
            "errorData": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        try:
            transaction = Transactions.objects.get(pk=pk, user_id=request.user.id)
            serializer = TransactionsSerializer(transaction)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Transactions.DoesNotExist:
            return Response(
                {"detail": "Transaction not found or does not belong to the current user."},
                status=status.HTTP_404_NOT_FOUND
            )

    def update(self, request, pk=None):
        try:
            transaction = Transactions.objects.get(pk=pk, user_id=request.user.id)
        except Transactions.DoesNotExist:
            return Response({
                "errorCode": "404_TRANSACTION_NOT_FOUND",
                "errorMessage": "Transaction not found or does not belong to the current user.",
                "errorData": {"pk": pk}
            }, status=status.HTTP_404_NOT_FOUND)

        serializer = TransactionsSerializer(transaction, data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({'detail': 'Update Successful!'}, status=status.HTTP_200_OK)

        return Response({
            "errorCode": "400_INVALID_TRANSACTION_UPDATE",
            "errorMessage": "Update failed due to invalid data.",
            "errorData": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        try:
            transaction = Transactions.objects.get(pk=pk, user_id=request.user.id)
        except Transactions.DoesNotExist:
            return Response({
                "errorCode": "404_TRANSACTION_NOT_FOUND",
                "errorMessage": "Transaction not found or does not belong to the current user.",
                "errorData": {"pk": pk}
            }, status=status.HTTP_404_NOT_FOUND)
        transaction.delete()
        return Response({"detail": "Transaction deleted successfully!"}, status=status.HTTP_204_NO_CONTENT)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def serve_protected_media(request, path):
    decoded_path = unquote(path)
    file_path = os.path.join(settings.MEDIA_ROOT, decoded_path)

    if not os.path.isfile(file_path):
        return Response({
            "errorCode": "404_FILE_NOT_FOUND",
            "errorMessage": "File không tồn tại hoặc đã bị xoá.",
            "errorData": decoded_path
        }, status=status.HTTP_404_NOT_FOUND)

    relative_path = decoded_path.lstrip('/')

    transaction = Transactions.objects.filter(
        user_id=request.user.id,
        attachment_url__icontains=relative_path
    ).first()

    if not transaction:
        return Response({
            "errorCode": "403_FORBIDDEN",
            "errorMessage": "Bạn không có quyền truy cập file này.",
            "errorData": decoded_path
        }, status=status.HTTP_403_FORBIDDEN)

    return FileResponse(open(file_path, 'rb'))


class RecurringTransactionsViewSet(viewsets.ViewSet):

    def list(self, request):
        queryset = RecurringTransactions.objects.filter(user_id=request.user.id, active=True)

        # Filter by type
        trans_type = request.query_params.get('type')
        if trans_type:
            queryset = queryset.filter(type=trans_type)

        # Filter by category
        category_id = request.query_params.get('category_id')
        if category_id:
            queryset = queryset.filter(category_id=category_id)

        # Filter by amount range
        amount_min = request.query_params.get('amount_min')
        amount_max = request.query_params.get('amount_max')
        try:
            if amount_min and amount_max:
                min_val = Decimal(amount_min)
                max_val = Decimal(amount_max)
                if min_val <= max_val:
                    queryset = queryset.filter(amount__gte=min_val, amount__lte=max_val)
                else:
                    return Response({
                        "errorCode": "400_INVALID_RANGE",
                        "errorMessage": "`amount_min` must be less than or equal to `amount_max`.",
                        "errorData": {
                            "amount_min": amount_min,
                            "amount_max": amount_max
                        }
                    }, status=status.HTTP_400_BAD_REQUEST)
        except InvalidOperation:
            return Response({
                "errorCode": "400_INVALID_DECIMAL",
                "errorMessage": "Invalid amount format.",
                "errorData": {
                    "amount_min": amount_min,
                    "amount_max": amount_max
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer = RecurringTransactionsSerializer(queryset, many=True)
        return Response(serializer.data)

    def create(self, request):
        data = request.data.copy()
        print(request.data)
        serializer = RecurringTransactionsSerializer(data=data, context={'request': request})
        if serializer.is_valid():
            serializer.save(user_id=request.user)
            return Response({'detail': 'Recurring transaction created successfully!'}, status=status.HTTP_201_CREATED)

        return Response({
            "errorCode": "400_INVALID_RECURRING_TRANSACTION",
            "errorMessage": "Recurring transaction creation failed.",
            "errorData": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        try:
            item = RecurringTransactions.objects.get(pk=pk, user_id=request.user.id)
        except RecurringTransactions.DoesNotExist:
            return Response({
                "errorCode": "404_RECURRING_TRANSACTION_NOT_FOUND",
                "errorMessage": "Recurring transaction not found.",
                "errorData": {"pk": pk}
            }, status=status.HTTP_404_NOT_FOUND)

        serializer = RecurringTransactionsSerializer(item)
        return Response(serializer.data)

    def update(self, request, pk=None):
        try:
            item = RecurringTransactions.objects.get(pk=pk, user_id=request.user.id)
        except RecurringTransactions.DoesNotExist:
            return Response({
                "errorCode": "404_RECURRING_TRANSACTION_NOT_FOUND",
                "errorMessage": "Recurring transaction not found.",
                "errorData": {"pk": pk}
            }, status=status.HTTP_404_NOT_FOUND)

        serializer = RecurringTransactionsSerializer(item, data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({'detail': 'Recurring transaction updated successfully!'}, status=status.HTTP_200_OK)

        return Response({
            "errorCode": "400_INVALID_RECURRING_TRANSACTION_UPDATE",
            "errorMessage": "Update failed due to invalid data.",
            "errorData": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        try:
            item = RecurringTransactions.objects.get(pk=pk, user_id=request.user.id)
        except RecurringTransactions.DoesNotExist:
            return Response({
                "errorCode": "404_RECURRING_TRANSACTION_NOT_FOUND",
                "errorMessage": "Recurring transaction not found.",
                "errorData": {"pk": pk}
            }, status=status.HTTP_404_NOT_FOUND)

        item.delete()
        return Response({'detail': 'Recurring transaction deleted successfully!'}, status=status.HTTP_204_NO_CONTENT)


class SettingsViewSet(viewsets.ViewSet):
    def list(self, request):
        try:
            settings = Settings.objects.filter(user_id=request.user).first()
            if not settings:
                return Response({
                    "errorCode": "404_SETTINGS_NOT_FOUND",
                    "errorMessage": "Settings not found for current user.",
                    "errorData": {"user_id": request.user.id}
                }, status=status.HTTP_404_NOT_FOUND)

            serializer = SettingsSerializer(settings)
            return Response(serializer.data)

        except Exception as e:
            return Response({
                "errorCode": "500_INTERNAL_ERROR",
                "errorMessage": "An unexpected error occurred.",
                "errorData": {"detail": str(e)}
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def create(self, request):
        if Settings.objects.filter(user_id=request.user).exists():
            return Response({
                "errorCode": "400_SETTINGS_EXISTS",
                "errorMessage": "Settings already exist for this user.",
                "errorData": {"user_id": request.user.id}
            }, status=status.HTTP_400_BAD_REQUEST)

        data = request.data.copy()
        data['user_id'] = request.user.id
        serializer = SettingsSerializer(data=data, context={'request': request})
        if serializer.is_valid():
            serializer.save(user_id=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response({
            "errorCode": "400_INVALID_SETTINGS_CREATE",
            "errorMessage": "Invalid settings data.",
            "errorData": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        try:
            settings = Settings.objects.filter(user_id=request.user).first()
            if not settings:
                return Response({
                    "errorCode": "404_SETTINGS_NOT_FOUND",
                    "errorMessage": "Settings not found for current user.",
                    "errorData": {"user_id": request.user.id}
                }, status=status.HTTP_404_NOT_FOUND)

            data = request.data.copy()
            data['user_id'] = request.user.id
            serializer = SettingsSerializer(settings, data=data, partial=True, context={'request': request})
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)

            return Response({
                "errorCode": "400_INVALID_SETTINGS_UPDATE",
                "errorMessage": "Invalid update data.",
                "errorData": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                "errorCode": "500_INTERNAL_ERROR",
                "errorMessage": "An unexpected error occurred while updating settings.",
                "errorData": {"detail": str(e)}
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
