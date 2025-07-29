import pytz
import cloudinary.uploader
import os
from rest_framework import parsers
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework import viewsets, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import action
from rest_framework.response import Response
from decimal import Decimal, InvalidOperation
from django.conf import settings
from django.utils import timezone
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from datetime import datetime, timezone as dt_timezone
from django.contrib.auth.hashers import make_password, check_password
from FinanceApp.serializers import RegisterSerializer, LoginUserSerializer, UserSerializer, CategorySerializer, \
    TransactionsSerializer, ChangePasswordSerializer
from FinanceApp.models import Users, Categories, Transactions, RevokedAccessToken


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
    parser_classes = [parsers.MultiPartParser, parsers.FormParser]

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
                file_name = default_storage.save(
                    f'attachments/{uploaded_file.name}',
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
