import pytz
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework import viewsets, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import action
from rest_framework.response import Response
from django.contrib.auth.hashers import make_password, check_password
from FinanceApp.serializers import RegisterSerializer, LoginUserSerializer, UserSerializer, CategorySerializer
from FinanceApp.models import Users, Categories


# ViewSet xử lý đăng ký tài khoản người dùng mới
class RegisterViewSet(viewsets.ViewSet):
    permission_classes = [AllowAny]

    def create(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Regiter successful."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# ViewSet xử lý đăng nhập, trả về access/refresh token
class LoginViewSet(viewsets.ViewSet):
    permission_classes = [AllowAny]

    def create(self, request):
        serializer = LoginUserSerializer(data=request.data)
        if serializer.is_valid():
            return Response(serializer.validated_data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# ViewSet xử lý đăng xuất người dùng, vô hiệu hóa refresh token
class LogoutViewSet(viewsets.ViewSet):

    def create(self, request):
        try:
            refresh_token = request.data.get("refresh")
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"detail": "Logout successful."}, status=status.HTTP_200_OK)
        except TokenError:
            return Response({"detail": "Invalid or expired refresh token."}, status=status.HTTP_400_BAD_REQUEST)


# ViewSet xử lý thông tin tài khoản người dùng đã đăng nhập
class UserViewSet(viewsets.ViewSet):
    """
    GET /api/user/profile/     → Lấy thông tin người dùng hiện tại
    PUT /api/user/profile/     → Cập nhật tên và timezone của người dùng
    """

    @action(detail=False, methods=['get', 'put'], url_path='profile')
    def profile(self, request):
        user = request.user

        if request.method == 'GET':
            serializer = UserSerializer(user)
            return Response(serializer.data, status=status.HTTP_200_OK)

        elif request.method == 'PUT':
            name = request.data.get('name')
            timezone = request.data.get('timezone')

            if timezone and timezone not in pytz.all_timezones:
                return Response({'timezone': 'Invalid timezone.'}, status=status.HTTP_400_BAD_REQUEST)

            if name:
                user.name = name
            if timezone:
                user.timezone = timezone
            user.save()
            return Response({'detail': 'Profile updated successfully.'}, status=status.HTTP_200_OK)

    @action(detail=False, methods=['put'], url_path='change-password')
    def change_password(self, request):
        user = request.user
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')

        """
        PUT /api/user/change-password/
        Đổi mật khẩu tài khoản:
        - Kiểm tra mật khẩu cũ đúng không
        - Mật khẩu mới không được trùng mật khẩu cũ
        - Kiểm tra độ dài tối thiểu
        """

        if not old_password or not new_password:
            return Response({'detail': 'Both old and new passwords are required.'}, status=status.HTTP_400_BAD_REQUEST)

        if not check_password(old_password, user.password_hash):
            return Response({'old_password': 'Old password is incorrect.'}, status=status.HTTP_400_BAD_REQUEST)

        if new_password == old_password:
            return Response({'new_password': 'New password must be different from the old password.'},
                            status=status.HTTP_400_BAD_REQUEST)

        if len(new_password) < 8:
            return Response({'new_password': 'New password must be at least 8 characters.'},
                            status=status.HTTP_400_BAD_REQUEST)

        user.password_hash = make_password(new_password)
        user.save()
        return Response({'detail': 'Password changed successfully.'}, status=status.HTTP_200_OK)


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

        serializer = CategorySerializer(queryset, many=True)
        return Response(serializer.data)

    def create(self, request):
        data = request.data.copy()
        data['user_id'] = request.user.id
        serializer = CategorySerializer(data=data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({'detail': 'Create Successful!'}, status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        try:
            category = Categories.objects.get(pk=pk, user_id=request.user.id)
            serializer = CategorySerializer(category)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Categories.DoesNotExist:
            return Response(
                {"detail": "Category not found or does not belong to the current user."},
                status=status.HTTP_404_NOT_FOUND
            )

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

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        try:
            category = Categories.objects.get(pk=pk, user_id=request.user.id)
        except Categories.DoesNotExist:
            return Response(
                {"detail": "Category not found or does not belong to the current user."},
                status=status.HTTP_404_NOT_FOUND
            )
        # update category_id = NULL
        category.transactions_set.update(category_id=None)
        category.recurringtransactions_set.update(category_id=None)

        category.delete()

        return Response({"detail": "Category deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
