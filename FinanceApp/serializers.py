import re
import uuid
import pytz
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from FinanceApp.models import Users, Categories
from django.contrib.auth.hashers import make_password, check_password


# Serializer dùng để hiển thị thông tin người dùng (GET /api/user/profile/)
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['id', 'email', 'name', 'timezone']


# Serializer xử lý đăng ký tài khoản mới
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = Users
        fields = ['name', 'email', 'password', 'timezone']

    def validate_email(self, value):
        if Users.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already in use.")
        return value

    def validate_timezone(self, value):
        if value not in pytz.all_timezones:
            raise serializers.ValidationError("Invalid timezone.")
        return value

    """
    Mật khẩu phải đủ mạnh:
    - Tối thiểu 8 ký tự
    - Có ít nhất 1 chữ cái
    - Có ít nhất 1 chữ số
    - Có ít nhất 1 ký tự đặc biệt
    """

    def validate_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters.")

        # Phải có ít nhất một chữ cái
        if not re.search(r'[A-Za-z]', value):
            raise serializers.ValidationError("Password must contain at least one letter.")

        # Phải có ít nhất một chữ số
        if not re.search(r'\d', value):
            raise serializers.ValidationError("Password must contain at least one digit.")

        # Phải có ít nhất một ký tự đặc biệt
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            raise serializers.ValidationError("Password must contain at least one special character.")

        return value

    # Hash password
    def create(self, validated_data):
        validated_data['username'] = validated_data['email'].split('@')[0] + '_' + str(uuid.uuid4())[:6]
        raw_password = validated_data.pop('password')
        validated_data['password_hash'] = make_password(raw_password)
        return Users.objects.create(**validated_data)


# Serializer xử lý đăng nhập (login)
class LoginUserSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        """
        Xác thực email + mật khẩu:
        - Kiểm tra người dùng tồn tại
        - Kiểm tra mật khẩu đúng
        - Kiểm tra tài khoản active
        - Trả về access và refresh token
        """

        try:
            user = Users.objects.get(email=email)
        except Users.DoesNotExist:
            raise serializers.ValidationError("Invalid email or password.")

        # Kiểm tra password
        if not check_password(password, user.password_hash):
            raise serializers.ValidationError("Invalid email or password.")

        if not user.is_active:
            raise serializers.ValidationError("User account is disabled.")

        # Trả về access và refresh token
        refresh = RefreshToken.for_user(user)
        return {
            'access': str(refresh.access_token),
            'refresh': str(refresh),
        }


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Categories
        fields = '__all__'

    def validate(self, data):
        user = self.context['request'].user
        parent = data.get('parent_category_id')
        current_instance = self.instance

        if parent:
            # So sánh user ID của parent với user hiện tại
            if parent.user_id_id != user.id:
                raise serializers.ValidationError({
                    'parent_category_id': 'Category does not belong to current user.'
                })
            if parent.id == current_instance.id and current_instance:
                raise serializers.ValidationError({
                    'parent_category_id': 'A category cannot be its own parent.'
                })
        return data
