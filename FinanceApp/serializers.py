import re
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from FinanceApp.models import Users
from django.contrib.auth.hashers import make_password, check_password
import pytz


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
        raw_password = validated_data.pop('password')
        hashed_password = make_password(raw_password)
        validated_data['password_hash'] = hashed_password
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
