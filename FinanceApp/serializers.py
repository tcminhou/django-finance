import re
import uuid
import pytz
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from FinanceApp.models import Users, Categories
from django.contrib.auth.hashers import make_password, check_password


# Serializer dùng để hiển thị thông tin người dùng (GET /api/user/profile/)
class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = Users
        fields = ['id', 'email', 'name', 'timezone', 'password']

    def validate_timezone(self, value):
        import pytz
        if value not in pytz.all_timezones:
            raise serializers.ValidationError("Invalid timezone.")
        return value

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        if password:
            instance.password = make_password(password)

        instance.save()
        return instance


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
        validated_data['password'] = make_password(raw_password)
        return Users.objects.create(**validated_data)


# Serializer xử lý đăng nhập (login)
class LoginUserSerializer(serializers.Serializer):
    email = serializers.EmailField(
        error_messages={
            "blank": "Email is blank.",
            "required": "Email is required.",
            "invalid": "Enter a valid email address."
        }
    )
    password = serializers.CharField(
        write_only=True,
        error_messages={
            "blank": "Password is blank.",
            "required": "Password is required."
        }
    )

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

            # Check out password customer user
        if not check_password(password, user.password):
            raise serializers.ValidationError({"Incorrect password": "Incorrect password please re-enter."})

        if not user.is_active:
            raise serializers.ValidationError("User account is disabled.")

        # Trả về access và refresh token
        refresh = RefreshToken.for_user(user)
        return {
            'message': "Login successful.",
            'access': str(refresh.access_token),
            'refresh': str(refresh),
        }


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)

    def validate_new_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters.")
        if not re.search(r'[A-Za-z]', value):
            raise serializers.ValidationError("Password must contain at least one letter.")
        if not re.search(r'\d', value):
            raise serializers.ValidationError("Password must contain at least one digit.")
        if not re.search(r'[^A-Za-z0-9]', value):
            raise serializers.ValidationError("Password must contain at least one special character.")
        return value

    def validate(self, attrs):
        user = self.context['request'].user
        old_password = attrs.get('old_password')
        new_password = attrs.get('new_password')

        if old_password == new_password:
            raise serializers.ValidationError({
                'new_password': 'New password must be different from the old password.'
            })

        if not check_password(old_password, user.password):
            raise serializers.ValidationError({
                'old_password': 'Old password is incorrect.'
            })

        return attrs


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

<< << << < Updated
upstream
if parent.id == current_instance.id and current_instance:
== == == =
# check out cate id to prove not itself
if current_instance and parent.id == current_instance.id:
>> >> >> > Stashed
changes
raise serializers.ValidationError({
    'parent_category_id': 'A category cannot be its own parent.'
})
return data
<< << << < Updated
upstream
== == == =

class TransactionsSerializer(serializers.ModelSerializer):
    user_id = serializers.PrimaryKeyRelatedField(read_only=True)
    active = serializers.BooleanField(default=True)

    class Meta:
        model = Transactions
        fields = '__all__'

    def validate(self, data):
        request = self.context.get('request')
        amount = data.get('amount')
        trans_date = data.get('date')
        category = data.get('category_id')

        # amount > 0
        if amount is None or amount <= Decimal('0.00'):
            raise serializers.ValidationError({"amount": "Amount must be greater than 0."})

        # date not in future
        if trans_date and trans_date > date.today():
            raise serializers.ValidationError({"date": "Date cannot be in the future."})

        # category belongs to current user
        if category and request:
            if category.user_id != request.user:
                raise serializers.ValidationError({"category_id": "Category does not belong to the current user."})

        return data

>> >> >> > Stashed
changes
