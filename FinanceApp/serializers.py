import re
import uuid
import pytz
from decimal import Decimal
from datetime import date
from django.contrib.auth.hashers import make_password, check_password
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from FinanceApp.models import Users, Categories, Transactions


# Serializer show profile customer user
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['id', 'email', 'name', 'timezone']


# Serializer register customer user
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = Users
        fields = ['name', 'email', 'password', 'timezone']

    # check email is available
    def validate_email(self, value):
        if Users.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already in use.")
        return value

    # check timezone value
    def validate_timezone(self, value):
        if value not in pytz.all_timezones:
            raise serializers.ValidationError("Invalid timezone.")
        return value

    def validate_password(self, value):
        # password must be at least 8 characters
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters.")

        # at least one letter
        if not re.search(r'[A-Za-z]', value):
            raise serializers.ValidationError("Password must contain at least one letter.")

        # at least one digit (one number)
        if not re.search(r'\d', value):
            raise serializers.ValidationError("Password must contain at least one digit.")

        # at least one special character
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            raise serializers.ValidationError("Password must contain at least one special character.")

        return value

    # Hash password
    def create(self, validated_data):
        validated_data['username'] = validated_data['email'].split('@')[0] + '_' + str(uuid.uuid4())[:6]
        raw_password = validated_data.pop('password')
        validated_data['password_hash'] = make_password(raw_password)
        return Users.objects.create(**validated_data)


# Serializer login
class LoginUserSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        # Check out user email and password
        try:
            user = Users.objects.get(email=email)
        except Users.DoesNotExist:
            raise serializers.ValidationError("Invalid email or password.")

        # Check out user is superuser or not
        if user.is_superuser:
            # Check out password superuser
            if not check_password(password, user.password):
                raise serializers.ValidationError("Invalid superuser email or password.")
        else:
            # Check out password customer user
            if not check_password(password, user.password_hash):
                raise serializers.ValidationError("Invalid email or password.")

        if not user.is_active:
            raise serializers.ValidationError("User account is disabled.")

        # return user access token and user refresh token
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
            # compare parent user id with current user
            if parent.user_id_id != user.id:
                raise serializers.ValidationError({
                    'parent_category_id': 'Category does not belong to current user.'
                })
            # check out cate id to prove not itself
            if parent.id == current_instance.id and current_instance:
                raise serializers.ValidationError({
                    'parent_category_id': 'A category cannot be its own parent.'
                })
        return data


class TransactionsSerializer(serializers.ModelSerializer):
    user_id = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = Transactions
        fields = '__all__'

    def validate(self, data):
        request = self.context.get('request')
        amount = data.get('amount')
        trans_date = data.get('date')
        attachment_url = data.get('attachment_url')
        category = data.get('category_id')

        # amount > 0
        if amount is None or amount <= Decimal('0.00'):
            raise serializers.ValidationError({"amount": "Amount must be greater than 0."})

        # date not in future
        if trans_date and trans_date > date.today():
            raise serializers.ValidationError({"date": "Date cannot be in the future."})

        # URL format
        if attachment_url and not attachment_url.startswith('http'):
            raise serializers.ValidationError({"attachment_url": "URL must start with http or https."})

        # category belongs to current user
        if category and request:
            if category.user_id != request.user:
                raise serializers.ValidationError({"category_id": "Category does not belong to the current user."})

        return data
