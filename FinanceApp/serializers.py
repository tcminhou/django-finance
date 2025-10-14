import re
import uuid
import pycountry
from iso4217 import Currency as ISO4217_Currency
from decimal import Decimal
from datetime import date
from django.contrib.auth.hashers import make_password, check_password
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from FinanceApp.models import Users, Categories, Transactions, RecurringTransactions, Settings
from django.urls import reverse
from django.conf import settings


class StrictFieldsMixin:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        incoming = set(self.initial_data.keys()) if hasattr(self, 'initial_data') else set()
        allowed = set(self.fields.keys())
        unknown = incoming - allowed
        if unknown:
            unknown_list = sorted(unknown)
            raise serializers.ValidationError({
                "errorCode": "400_UNKNOWN_FIELDS",
                "errorMessage": f"Unexpected fields: {', '.join(unknown_list)}",
                "errorData": {
                    "unknown_fields": unknown_list
                }
            })


# Serializer show profile customer user
class UserSerializer(StrictFieldsMixin, serializers.ModelSerializer):
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


# Serializer register customer user
class RegisterSerializer(serializers.ModelSerializer):
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
        raw_password = validated_data.pop('password')
        validated_data['password'] = make_password(raw_password)
        return Users.objects.create(**validated_data)


# Serializer login
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

        # Check out user email and password
        try:
            user = Users.objects.get(email=email)
        except Users.DoesNotExist:
            raise serializers.ValidationError("Invalid email or password.")

        # Check out password customer user
        if not check_password(password, user.password):
            raise serializers.ValidationError({"Incorrect password": "Incorrect password please re-enter."})

        if not user.is_active:
            raise serializers.ValidationError("User account is disabled.")

        # return user access token and user refresh token
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


class CategorySerializer(StrictFieldsMixin, serializers.ModelSerializer):
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

            if parent.id == current_instance.id and current_instance:
                raise serializers.ValidationError({
                    'parent_category_id': 'A category cannot be its own parent.'
                })

        return data


class TransactionsSerializer(StrictFieldsMixin, serializers.ModelSerializer):
    user_id = serializers.PrimaryKeyRelatedField(read_only=True)
    active = serializers.BooleanField(default=True)
    attachment_preview_url = serializers.SerializerMethodField()

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

    def get_attachment_preview_url(self, obj):
        request = self.context.get('request')
        if obj.attachment_url and request:
            path = obj.attachment_url.removeprefix('/media/')
            base_url = request.build_absolute_uri('/')
            url = f"{base_url}api/transaction/{path}"
            return url
        return None


class RecurringTransactionsSerializer(StrictFieldsMixin, serializers.ModelSerializer):
    user_id = serializers.PrimaryKeyRelatedField(read_only=True)
    active = serializers.BooleanField(default=True)

    class Meta:
        model = RecurringTransactions
        fields = '__all__'

    def validate_amount(self, value):
        if value <= Decimal('0.00'):
            raise serializers.ValidationError("Amount must be greater than 0.")
        return value

    def validate(self, data):
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        next_occurrence = data.get('next_occurrence')
        recurrence_type = data.get('recurrence_type')

        today = date.today()

        if start_date and start_date < today:
            raise serializers.ValidationError({
                "start_date": "Start date cannot be in the past."
            })

        if end_date:
            if start_date and end_date < start_date:
                raise serializers.ValidationError({
                    "end_date": "End date must be after start date."
                })

        if next_occurrence and next_occurrence < today:
            raise serializers.ValidationError({
                "next_occurrence": "Next occurrence date cannot be in the past."
            })

        # Kiểm tra recurrence_type hợp lệ (có thể bỏ nếu dùng choices trong model)
        allowed_recurrences = ['daily', 'weekly', 'monthly', 'yearly']
        if recurrence_type not in allowed_recurrences:
            raise serializers.ValidationError({
                "recurrence_type": f"Invalid recurrence type. Allowed: {allowed_recurrences}."
            })

        return data


class SettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Settings
        fields = ['id', 'user_id', 'currency', 'language']
        extra_kwargs = {
            'user_id': {'read_only': True}
        }

    def validate_currency(self, value):
        if not pycountry.currencies.get(alpha_3=value):
            raise serializers.ValidationError(
                f"Currency '{value}' không hợp lệ (theo ISO 4217, ví dụ: VND, USD, EUR)."
            )
        return value

    def validate_language(self, value):
        if not pycountry.languages.get(alpha_2=value):
            raise serializers.ValidationError(
                f"Language '{value}' không hợp lệ (theo ISO 639-1, ví dụ: vi, en, us, ja)."
            )
        return value