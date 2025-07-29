from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework import exceptions
from .models import RevokedAccessToken
from django.utils import timezone


class AccessTokenRevocationAuth(JWTAuthentication):
    def authenticate(self, request):
        header = self.get_header(request)
        if header is None:
            return None  # Không có token → bỏ qua xác thực

        raw_token = self.get_raw_token(header)
        if raw_token is None:
            return None

        validated_token = self.get_validated_token(raw_token)
        jti = validated_token.get('jti')

        # Xoá token hết hạn
        RevokedAccessToken.objects.filter(expires_at__lt=timezone.now()).delete()

        if RevokedAccessToken.objects.filter(jti=jti).exists():
            raise exceptions.AuthenticationFailed(detail={
                "errorCode": "401_TOKEN_REVOKED",
                "errorMessage": "Access token has been revoked.",
                "errorData": None
            })

        return self.get_user(validated_token), validated_token
