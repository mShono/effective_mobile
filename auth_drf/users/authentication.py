import uuid
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.utils import timezone
from .models import Token

class TokenAuthentication(BaseAuthentication):
    keyword = "Token"

    def authenticate(self, request):
        auth = request.headers.get("Authorization")
        if not auth:
            return None
        try:
            scheme, token_string  = auth.split()
        except ValueError:
            raise AuthenticationFailed("Invalid authorization header.")
        if scheme != self.keyword:
            return None
        try:
            jti_hex, raw = token_string.split(".", 1)
        except ValueError:
            raise AuthenticationFailed("Invalid token format.")
        try:
            jti = uuid.UUID(hex=jti_hex)
        except (ValueError, AttributeError):
            raise AuthenticationFailed("Invalid token identifier.")
        try:
            token = Token.objects.select_related("user").get(jti=jti, revoked=False)
        except Token.DoesNotExist:
            raise AuthenticationFailed("Invalid token.")
        if not token.verify_raw(raw):
            raise AuthenticationFailed("Invalid token.")
        if token.expires_at and token.expires_at < timezone.now():
            raise AuthenticationFailed("Token expired.")
        user = token.user
        if not user.is_active:
            raise AuthenticationFailed("User inactive.")
        return (user, token)