from rest_framework import serializers
from django.contrib.auth import authenticate
from auth_drf.constants import MIN_LEN_PASSWORD, MAX_LEN_TITLE
from .models import User, Role, ResourceType, RolePermission

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=MIN_LEN_PASSWORD)
    password_confirm = serializers.CharField(write_only=True, min_length=MIN_LEN_PASSWORD)

    class Meta:
        model = User
        fields = ("email","first_name","last_name","patronymic","password","password_confirm")

    def validate(self, attrs):
        if attrs.get("password") != attrs.get("password_confirm"):
            raise serializers.ValidationError({"password_confirm": "Passwords do not match."})
        return attrs

    def create(self, validated_data):
        password = validated_data.pop("password")
        validated_data.pop("password_confirm", None)
        user = User.objects.create_user(password=password, **validated_data)
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")
        user = authenticate(username=email, password=password)
        if not user:
            raise serializers.ValidationError({"detail": "Invalid credentials."})
        if not user.is_active:
            raise serializers.ValidationError({"detail": "User inactive."})
        attrs["user"] = user
        return attrs

class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ("id","email","first_name","last_name","patronymic","is_active","created_at")
        read_only_fields = ("is_active","created_at")


class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = ("id", "name", "description")

class ResourceTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = ResourceType
        fields = ("id", "code", "description")

class RolePermissionSerializer(serializers.ModelSerializer):
    role = serializers.SlugRelatedField(slug_field="name", queryset=Role.objects.all())
    resource_type = serializers.SlugRelatedField(slug_field="code", queryset=ResourceType.objects.all())

    class Meta:
        model = RolePermission
        fields = (
            "id", "role", "resource_type",
            "owner_only",
            "can_read", "can_create", "can_update", "can_delete",
        )

class MockDocumentSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=MAX_LEN_TITLE, allow_blank=True, required=False)
    content = serializers.CharField(allow_blank=True, required=False)