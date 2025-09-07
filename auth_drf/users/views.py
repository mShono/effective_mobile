from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions, viewsets


from .permissions import IsAdminRole, HasRolePermission
from .serializers import RegisterSerializer, LoginSerializer, UserSerializer, MockDocumentSerializer, RoleSerializer, ResourceTypeSerializer, RolePermissionSerializer
from .models import Token, User, Role, RolePermission, ResourceType, UserRole
from django.utils import timezone

class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        expires_at = None
        token_obj, token_string = Token.create_token(user, expires_at=expires_at)
        return Response({"token": token_string, "expires_at": token_obj.expires_at}, status=status.HTTP_200_OK)

class LogoutView(APIView):
    """
    Requires TokenAuthentication authentication.
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        """Revoking the token used for the current request."""
        token = request.auth
        if token and hasattr(token, "revoked"):
            token.revoked = True
            token.save(update_fields=["revoked"])
        return Response(status=status.HTTP_204_NO_CONTENT)

class MeView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({
            "id": user.id,
            "email": user.email,
            "first_name": getattr(user, "first_name", ""),
            "last_name": getattr(user, "last_name", ""),
            "patronymic": getattr(user, "patronymic", None),
            "is_active": user.is_active,
            "created_at": getattr(user, "created_at", None),
        })

    def put(self, request):
        ser = UserSerializer(request.user, data=request.data, partial=True)
        ser.is_valid(raise_exception=True)
        ser.save()
        return Response(ser.data)

    def delete(self, request):
        """Soft delete"""
        user = request.user
        user.is_active = False
        user.deleted_at = timezone.now()
        user.save(update_fields=["is_active","deleted_at"])
        # revoke all tokens
        user.tokens.update(revoked=True)
        return Response(status=status.HTTP_204_NO_CONTENT)


class RoleViewSet(viewsets.ModelViewSet):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    permission_classes = [IsAdminRole]


class ResourceTypeViewSet(viewsets.ModelViewSet):
    queryset = ResourceType.objects.all()
    serializer_class = ResourceTypeSerializer
    permission_classes = [IsAdminRole]


class RolePermissionViewSet(viewsets.ModelViewSet):
    queryset = RolePermission.objects.all()
    serializer_class = RolePermissionSerializer
    permission_classes = [IsAdminRole]


_DOCS = []
_DOC_ID_COUNTER = 1

class MockDocumentListCreate(APIView):
    permission_classes = [HasRolePermission]
    resource_type_code = "document"

    def get(self, request):
        user = request.user
        try:
            resource_type = ResourceType.objects.get(code=self.resource_type_code)
        except ResourceType.DoesNotExist:
            return Response([], status=status.HTTP_200_OK)
        role_ids = list(user.user_roles.values_list("role_id", flat=True))
        permissions = RolePermission.objects.filter(role_id__in=role_ids, resource_type=resource_type)
        show_all = any(perm.can_read and not perm.owner_only for perm in permissions)
        if show_all:
            return Response(_DOCS)
        own = [document for document in _DOCS if document.get("owner_id") == user.id]
        return Response(own)

    def post(self, request):
        global _DOC_ID_COUNTER
        serializer = MockDocumentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        title = data.get("title","")
        content = data.get("content","")
        doc = {
            "id": _DOC_ID_COUNTER,
            "resource_type": self.resource_type_code,
            "title": title,
            "content": content,
            "owner_id": request.user.id
        }
        _DOC_ID_COUNTER += 1
        _DOCS.append(doc)
        return Response(doc, status=status.HTTP_201_CREATED)

class MockDocumentDetail(APIView):
    permission_classes = [HasRolePermission]
    resource_type_code = "document"

    def get_object(self, pk):
        return next((d for d in _DOCS if d["id"] == pk), None)

    def get(self, request, pk):
        object = next((document for document in _DOCS if document["id"] == pk), None)
        if not object:
            return Response({"detail": "Not found"}, status=status.HTTP_404_NOT_FOUND)
        self.check_object_permissions(request, object)
        return Response(object)

    def put(self, request, pk):
        object = next((document for document in _DOCS if document["id"] == pk), None)
        if not object:
            return Response({"detail": "Not found"}, status=status.HTTP_404_NOT_FOUND)
        self.check_object_permissions(request, object)
        serializer = MockDocumentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = request.data or {}
        object["title"] = data.get("title", object["title"])
        object["content"] = data.get("content", object["content"])
        return Response(object)

    def delete(self, request, pk):
        object = next((document for document in _DOCS if document["id"] == pk), None)
        if not object:
            return Response({"detail": "Not found"}, status=status.HTTP_404_NOT_FOUND)
        self.check_object_permissions(request, object)
        _DOCS.remove(object)
        return Response(status=status.HTTP_204_NO_CONTENT)
