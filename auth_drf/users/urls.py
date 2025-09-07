from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import RegisterView, LoginView, LogoutView, MeView, MockDocumentListCreate, MockDocumentDetail, RoleViewSet, ResourceTypeViewSet, RolePermissionViewSet

router = DefaultRouter()
router.register("roles", RoleViewSet, basename="role")
router.register("resource-types", ResourceTypeViewSet, basename="resourcetype")
router.register("role-permissions", RolePermissionViewSet, basename="rolepermission")

urlpatterns = [
    # Auth / user endpoints
    path("auth/register/", RegisterView.as_view(), name="register"),
    path("auth/login/", LoginView.as_view(), name="login"),
    path("auth/logout/", LogoutView.as_view(), name="logout"),
    path("users/me/", MeView.as_view(), name="users-me"),

    # Admin endpoints
    path("admin/", include(router.urls)),

    # Mock documents endpoints
    path("mock/documents/", MockDocumentListCreate.as_view(), name="mock-docs-list"),
    path("mock/documents/<int:pk>/", MockDocumentDetail.as_view(), name="mock-docs-detail"),
]