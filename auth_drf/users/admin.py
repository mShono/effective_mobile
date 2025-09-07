from django.contrib import admin

from .models import User, Role, UserRole, ResourceType, RolePermission, Token

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    """
    Very minimal admin for custom User model.
    No inlines, no custom actions — just basic list/search/readonly fields.
    """
    list_display = ("id", "email", "first_name", "last_name", "is_active", "is_staff", "created_at")
    search_fields = ("email", "first_name", "last_name")
    list_filter = ("is_active", "is_staff")
    ordering = ("email",)
    readonly_fields = ("created_at", "deleted_at")
    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Personal info", {"fields": ("first_name", "last_name", "patronymic")}),
        ("Permissions", {"fields": ("is_active", "is_staff", "is_superuser")}),
        ("Dates", {"fields": ("created_at", "deleted_at")}),
    )


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "description")
    search_fields = ("name",)
    ordering = ("name",)


@admin.register(UserRole)
class UserRoleAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "role", "assigned_at")
    list_filter = ("role",)
    search_fields = ("user__email", "role__name")
    readonly_fields = ("assigned_at",)
    ordering = ("-assigned_at",)


@admin.register(ResourceType)
class ResourceTypeAdmin(admin.ModelAdmin):
    list_display = ("id", "code", "description")
    search_fields = ("code",)
    ordering = ("code",)


@admin.register(RolePermission)
class RolePermissionAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "role",
        "resource_type",
        "owner_only",
        "can_read",
        "can_create",
        "can_update",
        "can_delete",
    )
    list_filter = ("resource_type", "owner_only", "can_delete", "role")
    search_fields = ("role__name", "resource_type__code")
    ordering = ("role__name", "resource_type__code")


@admin.register(Token)
class TokenAdmin(admin.ModelAdmin):
    list_display = ("id", "jti", "user", "created_at", "expires_at", "revoked")
    list_filter = ("revoked", "created_at", "expires_at")
    search_fields = ("jti", "user__email")
    readonly_fields = ("jti", "created_at")
    ordering = ("-created_at",)
