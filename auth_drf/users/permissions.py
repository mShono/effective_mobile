from rest_framework.permissions import BasePermission, SAFE_METHODS
from .models import ResourceType, RolePermission

HTTP_TO_FLAG = {
    "GET": "can_read",
    "POST": "can_create",
    "PUT": "can_update",
    "PATCH": "can_update",
    "DELETE": "can_delete",
}


class ReadOnly(BasePermission):
    """Allows only safe methods: GET, HEAD, OPTIONS."""
    def has_permission(self, request, view):
        return request.method in SAFE_METHODS


class IsAdminRole(BasePermission):
    """Checks if the user has a role with name='admin'."""
    def has_permission(self, request, view):
        user = request.user
        return bool(user and getattr(user, "is_authenticated", False) and
                    user.user_roles.filter(role__name="admin").exists())


class HasRolePermission(BasePermission):

    def has_permission(self, request, view):
        """Verifies that the user has a role that grants permission for the method."""

        resource_code = getattr(view, "resource_type_code", None)
        if resource_code is None:
            return True  # public access by default

        user = request.user
        if not user or not getattr(user, "is_authenticated", False):
            return False

        flag = HTTP_TO_FLAG.get(request.method)
        if not flag:
            return False

        try:
            resource_type = ResourceType.objects.get(code=resource_code)
        except ResourceType.DoesNotExist:
            return False

        # looking for at least one user role with permission
        role_ids = list(user.user_roles.values_list("role_id", flat=True))
        if not role_ids:
            return False

        permissions = RolePermission.objects.filter(role_id__in=role_ids, resource_type=resource_type)
        # if there is a global permission (owner_only=False) — immediately allow
        if any(getattr(permission, flag) and not permission.owner_only for permission in permissions):
            return True
        # otherwise, we allow it at the view level for POST (creation) or GET (list)
        if any(getattr(permission, flag) for permission in permissions):
            return True
        return False

    def has_object_permission(self, request, view, obj):
        """
        Additionally checks the owner_id if the owner_only rule applies.
        Verifying rights at the object level:
        - first we check the global rights (owner_only == False)
        - then we check the owner_only rights — we allow if owner_id == user.id
        """

        # obj — dict with the owner_id key in the mock-view; in the real model, the owner or owner_id field
        resource_code = getattr(view, "resource_type_code", None)
        if resource_code is None:
            return True

        user = request.user
        if not user or not getattr(user, "is_authenticated", False):
            return False

        flag = HTTP_TO_FLAG.get(request.method)
        if not flag:
            return False

        try:
            resource_type = ResourceType.objects.get(code=resource_code)
        except ResourceType.DoesNotExist:
            return False

        role_ids = list(user.user_roles.values_list("role_id", flat=True))
        permissions = RolePermission.objects.filter(role_id__in=role_ids, resource_type=resource_type)

        # global allow
        for permission in permissions:
            if getattr(permission, flag, False) and not permission.owner_only:
                return True

        # owner only -> check owner_id on obj
        owner_id = obj.get("owner_id") if isinstance(obj, dict) else getattr(obj, "owner_id", None)
        for permission in permissions:
            if getattr(permission, flag, False) and permission.owner_only:
                if owner_id == user.id:
                    return True
        return False