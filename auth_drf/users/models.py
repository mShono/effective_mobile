import hmac
import hashlib
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models
import secrets
import uuid

from auth_drf import settings
from auth_drf.constants import MAX_LEN_INFO, MAX_LEN_USER_INFO, MAX_LEN_KEY_HASH

from django.contrib.auth.base_user import BaseUserManager
from django.utils.translation import gettext_lazy as _
from django.utils import timezone

class UserManager(BaseUserManager):

    def _create_user(self, email, password, **extra_fields):
        """
        The auxiliary private method generates and saves the user.
        Called from create_user and create_superuser.
        """
        if not email:
            raise ValueError(_("The given email must be set"))
        email = self.normalize_email(email)
        user = self.model(
            email=self.normalize_email(email),
            **extra_fields
        )
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        """
        Creates and saves a User.
        """
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(email, password, **extra_fields)

    def create_staff_user(self, email, password=None, **extra_fields):
        """
        Creates and saves a staff User.
        """
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", False)
        if extra_fields.get("is_staff") is not True:
            raise ValueError("The staff user must have is_staff=True.")
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password=None, **extra_fields):
        """
        Creates and saves a superuser.
        """
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self._create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """Custom user model."""

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = (
        "first_name",
        "last_name"
    )

    email = models.EmailField("email address", unique=True)
    first_name = models.CharField("First name", max_length=MAX_LEN_USER_INFO)
    last_name = models.CharField("Last name", max_length=MAX_LEN_USER_INFO)
    patronymic = models.CharField("Patronymic", max_length=MAX_LEN_USER_INFO, blank=True, null=True)

    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    deleted_at = models.DateTimeField(null=True, blank=True)

    objects = UserManager()

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"

    def __str__(self):
        return self.email

    def soft_delete(self):
        self.is_active = False
        self.deleted_at = timezone.now()
        self.save(update_fields=["is_active", "deleted_at"])


class Role(models.Model):
    """
    The user's role in the system (for example: admin, editor, user).
    """
    name = models.CharField(max_length=MAX_LEN_INFO, unique=True)
    description = models.TextField(blank=True)

    class Meta:
        verbose_name = "Role"
        verbose_name_plural = "Roles"

    def __str__(self):
        return self.name


class UserRole(models.Model):
    """
    Linking a user to a role.
    One record means that a specific user has a specified role.
    """
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="user_roles",
    )
    role = models.ForeignKey(
        Role,
        on_delete=models.CASCADE,
        related_name="user_roles",
    )
    assigned_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("user", "role")
        verbose_name = "User role"
        verbose_name_plural = "User roles"

    def __str__(self):
        return f"{self.user} -> {self.role}"


class ResourceType(models.Model):
    """
    The type of resource in the system (the code that access rules are linked to).
    """
    code = models.CharField(max_length=MAX_LEN_INFO, unique=True)
    description = models.TextField(blank=True)

    class Meta:
        verbose_name = "Resource type"
        verbose_name_plural = "Resource types"

    def __str__(self):
        return self.code


class RolePermission(models.Model):
    """
    A set of rights for a role relative to a specific type of resource.
    """
    role = models.ForeignKey(
        Role,
        on_delete=models.CASCADE,
        related_name="permissions"
    )
    resource_type = models.ForeignKey(
        ResourceType,
        on_delete=models.CASCADE,
        related_name="permissions"
    )

    owner_only = models.BooleanField(default=False)
    can_read = models.BooleanField(default=False)
    can_create = models.BooleanField(default=False)
    can_update = models.BooleanField(default=False)
    can_delete = models.BooleanField(default=False)

    class Meta:
        unique_together = ("role", "resource_type")
        verbose_name = "Role permission"
        verbose_name_plural = "Role permissions"

    def __str__(self):
        flags = []
        if self.can_read: flags.append("R")
        if self.can_create: flags.append("C")
        if self.can_update: flags.append("U")
        if self.can_delete: flags.append("D")
        flags_str = "".join(flags) or "none"
        return f"{self.role} @ {self.resource_type}: {flags_str}"



def _hash_token(raw: str) -> str:
    """
    HMAC-SHA256 from a raw token with SECRET_KEY as the key.
    Returns a hex string of length 64.
    """
    key = settings.SECRET_KEY.encode()
    return hmac.new(key, raw.encode(), hashlib.sha256).hexdigest()


class Token(models.Model):
    """
    The token stores only the jti (uuid) and key_hash (HMAC-SHA256 from the raw token).
    The string "<jti_hex>" is returned to the client.<raw>".
    """

    jti = models.UUIDField(default=uuid.uuid4, editable=False, unique=True, db_index=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="tokens")
    key_hash = models.CharField(max_length=MAX_LEN_KEY_HASH, unique=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    revoked = models.BooleanField(default=False)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return f"Token {self.jti} for {self.user}"

    @classmethod
    def create_token(cls, user, expires_at=None, raw_length=48):
        """
        Creates a record in the database and returns (instance, token_string).
        token_string = "<jti_hex>.<raw>."
        """
        raw = secrets.token_urlsafe(raw_length)
        key_hash = _hash_token(raw)
        instance = cls.objects.create(user=user, key_hash=key_hash, expires_at=expires_at)
        token_string = f"{instance.jti.hex}.{raw}"
        return instance, token_string
    
    def verify_raw(self, raw: str) -> bool:
        """Hash сomparison."""
        return hmac.compare_digest(self.key_hash, _hash_token(raw))
