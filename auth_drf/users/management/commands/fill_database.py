from django.core.management.base import BaseCommand

from users.models import Role, ResourceType, RolePermission, UserRole, User


class Command(BaseCommand):
    help = "Fills the database with roles, resource types, role permissions, test users"

    def handle(self, *args, **options):
        # Roles
        admin_role, _ = Role.objects.get_or_create(name="admin", defaults={"description":"Administrator"})
        editor_role, _ = Role.objects.get_or_create(name="editor", defaults={"description":"Editor"})
        user_role, _ = Role.objects.get_or_create(name="user", defaults={"description":"Regular user"})

        # ResourceType
        doc_resource_type, _ = ResourceType.objects.get_or_create(
            code="document",
            defaults={"description":"Mock document"}
        )

        # RolePermission: admin -> all
        RolePermission.objects.update_or_create(
            role=admin_role, resource_type=doc_resource_type,
            defaults={
                "owner_only": False,
                "can_read": True,
                "can_create": True,
                "can_update": True,
                "can_delete": True
            }
        )
        # editor -> create/read/update (all documents)
        RolePermission.objects.update_or_create(
            role=editor_role, resource_type=doc_resource_type,
            defaults={
                "owner_only": False,
                "can_read": True,
                "can_create": True,
                "can_update": True,
                "can_delete": False
            }
        )
        # user -> read all? or owner_only? we'll make user owner_only for create/update
        RolePermission.objects.update_or_create(
            role=user_role, resource_type=doc_resource_type,
            defaults={
                "owner_only": True,
                "can_read": True,
                "can_create": True,
                "can_update": True,
                "can_delete": False
            }
        )

        # Create test users if not exists
        admin_user, created = User.objects.get_or_create(email="admin@example.com", defaults={"first_name":"Admin","last_name":"Admin_last_name"})
        if created:
            admin_user.set_password("adminpass")
            admin_user.is_staff = True
            admin_user.save()

        editor_user, created = User.objects.get_or_create(email="editor@example.com", defaults={"first_name":"Editor","last_name":"Editor_last_name"})
        if created:
            editor_user.set_password("editorpass")
            editor_user.save()

        user_1, created = User.objects.get_or_create(email="user1@example.com", defaults={"first_name":"User1","last_name":"User1_last_name"})
        if created:
            user_1.set_password("user1pass")
            user_1.save()

        user_2, created = User.objects.get_or_create(email="user2@example.com", defaults={"first_name":"User2","last_name":"User2_last_name"})
        if created:
            user_2.set_password("user2pass")
            user_2.save()

        # assign roles
        UserRole.objects.get_or_create(user=admin_user, role=admin_role)
        UserRole.objects.get_or_create(user=editor_user, role=editor_role)
        UserRole.objects.get_or_create(user=user_1, role=user_role)
        UserRole.objects.get_or_create(user=user_2, role=user_role)

        self.stdout.write(self.style.SUCCESS(
            "The database is filled. Roles: admin_role/editor_role/user_role, ResourceType: document, " \
            "RolePermissions: owner_only/can_read/can_create/can_update/can_delete, Users: admin/editor/user1/user2"
        ))