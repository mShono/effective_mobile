from datetime import timedelta
from django.utils import timezone
import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from users.models import Role, User, UserRole, ResourceType, RolePermission, Token

@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def roles_and_permissions(db):
    # Create roles
    admin_role = Role.objects.create(name="admin", description="Administrator")
    editor_role = Role.objects.create(name="editor", description="Editor")
    user_role = Role.objects.create(name="user", description="Regular user")

    # resource type
    doc_rt = ResourceType.objects.create(code="document", description="Mock document")

    # Permissions:
    # admin: global all
    RolePermission.objects.create(
        role=admin_role, resource_type=doc_rt,
        owner_only=False, can_read=True, can_create=True, can_update=True, can_delete=True
    )
    # editor: global read/create/update (no delete)
    RolePermission.objects.create(
        role=editor_role, resource_type=doc_rt,
        owner_only=False, can_read=True, can_create=True, can_update=True, can_delete=False
    )
    # user: owner-only read/create/update
    RolePermission.objects.create(
        role=user_role, resource_type=doc_rt,
        owner_only=True, can_read=True, can_create=True, can_update=True, can_delete=False
    )

    return {"admin": admin_role, "editor": editor_role, "user": user_role, "resource": doc_rt}


@pytest.fixture
def users(db, roles_and_permissions):
    # Create users
    admin = User.objects.create_user(email="admin@example.com", password="adminpass", first_name="Admin", last_name="Admin_last_name")
    editor = User.objects.create_user(email="editor@example.com", password="editorpass", first_name="editoe", last_name="Editor_last_name")
    user1 = User.objects.create_user(email="user1@example.com", password="user1pass", first_name="User1", last_name="User1_last_name")
    user2 = User.objects.create_user(email="user2@example.com", password="user2pass", first_name="User2", last_name="User2_last_name")

    # assign roles
    UserRole.objects.create(user=admin, role=roles_and_permissions["admin"])
    UserRole.objects.create(user=editor, role=roles_and_permissions["editor"])
    UserRole.objects.create(user=user1, role=roles_and_permissions["user"])
    UserRole.objects.create(user=user2, role=roles_and_permissions["user"])

    return {"admin": admin, "editor": editor, "user1": user1, "user2": user2}


@pytest.fixture
def tokens(users):
    # Create tokens using Token.create_token (returns (instance, token_string))
    tokens = {}
    for name, user in users.items():
        token_obj, token_string = Token.create_token(user)
        tokens[name] = {"obj": token_obj, "str": token_string}
    return tokens


def auth(client: APIClient, token_str: str):
    client.credentials(HTTP_AUTHORIZATION=f"Token {token_str}")

# ---------- registration ----------

@pytest.mark.django_db
def test_register_validation(api_client):
    # mismatched passwords -> 400
    response = api_client.post("/api/auth/register/",
                           {"email": "x@y.com", "first_name": "A", "last_name": "B", "password": "p1", "password_confirm": "p2"},
                           format="json")
    assert response.status_code == 400

    # missing email -> 400
    response = api_client.post("/api/auth/register/",
                           {"first_name": "A", "last_name": "B", "password": "p1", "password_confirm": "p1"},
                           format="json")
    assert response.status_code == 400

    # wrong email type -> 400
    response = api_client.post("/api/auth/register/",
                           {"email": "xy.com", "first_name": "A", "last_name": "B", "password": "p1", "password_confirm": "p1"},
                           format="json")
    assert response.status_code == 400


@pytest.mark.django_db
def test_login_errors_and_missing_token(api_client):
    # create user
    user = User.objects.create_user(email="testlogin@example.com", password="testpass", first_name="Test", last_name="Test")

    # wrong password -> 400
    response = api_client.post("/api/auth/login/", {"email": user.email, "password": "wrong"}, format="json")
    assert response.status_code == 400

    # no access without token -> 401
    response = api_client.get("/api/users/me/")
    assert response.status_code == 403


# ---------- token expiry and revoke ----------

@pytest.mark.django_db
def test_token_expiry_and_revoke(api_client, users):
    user = users["user1"]
    # create expired token
    past = timezone.now() - timedelta(days=1)
    token_obj, token_str = Token.create_token(user, expires_at=past)
    auth(api_client, token_str)
    # should be unauthorized (token expired)
    response = api_client.get("/api/mock/documents/")
    print(response.status_code, response.data)
    assert response.status_code == 403

    # create valid token and revoke it
    token_obj2, token_str2 = Token.create_token(user, expires_at=None)
    auth(api_client, token_str2)
    response = api_client.get("/api/mock/documents/")
    print(response.status_code, response.data)
    assert response.status_code == 200

    # now revoke token and check requests fail
    token_obj2.revoked = True
    token_obj2.save()
    response = api_client.get("/api/mock/documents/")
    print(response.status_code, response.data)
    assert response.status_code == 403


# ---------- soft-delete user ----------

@pytest.mark.django_db
def test_soft_delete_user_revokes_tokens_and_blocks_login(api_client, users, tokens):
    user = users["user2"]
    token_str = tokens["user2"]["str"]
    auth(api_client, token_str)

    # delete (soft-delete)
    response = api_client.delete("/api/users/me/")
    assert response.status_code == 204

    # user should be inactive
    user.refresh_from_db()
    assert user.is_active is False

    # tokens should be revoked
    assert user.tokens.filter(revoked=True).exists()

    # login attempt should fail
    response = api_client.post("/api/auth/login/", {"email": user.email, "password": "user2pass"}, format="json")
    assert response.status_code == 403


# ---------- work with document ----------

@pytest.mark.django_db
def test_create_and_list_documents_for_different_roles(api_client, users, tokens):
    # create docs by user1, editor, admin
    auth(api_client, tokens["user1"]["str"])
    response = api_client.post("/api/mock/documents/", {"title": "User1 doc", "content": "test"}, format="json")
    assert response.status_code == 201
    doc_user1 = response.json()

    auth(api_client, tokens["editor"]["str"])
    response = api_client.post("/api/mock/documents/", {"title": "Editor doc", "content": "test"}, format="json")
    assert response.status_code == 201
    doc_editor = response.json()

    auth(api_client, tokens["admin"]["str"])
    response = api_client.post("/api/mock/documents/", {"title": "Admin doc", "content": "test"}, format="json")
    assert response.status_code == 201
    doc_admin = response.json()

    # user1 list -> only own
    auth(api_client, tokens["user1"]["str"])
    response = api_client.get("/api/mock/documents/")
    assert response.status_code == 200
    data = response.json()
    assert all(document["owner_id"] == users["user1"].id for document in data)
    assert any(document["id"] == doc_user1["id"] for document in data)
    assert not any(document["id"] == doc_editor["id"] for document in data)

    # editor list -> shows all
    auth(api_client, tokens["editor"]["str"])
    response = api_client.get("/api/mock/documents/")
    assert response.status_code == 200
    data = response.json()
    ids = {document["id"] for document in data}
    assert doc_user1["id"] in ids and doc_editor["id"] in ids and doc_admin["id"] in ids


@pytest.mark.django_db
def test_update_document(api_client, tokens):
    # editor_or_admin_can_update_but_user_cant_update_others
    # user1 create doc
    auth(api_client, tokens["user1"]["str"])
    response = api_client.post("/api/mock/documents/", {"title": "User1 doc", "content": "c"}, format="json")
    assert response.status_code == 201
    doc = response.json()

    # user2 can't update
    auth(api_client, tokens["user2"]["str"])
    response = api_client.put(f"/api/mock/documents/{doc['id']}/", {"title": "title2"}, format="json")
    assert response.status_code == 403

    # editor can update
    auth(api_client, tokens["editor"]["str"])
    response = api_client.put(f"/api/mock/documents/{doc['id']}/", {"title": "edited by editor"}, format="json")
    assert response.status_code == 200
    assert response.json()["title"] == "edited by editor"

    # admin can update
    auth(api_client, tokens["admin"]["str"])
    response = api_client.put(f"/api/mock/documents/{doc['id']}/", {"title": "edited by admin"}, format="json")
    assert response.status_code == 200
    assert response.json()["title"] == "edited by admin"


@pytest.mark.django_db
def test_delete_allowed_for_admin_only(api_client, tokens):
    # user1 create doc
    auth(api_client, tokens["user1"]["str"])
    response = api_client.post("/api/mock/documents/", {"title": "User1 doc", "content": "content"}, format="json")
    assert response.status_code == 201
    doc = response.json()

    # user1 can't delete
    auth(api_client, tokens["user1"]["str"])
    response = api_client.delete(f"/api/mock/documents/{doc['id']}/")
    assert response.status_code == 403

    # editor can't delete
    auth(api_client, tokens["editor"]["str"])
    response = api_client.delete(f"/api/mock/documents/{doc['id']}/")
    assert response.status_code == 403

    # admin can delete
    auth(api_client, tokens["admin"]["str"])
    response = api_client.delete(f"/api/mock/documents/{doc['id']}/")
    assert response.status_code == 204
