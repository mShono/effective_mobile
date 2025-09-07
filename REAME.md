# О проекте
Проект auth_drf — учебная реализация собственной системы аутентификации и авторизации на Django + DRF.

## Подготовка проекта auth_drf к запуску:
1. Клонируйте репозиторий и перейдите в него в командной строке:
```
git clone https://github.com/mShono/effective_mobile
cd auth_drf
```
2. Cоздайте и активируйте виртуальное окружение:
```
python3 -m venv venv
source env/bin/activate
```
3. Установите все необходимые пакеты из requirements.txt.
```
python3 -m pip install --upgrade pip
pip install -r requirements.txt
```
4. Перейдите в директорию с файлом manage.py и выполните миграции.
```
python3 manage.py makemigrations
python3 manage.py migrate
```
5. Запустите сервер.
```
python3 manage.py runserver
```
6. Наполните базу данных из файлов csv
```
python manage.py fill_database
```

## Cтруктура управления ограничениями доступа
## Основные сущности (модели / таблицы):

1. Role - таблица ролей: id, name (уникально), description.
Примеры: admin, editor, user.

2. UserRole - связующая таблица user ↔ role: user_id, role_id, assigned_at.
Позволяет одному пользователю иметь несколько ролей.

3. ResourceType - описание типа ресурса: id, code (уникально), description.
В проекте во в момент наполения базы создаётся один тип - "document".

4. RolePermission - носитель правил для комбинации (role, resource_type). Поля:
id
role_id (ForeignKey → Role)
resource_type_id (ForeignKey → ResourceType)
owner_only (bool) — если True, правило применимо только к объектам, где owner_id == user.id.
can_read (bool) — разрешено читать
can_create (bool) — разрешено создавать
can_update (bool) — разрешено обновлять
can_delete (bool) — разрешено удалять
Уникальность: (role_id, resource_type_id).

## В момент наполнения базы у ролей появляются следующие разрешения:
admin:
    "owner_only" - False,
    "can_read" - True,
    "can_create" - True,
    "can_update" - True,
    "can_delete" - True

editor:
    "owner_only" - False,
    "can_read" - True,
    "can_create" - True,
    "can_update" - True,
    "can_delete" - False

user:
    "owner_only" - True,
    "can_read" - True,
    "can_create" - True,
    "can_update" - True,
    "can_delete" - False

## Тесты:
Используется pytest + pytest-django:
```
pytest
```

## Реализованы следующие эндпоинты:

Auth/user endpoints

POST /api/auth/register/ — регистрация
POST /api/auth/login/ — логин
POST /api/auth/logout/ — logout (требует токен) — отзывает используемый токен
GET /api/users/me/ — информация о текущем пользователе (требует токен)
PUT /api/users/me/ — обновление профиля
DELETE /api/users/me/ — soft-delete: is_active=False, revoke всех токенов

Admin endpoints

GET/POST /api/admin/users/role/
GET/PUT/PATCH/DELETE /api/admin/roles/{id}/
GET/POST /api/admin/users/resourcetype/
GET/PUT/PATCH/DELETE /api/admin/users/resourcetype/{id}/
GET/POST /api/admin/users/rolepermission/
GET/PUT/PATCH/DELETE /api/admin/users/rolepermission/{id}/

Mock documents endpoints

GET /api/mock/documents/ — список документов
POST /api/mock/documents/ — создание документа
GET/PUT/DELETE /api/mock/documents/{id}/ — действия с документом

## Примеры curl:
Регистрация:
```
curl -X POST http://localhost:8000/api/auth/register/ \
  -H "Content-Type: application/json" \
  -d '{"email":"a@b.com","first_name":"A","last_name":"B","password":"pass12345","password_confirm":"pass12345"}'
```
Login:
```
curl http://localhost:8000/api/auth/login/ \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  -d '{"email":"a@b.com","password":"pass12345"}' \
```
Страница пользователя:
```
curl http://localhost:8000/api/users/me/ \
  -H "Authorization: Token ${TOKEN}"
```
Создать mock-документ:
```
curl -X POST http://localhost:8000/api/mock/documents/ \
  -H "Authorization: Token ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"title":"User1 doc","content":"User1 content"}'
```
Список документов:
```
curl http://localhost:8000/api/mock/documents/ \
  -H "Authorization: Token ${TOKEN}"
```
Обновление документа:
```
curl -X PUT http://localhost:8000/api/mock/documents/1/ \
  -H "Authorization: Token ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"title":"User1 new doc"}'
```
Удаление документа:
```
curl -X DELETE http://localhost:8000/api/mock/documents/1/ \
  -H "Authorization: Token ${TOKEN}" \
```
