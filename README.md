# Custom RBAC Authentication System

Современная система аутентификации и авторизации с ролевой моделью доступа (RBAC) на Django + DRF с наглядным демо‑интерфейсом и административной панелью.

## Возможности

- ✅ Кастомная модель пользователя (UUID)
- ✅ JWT аутентификация (Access + Refresh)
- ✅ Ролевая модель доступа (RBAC)
- ✅ CRUD ролей и прав, привязка прав к ролям
- ✅ Защищённые ресурсы с проверкой прав
- ✅ Разделение сессий: Django Admin (cookie sessions) и Демо (JWT)
- ✅ Логирование действий администратора в Django Admin (Recent actions)
- ✅ Swagger/OpenAPI документация
- ✅ Docker поддержка
- ✅ Веб‑интерфейс: Login, Register, Dashboard, Detailed Demo

## 🚀 Быстрый старт (Docker — рекомендуется)

### 1. Автоматическая настройка

**Windows:**
```cmd
# Клонируйте репозиторий
git clone https://github.com/YeralyKuatuly/Test-task-custom-auth.git custom_auth
cd custom_auth

# Запустите автоматическую настройку
setup.bat

# Запустите систему
docker-compose up --build
```

**Linux/Mac:**
```bash
# Клонируйте репозиторий
git clone https://github.com/YeralyKuatuly/Test-task-custom-auth.git custom_auth
cd custom_auth

# Запустите автоматическую настройку
make setup

# Запустите систему
make up
```

### 2. Ручная настройка (альтернатива)

```bash
# Скопируйте файл окружения
cp env.example .env

# Отредактируйте .env при необходимости
# Затем запустите систему
docker-compose up --build
```

После сборки система автоматически:
- ✅ Создаст PostgreSQL базу данных
- ✅ Применит все миграции
- ✅ Заполнит демо-данными
- ✅ Запустит веб-сервер

### 2. Доступ к приложению

- **Главная:** http://localhost:8000
- **Вход в систему:** http://localhost:8000/login/
- **Регистрация:** http://localhost:8000/register/
- **Панель управления:** http://localhost:8000/dashboard/
- **Демо-интерфейс:** http://localhost:8000/detailed-demo/
- **API документация (Swagger):** http://localhost:8000/api/docs/
- **Админ панель:** http://localhost:8000/admin/

### 3. Демо‑данные (создаются автоматически)

#### Демо‑пользователи
- Администратор: admin@example.com / admin123
- Менеджер: manager@example.com / password123
- Просмотр: viewer@example.com / password123
- Секреты: secret@example.com / password123
- Аналитик: analyst@example.com / password123

#### Роли и права
- 6 ролей с различными уровнями доступа
- Набор детализированных прав (CRUD, доступ к ресурсам, спец‑доступ)
- Ресурсы для тестирования доступа

### 4. Быстрый тест

1. **Откройте** http://localhost:8000/login/
2. **Нажмите** кнопку "Админ" для автозаполнения
3. **Нажмите** "Войти" для входа в систему
4. **Изучите** панель управления и роли пользователя

### 5. Управление Docker

**С помощью Make (Linux/Mac):**
```bash
make up          # Запустить контейнеры
make down        # Остановить контейнеры
make logs        # Просмотр логов
make shell       # Открыть shell в контейнере
make clean       # Очистить все данные
```

**Или напрямую:**
```bash
# Остановить контейнеры
docker-compose down

# Остановить и удалить данные
docker-compose down -v

# Перезапустить систему
docker-compose restart

# Просмотр логов
docker-compose logs -f web

# Выполнить команду в контейнере
docker-compose exec web python manage.py shell
```

## 💻 Локальная разработка (альтернатива)

> **Примечание:** Для большинства пользователей рекомендуется использовать Docker. Локальная разработка нужна только для внесения изменений в код.

### Автоматическая настройка

**Linux/Mac:**
```bash
make setup-local
```

**Windows:**
```cmd
# Создайте виртуальное окружение
python -m venv venv
venv\Scripts\activate

# Установите зависимости
pip install -r requirements.txt

# Настройте окружение
copy env.example .env
# Отредактируйте .env: установите USE_SQLITE=True

# Запустите миграции и демо-данные
python manage.py migrate
python manage.py setup_demo_data

# Запустите сервер
python manage.py runserver
```

### Ручная настройка

```bash
# Клонируйте репозиторий
git clone https://github.com/YeralyKuatuly/Test-task-custom-auth.git custom_auth
cd custom_auth

# Создайте виртуальное окружение
python -m venv venv
source venv/bin/activate  # Linux/Mac
# или venv\Scripts\activate  # Windows

# Установите зависимости
pip install -r requirements.txt

# Настройте базу данных
cp env.example .env
# Отредактируйте .env при необходимости

# Запустите миграции
python manage.py migrate
python manage.py setup_demo_data

# Запустите сервер
python manage.py runserver
```

## Веб‑интерфейс

### Страницы аутентификации

#### Страница входа (`/login/`)
- **Современный дизайн** с адаптивной версткой
- **Автозаполнение** для демо-пользователей
- **Валидация** в реальном времени
- **JWT аутентификация** через API
- **Автоматический редирект** на панель управления

#### Страница регистрации (`/register/`)
- **Полная форма** с именем, фамилией, email, паролем
- **Проверка силы пароля** с требованиями
- **Подтверждение пароля** с валидацией
- **Обработка ошибок** с детальными сообщениями
- **Автоматический редирект** на страницу входа

#### Панель управления (`/dashboard/`)
- **Персонализированная информация** о пользователе
- **Отображение ролей и прав** с визуальными индикаторами
- **Быстрые действия** для тестирования системы
- **Навигация** к демо-интерфейсу и API документации
- **Безопасный выход** из системы

### Особенности интерфейса

#### **Адаптивный дизайн**
- **Мобильная версия** для всех устройств
- **Современный UI** с Bootstrap-подобными стилями
- **Интуитивная навигация** между страницами

#### Безопасность
- JWT токены в localStorage (Демо)
- Сессии Django Admin отдельные (cookie, httpOnly)
- Автоматическая обработка 401/403 в демо и разлогин
- Валидация на клиенте и сервере

#### **Пользовательский опыт**
- **Мгновенная обратная связь** при действиях
- **Загрузочные состояния** для всех операций
- **Детальные сообщения об ошибках**
- **Демо-кнопки** для быстрого тестирования

## API Endpoints (основные)

### Аутентификация (JWT)
- POST `/api/auth/register/` — регистрация
- POST `/api/auth/login/` — вход (возвращает access_token, refresh_token)
- POST `/api/auth/logout/` — выход (логическая операция)
- POST `/api/auth/refresh/` — обновление access_token
- GET `/api/auth/profile/` — профиль текущего пользователя

### Роли и права (требует JWT)
- GET `/api/authorization/roles/`
- POST `/api/authorization/roles/`
- PUT `/api/authorization/roles/{id}/`
- DELETE `/api/authorization/roles/{id}/`
- GET `/api/authorization/permissions/`
- POST `/api/authorization/permissions/`
- PUT `/api/authorization/permissions/{id}/`
- DELETE `/api/authorization/permissions/{id}/`

### Ресурсы (требует JWT)
- GET `/api/resources/resources/`
- POST `/api/resources/resources/`
- GET `/api/resources/resources/{id}/`
- PUT `/api/resources/resources/{id}/`
- DELETE `/api/resources/resources/{id}/`
- GET `/api/resources/test-access/{id}/` — тест доступа к ресурсу

## Тестирование

```bash
# Запуск всех тестов
python manage.py test --settings=config.test_settings

# Запуск тестов конкретного приложения
python manage.py test accounts --settings=config.test_settings
python manage.py test authorization --settings=config.test_settings
python manage.py test resources --settings=config.test_settings
python manage.py test core --settings=config.test_settings
```

## Структура проекта

```
custom_auth/
├── accounts/                 # Модель пользователя
├── auth_api/                # API аутентификации
├── authorization/           # Управление ролями и правами
├── resources/              # Управление ресурсами
├── core/                   # Общие компоненты
│   ├── views.py           # Веб-представления (auth, demo)
│   ├── auth_decorators.py  # JWT декораторы
│   ├── jwt_service.py      # JWT сервис
│   └── permissions.py      # Система прав
├── config/                 # Настройки Django
├── templates/              # HTML шаблоны
│   ├── static/
│   │   ├── css/           # Стили
│   │   └── js/            # JavaScript
│   ├── login.html         # Страница входа
│   ├── register.html      # Страница регистрации
│   ├── dashboard.html     # Панель управления
│   └── detailed_demo.html # Демо интерфейс
├── docker-compose.yml      # Docker конфигурация
├── dockerfile             # Docker образ
└── requirements.txt       # Python зависимости
```

## Технологии

- **Backend:** Django 5.2, Django REST Framework
- **База данных:** PostgreSQL (Docker), SQLite (разработка)
- **Аутентификация:** JWT (PyJWT)
- **Документация:** drf-spectacular (Swagger)
- **Контейнеризация:** Docker, Docker Compose
- **Frontend:** HTML5, CSS3, JavaScript (ES6+), Fetch API
- **UI/UX:** Адаптивный дизайн, современные CSS стили
- **Безопасность:** JWT токены, CSRF защита, валидация

## Лицензия

MIT License
