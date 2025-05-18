# Authorization Service Go


## Основные эндпоинты

- `GET /tokens?guid=...` — получить пару токенов
- `GET /refresh` — обновить токены
- `GET /guid` — получить GUID пользователя (требует авторизации)
- `GET /logout` — выйти (удалить refresh токен)

## Swagger

Документация доступна по адресу: http://localhost:3000/swagger/index.html

## Структура проекта
- `main.go` — точка входа
- `handlers/` — обработчики HTTP-запросов
- `models/` — модели данных
- `tokenutils/` — работа с токенами
- `middleware/` — middleware для авторизации
- `docs/` — Swagger спецификация

## Сборка и запуск вручную
```sh
go build -o authorization_service_go .
./authorization_service_go
```
