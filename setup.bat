@echo off
echo ========================================
echo Custom Auth System - Windows Setup
echo ========================================
echo.

REM Check if .env already exists
if exist .env (
    echo .env file already exists!
    set /p overwrite="Do you want to overwrite it? (y/N): "
    if /i not "%overwrite%"=="y" (
        echo Setup cancelled.
        pause
        exit /b 0
    )
)

REM Copy env.example to .env
echo Creating .env file from template...
copy env.example .env
if errorlevel 1 (
    echo Error: Could not create .env file!
    pause
    exit /b 1
)

REM Generate random secret keys
echo Generating random secret keys...
python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(50))" > temp_secret.txt
python -c "import secrets; print('JWT_SECRET_KEY=' + secrets.token_urlsafe(50))" > temp_jwt.txt

REM Update .env with random keys
powershell -Command "(Get-Content .env) -replace 'SECRET_KEY=.*', (Get-Content temp_secret.txt) | Set-Content .env"
powershell -Command "(Get-Content .env) -replace 'JWT_SECRET_KEY=.*', (Get-Content temp_jwt.txt) | Set-Content .env"

REM Clean up temp files
del temp_secret.txt temp_jwt.txt

echo.
echo ========================================
echo Setup completed successfully!
echo ========================================
echo.
echo Next steps:
echo 1. Run: docker-compose up --build
echo 2. Open: http://localhost:8000
echo.
echo The .env file has been created with random secret keys.
echo You can modify it if needed.
echo.
pause
