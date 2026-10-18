@echo off
title PhishSense - Starting All Services
color 0A

echo.
echo  =========================================
echo   PhishSense - AI Phishing Detection
echo   Starting all services...
echo  =========================================
echo.

:: ── 1. Python AI Service ──────────────────────────────────────────────────────
echo [1/3] Starting Python AI Service on port 8000...
start "PhishSense AI" cmd /k "cd /d D:\MAJOR\Ai && uvicorn main:app --host 0.0.0.0 --port 8000 --reload"
timeout /t 3 /nobreak >nul

:: ── 2. Spring Boot Backend ────────────────────────────────────────────────────
echo [2/3] Starting Spring Boot Backend on port 8080...
start "PhishSense Backend" cmd /k "cd /d D:\MAJOR\Back-End && mvn spring-boot:run"
timeout /t 3 /nobreak >nul

:: ── 3. React Frontend ─────────────────────────────────────────────────────────
echo [3/3] Starting React Frontend on port 5173...
start "PhishSense Frontend" cmd /k "cd /d D:\MAJOR\Front-End && npm run dev"
timeout /t 4 /nobreak >nul

:: ── Open browser ──────────────────────────────────────────────────────────────
echo.
echo  =========================================
echo   All services starting!
echo   Opening browser in 10 seconds...
echo  =========================================
echo.
echo   AI        : http://localhost:8000/docs
echo   Backend   : http://localhost:8080/api/health
echo   Frontend  : http://localhost:5173
echo.
timeout /t 10 /nobreak >nul
start "" "http://localhost:5173"

echo  Done! Check the 3 terminal windows.
pause
