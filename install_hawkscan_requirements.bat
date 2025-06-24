@echo off
echo ====================================
echo تثبيت متطلبات HawkScan
echo ====================================
echo.

echo التحقق من تثبيت Python...
python --version 2>NUL
if %ERRORLEVEL% NEQ 0 (
    echo [خطأ] لم يتم العثور على Python. يرجى تثبيت Python 3.6 أو أحدث.
    echo يمكنك تنزيل Python من https://www.python.org/downloads/
    pause
    exit /b 1
)

echo تثبيت المكتبات المطلوبة...
pip install -r requirements_hawkscan.txt

if %ERRORLEVEL% NEQ 0 (
    echo [خطأ] فشل في تثبيت المتطلبات.
    pause
    exit /b 1
)

echo.
echo تم تثبيت جميع المتطلبات بنجاح!
echo يمكنك الآن استخدام HawkScan.
echo.
echo للمساعدة، قم بتشغيل: python hawkscan.py --help
echo.

pause