# مستندسازی جامع پروژه CAREL Commissioning Dashboard

## معرفی پروژه

این پروژه یک **داشبورد commissioning پیشرفته** برای دستگاه‌های CAREL است که به طور تخصصی برای کنترل، مانیتورینگ و پیکربندی سیستم‌های HVAC طراحی شده است. پروژه از معماری چندلایه شامل frontend (HTML/CSS/JS)، backend (Node.js)، و اسکریپت‌های PowerShell برای ارتباط مستقیم با دستگاه استفاده می‌کند.

## معماری فنی پروژه

### لایه Presentation (Frontend)
- **dashboard.html** - صفحه اصلی داشبورد با طراحی PWA (Progressive Web App)
- **index.html** - صفحه ورودی با سیستم authentication
- **CSS Framework** - Bootstrap با تم سفارشی شده برای CAREL
- **JavaScript Libraries** - jQuery, Knockout.js, RequireJS
- **Component System** - کامپوننت‌های modular با استفاده از comfort-dashboard-component.js

### لایه Business Logic (Backend)
- **server.js** - سرور Express.js با قابلیت‌های:
  - REST API endpoints
  - Proxy به دستگاه CAREL
  - مدیریت CORS
  - WebSocket support
- **API Proxy** - middleware برای ارتباط امن با دستگاه

### لایه Data Access
- **اسکریپت‌های PowerShell** - ارتباط مستقیم با دستگاه از طریق پروتکل‌های CAREL
- **CSV Configuration** - فایل‌های getvar.csv و setvar.csv برای mapping متغیرها
- **Device Engine** - موتور ارتباط با دستگاه در deviceengine.js

## وضعیت فعلی پروژه - تحلیل تخصصی

### وضعیت شبکه و ارتباط
- **آدرس دستگاه**: 169.254.61.68 (APIPA range - Automatic Private IP Addressing)
- **پروتکل**: HTTP روی پورت 80
- **Ping Status**: ✅ موفقیت‌آمیز - 0% packet loss, latency 1-5ms
- **Port Status**: ✅ پورت 80 باز و پاسخگو
- **Service Status**: ❌ سرویس commissioning پاسخ نمی‌دهد

### تشخیص مشکل
مشکل از نوع **"Service Unavailable"** است که نشان‌دهنده موارد زیر می‌تواند باشد:

1. **سرویس commissioning crashed** - process terminated unexpectedly
2. **Device reboot** - دستگاه در حال بوت شدن است
3. **Configuration corruption** - فایل‌های پیکربندی آسیب دیده‌اند
4. **Resource exhaustion** - memory یا CPU دستگاه پر شده

### dependencyهای پروژه
```json
{
  "cors": "^2.8.5",      // مدیریت Cross-Origin Resource Sharing
  "express": "^4.18.2",  // فریم‌ورک وب سرور
  "node-fetch": "^2.6.7" // HTTP client برای درخواست‌های خارجی
}
```

## اقدامات انجام شده - به صورت chronological

### فاز ۱: ارزیابی اولیه
1. **تست ارتباط پایه** - اجرای ping برای verify کردن connectivity
2. **پورت اسکنینگ** - بررسی پورت‌های 80, 8080, 443, 502, 20000, 20001
3. **Service Discovery** - شناسایی سرویس‌های در حال اجرا

### فاز ۲: عیب‌یابی شبکه
1. **Network Connectivity** - تأیید connection در لایه ۳ (IP)
2. **Port Availability** - تأیید connection در لایه ۴ (TCP)
3. **Service Responsiveness** - بررسی لایه ۷ (Application)

### فاز ۳: تحلیل پاسخ‌ها
1. **Ping Results** - شبکه سالم، دستگاه reachable
2. **Port 80 Test** - پورت باز اما سرویس پاسخگو نیست
3. **Error Analysis** - "Unable to connect to remote server"

## ساختار فایل‌ها - دسته‌بندی تخصصی

### Core Application Files
- `dashboard.html` - Main SPA با routing و state management
- `server.js` - REST API server با authentication middleware
- `package.json` - Dependency management و build scripts

### PowerShell Scripts (دسته‌بندی بر اساس functionality)

#### دسته ۱: Device Control
- `force_comfort.ps1` - تنظیم حالت Comfort
- `force_economy_precomfort.ps1` - تنظیم حالت Economy
- `set_systemstatus_comfort.ps1` - تنظیم system status
- `set_unitstatus_comfort.ps1` - تنظیم unit status

#### دسته ۲: Temperature Management
- `simple_set_temp.ps1` - تنظیم دمای مستقیم
- `stabilize_comfort_24.ps1` - تثبیت دما روی 24°C
- `apply_direct_setpoints.ps1` - اعتماد مستقیم setpoints

#### دسته ۳: Power Management
- `aggressive_power_off.ps1` - خاموش کردن агрессивی
- `unified_power_control.ps1` - کنترل power یکپارچه
- `remote_on_off_control.ps1` - کنترل ریموت on/off

#### دسته ۴: Monitoring & Diagnostics
- `test_real_device.ps1` - تست دستگاه real-time
- `check_modes.ps1` - بررسی حالت‌های دستگاه
- `read_comfort.ps1` - خواندن وضعیت Comfort

#### دسته ۵: Advanced Operations
- `bruteforce_service_user_codes.ps1` - brute force کدهای کاربر
- `explore_endpoints.ps1` - کشف API endpoints
- `extract_ids_proxy.ps1` - استخراج IDها از proxy

### Configuration Files
- `device.json` - Device-specific configuration
- `cfield.json` - Field commissioning parameters
- `getvar.csv` - Variable mapping برای read operations
- `setvar.csv` - Variable mapping برای write operations

### Asset Files
- `assets/img/` - تصاویر و آیکون‌ها
- `assets/data/` - فایل‌های داده و templates
- `font/` - فونت‌های سفارشی CAREL

## معماری ارتباطی پروژه

### Communication Flow
```
Frontend (Browser) → Express Server → PowerShell Scripts → CAREL Device
```

### پروتکل‌های استفاده شده
1. **HTTP/REST** - برای communication بین frontend و backend
2. **PowerShell Remoting** - برای execute کردن commands روی دستگاه
3. **CAREL Proprietary Protocol** - برای communication با دستگاه HVAC

### Security Layers
1. **CORS Protection** - restrict cross-origin requests
2. **Input Validation** - validate تمام user inputs
3. **Command Sanitization** - prevent injection attacks

## مشکلات شناسایی شده

### مشکل ۱: Service Unavailability
- **علائم**: پورت 80 باز اما سرویس پاسخ نمی‌دهد
- **علل احتمالی**:
  - سرویس commissioning crashed
  - دستگاه در حال reboot است
  - configuration corruption
  - resource exhaustion

### مشکل ۲: Script Execution Errors
- **خطا**: "Unable to connect to the remote server"
- **نشان‌دهنده**: عدم دسترسی به سرویس commissioning

### مشکل ۳: Project Structure Issues
- **تعداد زیاد** فایل‌های تست و توسعه‌ای
- **عدم organization** مناسب فایل‌ها
- **وجود duplicate** scripts

## راه‌حل‌های پیشنهادی

### Short-term Solutions
1. **Wait and Retry** - صبر برای recovery سرویس
2. **Physical Reset** - ریستارت فیزیکی دستگاه
3. **Service Restart** - restart سرویس commissioning (اگر accessible باشد)

### Medium-term Solutions
1. **Connection Pooling** - implement connection pooling برای scripts
2. **Retry Mechanism** - اضافه کردن automatic retry logic
3. **Health Checks** - implement continuous health monitoring

### Long-term Solutions
1. **Architecture Refactor** - reorganize پروژه برای production
2. **Code Cleanup** - حذف فایل‌های unnecessary
3. **Documentation** - ایجاد comprehensive documentation
4. **Testing Suite** - implement automated testing

## اقدامات بعدی Recommended

1. **فاز پاک‌سازی** - حذف فایل‌های تست و توسعه‌ای
2. **فاز reorganization** - دسته‌بندی فایل‌ها به صورت logical
3. **فاز optimization** - بهینه‌سازی اسکریپت‌ها و کد
4. **فاز documentation** - ایجاد مستندات فنی کامل
5. **فاز deployment** - آماده‌سازی برای production deployment

## نکات فنی مهم

- پروژه از **APIPA address** (169.254.x.x) استفاده می‌کند که نشان‌دهنده عدم دریافت IP از DHCP است
- **پورت 80** پاسخگو است اما سرویس application layer کار نمی‌کند
- **PowerShell scripts** به صورت مستقیم با دستگاه communication می‌کنند
- **Frontend** به صورت PWA طراحی شده که قابلیت نصب روی دستگاه‌های مختلف را دارد

---

این مستندات به صورت جامع وضعیت پروژه، مشکلات فنی، و راه‌حل‌های پیشنهادی را پوشش می‌دهد. برای هر بخش additional details مورد نیاز است، لطفاً specify کنید.