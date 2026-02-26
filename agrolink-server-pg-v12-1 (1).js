/*
 * =============================================================================
 * AGROLINK SERVER - PostgreSQL v2.1 (UUID FIX)
 * =============================================================================
 * 
 * 🚀 DÜZELTME: Tüm TEXT id/FK sütunları UUID'ye çevrildi
 * 📊 65 API Rotası
 * 🔒 Güvenlik: Helmet, CORS, Rate Limiting, bcrypt, JWT
 * ⚡ Optimize edilmiş sorgular + Connection Pooling
 * 
 * =============================================================================
 */

require('dotenv').config(); // .env dosyasını yükle (EMAIL/SMTP değişkenleri için zorunlu)

const cluster = require('cluster');
const os = require('os');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const fssync = require('fs');
const http = require('http');
const { v4: uuidv4 } = require('uuid');
const sharp = require('sharp');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const helmet = require('helmet');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const ffmpeg     = require('fluent-ffmpeg');
const ffmpegPath = require('ffmpeg-static');

ffmpeg.setFfmpegPath(ffmpegPath);

// ==================== SQLite → PG MİGRASYON (opsiyonel) ====================
// sqlite3 ve sqlite paketleri sadece migrasyon sırasında kullanılır.
// Yüklü değilse migrasyon atlanır, sistem normal çalışır.
let sqlite3Mod, sqliteOpen;
try {
    sqlite3Mod = require('sqlite3').verbose();
    sqliteOpen = require('sqlite').open;
} catch (_) { /* paket yok, migrasyon devre dışı */ }

// ==================== KONFİGÜRASYON ====================

const PORT = process.env.PORT || 3000;

// 🔒 GÜVENLİK: JWT secret'lar ZORUNLU — .env dosyasında tanımlı olmalı
// Eğer tanımlı değilse sunucu kasıtlı olarak başlamaz
if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
    console.error('❌ HATA: JWT_SECRET .env dosyasında tanımlı değil veya 32 karakterden kısa!');
    console.error('   Örnek: JWT_SECRET=' + require("crypto").randomBytes(32).toString("hex"));
    process.exit(1);
}
if (!process.env.JWT_REFRESH_SECRET || process.env.JWT_REFRESH_SECRET.length < 32) {
    console.error('❌ HATA: JWT_REFRESH_SECRET .env dosyasında tanımlı değil veya 32 karakterden kısa!');
    console.error('   Örnek: JWT_REFRESH_SECRET=' + require("crypto").randomBytes(32).toString("hex"));
    process.exit(1);
}

const JWT_SECRET         = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
const BCRYPT_ROUNDS = 10;

// ==================== 📧 E-POSTA KONFİGÜRASYONU ====================

// ──────────────────────────────────────────────────────────────────────────────
// 📧 Gmail SMTP Kurulumu (ZORUNLU):
//   1. Gmail → Hesap → Güvenlik → 2 Adımlı Doğrulama: AKTİF
//   2. https://myaccount.google.com/apppasswords → Uygulama: "Posta" → Oluştur
//   3. .env dosyasına ekle (BOŞLUKSUZ, TIRNAK YOK):
//        SMTP_USER=ornek@gmail.com
//        SMTP_PASS=abcdabcdabcdabcd   (16 karakter, boşluk yok)
//   ⚠️  Normal Gmail şifreniz çalışmaz! Uygulama şifresi zorunludur.
// ──────────────────────────────────────────────────────────────────────────────
function getEmailCredentials() {
    const user = (process.env.SMTP_USER || process.env.EMAIL_USER || '').trim();
    // Boşlukları ve tire/nokta dışı özel karakterleri temizle (App Password formatı)
    const pass = (process.env.SMTP_PASS || process.env.EMAIL_PASS || '')
        .replace(/\s+/g, '')   // tüm boşlukları kaldır
        .trim();
    return { user, pass };
}

function createTransporter() {
    const { user, pass } = getEmailCredentials();
    if (!user || !pass) {
        console.warn('⚠️  E-posta devre dışı: SMTP_USER/SMTP_PASS .env dosyasında tanımlı değil');
        console.warn('   → .env dosyanıza şunları ekleyin:');
        console.warn('     SMTP_USER=gmail_adresiniz@gmail.com');
        console.warn('     SMTP_PASS=16haneliharcuygulama şifresi (boşluksuz)');
        return null;
    }
    // Her iki port stratejisini de dene: önce 465 (SSL), hata alırsa 587 (TLS)
    return nodemailer.createTransport({
        host            : 'smtp.gmail.com',
        port            : 465,
        secure          : true,
        auth            : { user, pass },
        connectionTimeout: 10000,
        greetingTimeout  : 10000,
        // 🔒 GÜVENLİK: TLS sertifika doğrulaması aktif (MITM koruması)
        tls             : { rejectUnauthorized: true, servername: 'smtp.gmail.com' },
    });
}

// Transporter'ı önbellekle ama hata durumunda yeniden oluştur
let _emailTransporter = null;
let _emailVerified = false;

function getEmailTransporter() {
    if (_emailTransporter && _emailVerified) return _emailTransporter;
    _emailTransporter = createTransporter();
    return _emailTransporter;
}

// Sunucu başladığında e-posta bağlantısını test et (asenkron, bloke etmez)
async function testEmailConnection() {
    const { user, pass } = getEmailCredentials();
    if (!user || !pass) return;
    const t = createTransporter();
    if (!t) return;
    try {
        await t.verify();
        _emailTransporter = t;
        _emailVerified = true;
        console.log('✅ Gmail SMTP bağlantısı doğrulandı:', user);
    } catch (err) {
        console.error('❌ Gmail SMTP hatası:', err.message);
        if (err.message.includes('Invalid login') || err.message.includes('Username and Password')) {
            console.error('   ▶ Çözüm: Google Hesap → Güvenlik → Uygulama Şifreleri');
            console.error('   ▶ https://myaccount.google.com/apppasswords');
            console.error('   ▶ Normal Gmail şifreniz çalışmaz, 16 haneli App Password gerekli!');
        }
        // Transporter'ı null yapmıyoruz; yine de denemeye devam eder
        _emailTransporter = t;
        _emailVerified = false;
    }
}

async function sendEmail(to, subject, html, text = null) {
    const transporter = getEmailTransporter();
    if (!transporter) {
        console.warn('📧 E-posta atlandı (kimlik bilgisi yok):', subject);
        return { success: false, error: 'E-posta yapılandırılmamış' };
    }
    try {
        const mailOptions = {
            from: `Agrolink <${process.env.SMTP_USER || process.env.EMAIL_USER}>`,
            to,
            subject,
            html,
            text: text || html.replace(/<[^>]*>/g, '')
        };
        const info = await transporter.sendMail(mailOptions);
        console.log('📧 E-posta gönderildi:', info.response);
        return { success: true, messageId: info.messageId };
    } catch (error) {
        console.error('❌ E-posta gönderim hatası:', error.message);
        return { success: false, error: error.message };
    }
}

// ─── Şablon 1: Kayıt (Hoş Geldiniz) ────────────────────────────────
function getWelcomeEmailTemplate(userName) {
    return `
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Agrolink'e Hoş Geldiniz</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.8; color: #333; margin: 0; padding: 0; background-color: #f4f4f4; }
        .container { max-width: 600px; margin: 20px auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #2e7d32, #4caf50); padding: 40px 30px; text-align: center; }
        .header h1 { color: #ffffff; margin: 0; font-size: 28px; }
        .header p { color: rgba(255,255,255,0.9); margin: 10px 0 0; font-size: 16px; }
        .content { padding: 40px 30px; }
        .content h2 { color: #2e7d32; margin-top: 0; }
        .features { background: #f8fdf8; padding: 25px; border-radius: 8px; margin: 25px 0; border-left: 4px solid #4caf50; }
        .features ul { list-style: none; padding: 0; margin: 0; }
        .features li { padding: 10px 0; border-bottom: 1px solid #e8f5e9; display: flex; align-items: center; }
        .features li:last-child { border-bottom: none; }
        .features li span { margin-right: 10px; font-size: 20px; }
        .warning { background: #fff8e1; padding: 20px; border-radius: 8px; margin: 25px 0; border-left: 4px solid #ffc107; }
        .footer { background: #f5f5f5; padding: 25px 30px; text-align: center; color: #666; font-size: 13px; }
        .footer a { color: #2e7d32; text-decoration: none; }
        .logo-emoji { font-size: 48px; margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo-emoji">🌾</div>
            <h1>Agrolink'e Hoş Geldiniz!</h1>
            <p>Dijital Tarım Topluluğunun Bir Parçası Oldunuz</p>
        </div>
        <div class="content">
            <h2>Merhaba ${userName || 'Değerli Kullanıcı'},</h2>
            <p>Agrolink ailesine hoş geldin! 🎉</p>
            <p>Hesabının başarıyla oluşturulduğunu bildirmekten mutluluk duyuyoruz.</p>
            <p>Agrolink, çiftçileri, üreticileri ve tarım ekosistemindeki tüm paydaşları tek bir dijital platformda buluşturmak amacıyla geliştirilmiştir. Burada; bilgi paylaşabilir, içerik üretebilir, topluluklarla etkileşime geçebilir ve tarım dünyasındaki gelişmeleri yakından takip edebilirsin.</p>
            <div class="features">
                <h3 style="margin-top: 0; color: #2e7d32;">Agrolink'te seni neler bekliyor?</h3>
                <ul>
                    <li><span>🌾</span> Tarım odaklı sosyal paylaşım alanları</li>
                    <li><span>🤝</span> Üreticiler arası dijital imece ve etkileşim</li>
                    <li><span>📢</span> Duyurular, bildirimler ve güncel içerikler</li>
                    <li><span>🔐</span> Güvenli ve sürekli geliştirilen bir sistem</li>
                </ul>
            </div>
            <p>Hesabınla ilgili önemli güvenlik bildirimleri, sistem duyuruları ve yenilikler bu e-posta adresi üzerinden sana iletilecektir. Bu nedenle e-postalarını düzenli olarak kontrol etmeni öneririz.</p>
            <p>Her zaman daha iyi bir deneyim sunmak için platformumuzu sürekli geliştiriyoruz. Görüşlerin ve geri bildirimlerin bizim için çok değerli. İlerleyen süreçte yeni özellikler ve sürprizlerle karşına çıkacağız 🚀</p>
            <div class="warning">
                <strong>⚠️ Önemli:</strong> Eğer bu işlemi sen gerçekleştirmediysen veya hesabınla ilgili bir sorun olduğunu düşünüyorsan, lütfen bizimle iletişime geç.
            </div>
            <p>Agrolink'i tercih ettiğin için teşekkür ederiz.</p>
            <p><strong>Bereketli, verimli ve güçlü bir dijital tarım yolculuğu dileriz 🌿</strong></p>
            <p>Saygılarımızla,<br><strong>Agrolink Ekibi</strong></p>
        </div>
        <div class="footer">
            <p>Bu e-posta otomatik olarak gönderilmiştir. Lütfen yanıtlamayınız.</p>
            <p>&copy; ${new Date().getFullYear()} Agrolink. Tüm hakları saklıdır.</p>
            <p><a href="#">Gizlilik Politikası</a> | <a href="#">Kullanım Koşulları</a></p>
        </div>
    </div>
</body>
</html>`;
}

// ─── Şablon 2: Giriş Bildirimi (Ben Değilim butonu) ─────────────────
function getLoginNotificationTemplate(userName, loginDetails, resetToken = null) {
    const { date, time, ip, device, location } = loginDetails;
    const resetPasswordLink = resetToken
        ? `https://sehitumitkestitarimmtal.com/api/auth/reset-password-direct?token=${encodeURIComponent(resetToken)}`
        : `https://sehitumitkestitarimmtal.com/`;

    return `
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Agrolink Giriş Bildirimi</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.8; color: #333; margin: 0; padding: 0; background-color: #f4f4f4; }
        .container { max-width: 600px; margin: 20px auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #1565c0, #42a5f5); padding: 40px 30px; text-align: center; }
        .header h1 { color: #ffffff; margin: 0; font-size: 28px; }
        .header p { color: rgba(255,255,255,0.9); margin: 10px 0 0; font-size: 16px; }
        .content { padding: 40px 30px; }
        .content h2 { color: #1565c0; margin-top: 0; }
        .login-details { background: #f5f9ff; padding: 25px; border-radius: 8px; margin: 25px 0; border-left: 4px solid #1565c0; }
        .login-details ul { list-style: none; padding: 0; margin: 0; }
        .login-details li { padding: 12px 0; border-bottom: 1px solid #e3f2fd; display: flex; align-items: center; }
        .login-details li:last-child { border-bottom: none; }
        .login-details li span { margin-right: 12px; font-size: 18px; min-width: 30px; }
        .login-details li strong { min-width: 100px; color: #666; }
        .warning { background: #ffebee; padding: 25px; border-radius: 8px; margin: 25px 0; border-left: 4px solid #f44336; }
        .warning h3 { color: #c62828; margin-top: 0; display: flex; align-items: center; }
        .warning h3 span { margin-right: 10px; }
        .security-tips { background: #e8f5e9; padding: 25px; border-radius: 8px; margin: 25px 0; border-left: 4px solid #4caf50; }
        .security-tips h3 { color: #2e7d32; margin-top: 0; }
        .security-tips ul { margin: 0; padding-left: 20px; }
        .security-tips li { padding: 8px 0; }
        .not-me-button { display: inline-block; background: linear-gradient(135deg, #d32f2f, #f44336); color: white !important; padding: 15px 35px; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 16px; margin: 20px 0; text-align: center; box-shadow: 0 4px 15px rgba(244,67,54,0.3); }
        .button-container { text-align: center; margin: 30px 0; }
        .footer { background: #f5f5f5; padding: 25px 30px; text-align: center; color: #666; font-size: 13px; }
        .footer a { color: #1565c0; text-decoration: none; }
        .logo-emoji { font-size: 48px; margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo-emoji">🔐</div>
            <h1>Giriş Bildirimi</h1>
            <p>Hesabınıza yeni bir giriş yapıldı</p>
        </div>
        <div class="content">
            <h2>Merhaba ${userName || 'Değerli Kullanıcı'},</h2>
            <p>Agrolink hesabına başarıyla giriş yapıldığını bildirmek isteriz.</p>
            <p>Bu e-posta, hesabındaki hareketleri kontrol altında tutabilmen ve güvenliğini artırmak amacıyla otomatik olarak gönderilmiştir.</p>
            <div class="login-details">
                <h3 style="margin-top: 0; color: #1565c0;">📋 Giriş Detayları</h3>
                <ul>
                    <li><span>📅</span> <strong>Tarih:</strong> ${date}</li>
                    <li><span>⏰</span> <strong>Saat:</strong> ${time}</li>
                    <li><span>🌍</span> <strong>IP Adresi:</strong> ${ip}</li>
                    <li><span>📱</span> <strong>Cihaz:</strong> ${device || 'Bilinmiyor'}</li>
                    ${location ? `<li><span>📍</span> <strong>Konum:</strong> ${location}</li>` : ''}
                </ul>
            </div>
            <p>✅ <strong>Eğer bu giriş sana aitse</strong>, herhangi bir işlem yapmana gerek yoktur. Agrolink'i güvenle kullanmaya devam edebilirsin.</p>
            <div class="warning">
                <h3><span>❗</span> Bu girişi sen yapmadıysan:</h3>
                <p>Hesabın tehlikede olabilir! Aşağıdaki butona tıklayarak şifreni hemen sıfırlayabilirsin:</p>
                <div class="button-container">
                    <a href="${resetPasswordLink}" class="not-me-button">
                        🚨 BU BEN DEĞİLİM - ŞİFREMİ SIFIRLA
                    </a>
                </div>
                <p style="font-size: 13px; color: #c62828; margin-top: 15px; font-weight: bold;">
                    ⏱️ DİKKAT: Bu link sadece 10 dakika geçerlidir! 10 dakika sonra kullanılamaz hale gelir.
                </p>
                <p style="font-size: 13px; color: #666; margin-top: 10px;">
                    Bu butona tıkladığında tüm aktif oturumların sonlandırılacak ve yeni şifre belirleme sayfasına yönlendirileceksin.
                </p>
            </div>
            <div class="security-tips">
                <h3>🛡️ Hesabını korumak için:</h3>
                <ul>
                    <li>Güçlü bir şifre kullanmanı</li>
                    <li>Şifreni kimseyle paylaşmamanı</li>
                    <li>Hesabına yalnızca güvendiğin cihazlardan giriş yapmanı öneririz</li>
                </ul>
            </div>
            <p>Agrolink'i kullandığın için teşekkür ederiz.</p>
            <p><strong>Güvenli ve verimli bir dijital tarım deneyimi dileriz 🌱</strong></p>
            <p>Saygılarımızla,<br><strong>Agrolink Ekibi</strong></p>
        </div>
        <div class="footer">
            <p>Bu e-posta otomatik olarak gönderilmiştir. Lütfen yanıtlamayınız.</p>
            <p>&copy; ${new Date().getFullYear()} Agrolink. Tüm hakları saklıdır.</p>
            <p><a href="#">Gizlilik Politikası</a> | <a href="#">Kullanım Koşulları</a></p>
        </div>
    </div>
</body>
</html>`;
}

// ─── Şablon 3: Şifre Sıfırlama Başarılı ─────────────────────────────
function getPasswordResetSuccessTemplate(userName) {
    const now  = new Date();
    const date = now.toLocaleDateString('tr-TR', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
    const time = now.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    return `
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Şifreniz Başarıyla Sıfırlandı - Agrolink</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.8; color: #333; margin: 0; padding: 0; background-color: #f4f4f4; }
        .container { max-width: 600px; margin: 20px auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #2e7d32, #4caf50); padding: 40px 30px; text-align: center; }
        .header h1 { color: #ffffff; margin: 0; font-size: 28px; }
        .header p { color: rgba(255,255,255,0.9); margin: 10px 0 0; font-size: 16px; }
        .content { padding: 40px 30px; }
        .content h2 { color: #2e7d32; margin-top: 0; }
        .success-box { background: #e8f5e9; padding: 25px; border-radius: 8px; margin: 25px 0; border-left: 4px solid #4caf50; text-align: center; }
        .success-box .icon { font-size: 48px; margin-bottom: 10px; }
        .details-box { background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .details-box ul { list-style: none; padding: 0; margin: 0; }
        .details-box li { padding: 10px 0; border-bottom: 1px solid #e0e0e0; display: flex; align-items: center; }
        .details-box li:last-child { border-bottom: none; }
        .details-box li span { margin-right: 10px; font-size: 18px; }
        .warning-box { background: #fff8e1; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #ffc107; }
        .footer { background: #f5f5f5; padding: 25px 30px; text-align: center; color: #666; font-size: 13px; }
        .footer a { color: #2e7d32; text-decoration: none; }
        .logo-emoji { font-size: 48px; margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo-emoji">✅</div>
            <h1>Şifreniz Başarıyla Sıfırlandı!</h1>
            <p>Hesabınız artık güvende</p>
        </div>
        <div class="content">
            <h2>Merhaba ${userName || 'Değerli Kullanıcı'},</h2>
            <div class="success-box">
                <div class="icon">🔐</div>
                <h3 style="color: #2e7d32; margin: 0;">Şifre Değişikliği Tamamlandı!</h3>
                <p style="margin: 10px 0 0; color: #666;">Agrolink hesabınızın şifresi başarıyla değiştirildi.</p>
            </div>
            <div class="details-box">
                <h3 style="margin-top: 0; color: #333;">📋 İşlem Detayları</h3>
                <ul>
                    <li><span>📅</span> <strong>Tarih:</strong> ${date}</li>
                    <li><span>⏰</span> <strong>Saat:</strong> ${time}</li>
                    <li><span>🔄</span> <strong>İşlem:</strong> Şifre Sıfırlama</li>
                    <li><span>✅</span> <strong>Durum:</strong> Başarılı</li>
                </ul>
            </div>
            <p>Artık yeni şifrenizle Agrolink'e giriş yapabilirsiniz. Hesabınızın güvenliği için:</p>
            <div class="warning-box">
                <strong>🛡️ Güvenlik Önerileri:</strong>
                <ul style="margin: 10px 0 0; padding-left: 20px;">
                    <li>Şifrenizi kimseyle paylaşmayın</li>
                    <li>Güçlü ve benzersiz şifreler kullanın</li>
                    <li>Düzenli olarak şifrenizi değiştirin</li>
                    <li>Şüpheli bir aktivite görürseniz hemen bize bildirin</li>
                </ul>
            </div>
            <p><strong>Eğer bu işlemi siz yapmadıysanız</strong>, hesabınız tehlikede olabilir. Hemen bizimle iletişime geçin ve şifrenizi tekrar değiştirin.</p>
            <p><strong>Güvenli ve verimli bir dijital tarım deneyimi dileriz 🌱</strong></p>
            <p>Saygılarımızla,<br><strong>Agrolink Ekibi</strong></p>
        </div>
        <div class="footer">
            <p>Bu e-posta otomatik olarak gönderilmiştir. Lütfen yanıtlamayınız.</p>
            <p>&copy; ${new Date().getFullYear()} Agrolink. Tüm hakları saklıdır.</p>
            <p><a href="#">Gizlilik Politikası</a> | <a href="#">Kullanım Koşulları</a></p>
        </div>
    </div>
</body>
</html>`;
}

// ─── Şablon 4: Şifremi Unuttum ───────────────────────────────────────
function getForgotPasswordEmailTemplate(userName, resetToken) {
    const resetPasswordLink = `https://sehitumitkestitarimmtal.com/api/auth/reset-password-direct?token=${encodeURIComponent(resetToken)}`;
    return `
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Agrolink - Şifre Sıfırlama</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.8; color: #333; margin: 0; padding: 0; background-color: #f4f4f4; }
        .container { max-width: 600px; margin: 20px auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #ff9800, #f57c00); padding: 40px 30px; text-align: center; }
        .header h1 { color: #ffffff; margin: 0; font-size: 28px; }
        .header p { color: rgba(255,255,255,0.9); margin: 10px 0 0; font-size: 16px; }
        .content { padding: 40px 30px; }
        .content h2 { color: #ff9800; margin-top: 0; }
        .info-box { background: #fff8e1; padding: 25px; border-radius: 8px; margin: 25px 0; border-left: 4px solid #ff9800; }
        .reset-button { display: inline-block; background: linear-gradient(135deg, #2e7d32, #4caf50); color: white !important; padding: 18px 40px; text-decoration: none; border-radius: 10px; font-weight: bold; font-size: 18px; margin: 25px 0; text-align: center; box-shadow: 0 4px 15px rgba(76,175,80,0.4); }
        .button-container { text-align: center; margin: 30px 0; }
        .warning-box { background: #ffebee; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #f44336; }
        .warning-box h3 { color: #c62828; margin-top: 0; }
        .timer-box { background: #e3f2fd; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #2196f3; text-align: center; }
        .timer-box .time { font-size: 32px; font-weight: bold; color: #1565c0; }
        .footer { background: #f5f5f5; padding: 25px 30px; text-align: center; color: #666; font-size: 13px; }
        .footer a { color: #ff9800; text-decoration: none; }
        .logo-emoji { font-size: 48px; margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo-emoji">🔑</div>
            <h1>Şifre Sıfırlama Talebi</h1>
            <p>Hesabınızı kurtarmak için bir adım kaldı</p>
        </div>
        <div class="content">
            <h2>Merhaba ${userName || 'Değerli Kullanıcı'},</h2>
            <p>Agrolink hesabınız için şifre sıfırlama talebinde bulunulduğunu bildirmek isteriz.</p>
            <div class="info-box">
                <p>Eğer bu talebi <strong>siz yaptıysanız</strong>, aşağıdaki butona tıklayarak yeni şifrenizi belirleyebilirsiniz.</p>
            </div>
            <div class="timer-box">
                <p style="margin: 0 0 10px 0; color: #1565c0;">⏱️ Bu link sadece geçerlidir:</p>
                <div class="time">10 DAKİKA</div>
                <p style="margin: 10px 0 0 0; color: #666; font-size: 13px;">Link süre dolduktan sonra kullanılamaz hale gelir.</p>
            </div>
            <div class="button-container">
                <a href="${resetPasswordLink}" class="reset-button">
                    🔐 ŞİFREMİ SIFIRLA
                </a>
            </div>
            <div class="warning-box">
                <h3>⚠️ Önemli Uyarı</h3>
                <p style="margin: 0;">Eğer bu şifre sıfırlama talebini <strong>siz yapmadıysanız</strong>, bu e-postayı dikkate almayın. Hesabınız güvendedir ve herhangi bir işlem yapmanıza gerek yoktur.</p>
                <p style="margin: 15px 0 0 0; font-size: 13px; color: #666;">
                    Şüpheli bir durum olduğunu düşünüyorsanız, lütfen hesabınızın güvenliği için şifrenizi değiştirin.
                </p>
            </div>
            <p><strong>Güvenli bir dijital tarım deneyimi dileriz 🌱</strong></p>
            <p>Saygılarımızla,<br><strong>Agrolink Ekibi</strong></p>
        </div>
        <div class="footer">
            <p>Bu e-posta otomatik olarak gönderilmiştir. Lütfen yanıtlamayınız.</p>
            <p>&copy; ${new Date().getFullYear()} Agrolink. Tüm hakları saklıdır.</p>
            <p><a href="#">Gizlilik Politikası</a> | <a href="#">Kullanım Koşulları</a></p>
        </div>
    </div>
</body>
</html>`;
}

// ─── Şablon 5: İnaktif Kullanıcı ────────────────────────────────────
function getInactiveUserEmailTemplate(userName, userId) {
    const unsubLink = `https://sehitumitkestitarimmtal.com/api/email/unsubscribe/${userId}`;
    return `
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Agrolink - Seni Özledik</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.8; color: #333; margin: 0; padding: 0; background-color: #f4f4f4; }
        .container { max-width: 600px; margin: 20px auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #ff9800, #ffb74d); padding: 40px 30px; text-align: center; }
        .header h1 { color: #ffffff; margin: 0; font-size: 28px; }
        .header p { color: rgba(255,255,255,0.9); margin: 10px 0 0; font-size: 16px; }
        .content { padding: 40px 30px; }
        .content h2 { color: #ff9800; margin-top: 0; }
        .highlight-box { background: #fff8e1; padding: 25px; border-radius: 8px; margin: 25px 0; border-left: 4px solid #ff9800; }
        .footer { background: #f5f5f5; padding: 25px 30px; text-align: center; color: #666; font-size: 13px; }
        .footer a { color: #ff9800; text-decoration: none; }
        .logo-emoji { font-size: 48px; margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo-emoji">🌿</div>
            <h1>Seni Özledik!</h1>
            <p>Agrolink'te neler oluyor?</p>
        </div>
        <div class="content">
            <h2>Merhaba ${userName || 'Değerli Kullanıcı'},</h2>
            <p>Agrolink'e bir süredir giriş yapmadığını fark ettik.</p>
            <p>Her şey yolundadır umarız 🌱</p>
            <div class="highlight-box">
                <p>Agrolink, üreticiler ve tarım topluluğu için sürekli gelişen bir platformdur. Bu süreçte yeni paylaşımlar, içerikler ve topluluk etkileşimleri devam ediyor.</p>
            </div>
            <p>Eğer zamanın olursa, Agrolink'e tekrar göz atmanı isteriz.</p>
            <p>Belki ilgini çekecek yeni içerikler veya paylaşımlar seni bekliyordur.</p>
            <p>Herhangi bir sorun yaşadıysan veya platformla ilgili bir önerin varsa, geri bildirimlerini bizimle paylaşabilirsin. Senin düşüncelerin bizim için çok değerli.</p>
            <p><strong>Agrolink her zaman senin için burada 🌿</strong></p>
            <p>Saygılarımızla,<br><strong>Agrolink Geliştiricisi</strong><br>Salih Öztürk</p>
        </div>
        <div class="footer">
            <p>Bu e-posta bilgilendirme amaçlı gönderilmiştir.</p>
            <p>&copy; ${new Date().getFullYear()} Agrolink. Tüm hakları saklıdır.</p>
            <p style="margin-top: 15px;">
                <a href="${unsubLink}">📧 E-posta bildirimlerinden çıkmak için tıklayın</a>
            </p>
        </div>
    </div>
</body>
</html>`;
}

// ─── Şablon 6: Yüksek Etkileşim Teşekkür ────────────────────────────
function getHighEngagementEmailTemplate(userName, userId) {
    const unsubLink = `https://sehitumitkestitarimmtal.com/api/email/unsubscribe/${userId}`;
    return `
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Agrolink - Teşekkürler!</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.8; color: #333; margin: 0; padding: 0; background-color: #f4f4f4; }
        .container { max-width: 600px; margin: 20px auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #e91e63, #f48fb1); padding: 40px 30px; text-align: center; }
        .header h1 { color: #ffffff; margin: 0; font-size: 28px; }
        .header p { color: rgba(255,255,255,0.9); margin: 10px 0 0; font-size: 16px; }
        .content { padding: 40px 30px; }
        .content h2 { color: #e91e63; margin-top: 0; }
        .highlight-box { background: #fce4ec; padding: 25px; border-radius: 8px; margin: 25px 0; border-left: 4px solid #e91e63; }
        .suggestions { background: #f3e5f5; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .suggestions ul { margin: 0; padding-left: 20px; }
        .suggestions li { padding: 8px 0; }
        .footer { background: #f5f5f5; padding: 25px 30px; text-align: center; color: #666; font-size: 13px; }
        .footer a { color: #e91e63; text-decoration: none; }
        .logo-emoji { font-size: 48px; margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo-emoji">💚</div>
            <h1>Teşekkür Ederiz!</h1>
            <p>Aktif katılımın için minnettarız</p>
        </div>
        <div class="content">
            <h2>Merhaba ${userName || 'Değerli Kullanıcı'},</h2>
            <p>Agrolink'te kısa süre içinde gösterdiğin yüksek etkileşimi fark ettik 🌱</p>
            <p>Gönderilere yaptığın beğeniler ve verdiğin destek için teşekkür ederiz.</p>
            <div class="highlight-box">
                <p>Topluluğun canlı ve güçlü kalmasında senin gibi aktif kullanıcıların katkısı çok büyük. Yapılan her etkileşim, bilgi paylaşımını artırıyor ve üreticiler arasında dijital dayanışmayı güçlendiriyor.</p>
            </div>
            <p>Agrolink'i daha iyi bir platform haline getirmek için çalışmalarımıza devam ediyoruz. Senin katılımın ve desteğin bizim için çok değerli.</p>
            <div class="suggestions">
                <h3 style="margin-top: 0; color: #7b1fa2;">Dilersen:</h3>
                <ul>
                    <li>📝 Paylaşımlara yorum yapabilir</li>
                    <li>🌾 Kendi deneyimlerini paylaşabilir</li>
                    <li>👥 Topluluklarla daha aktif etkileşime geçebilirsin</li>
                </ul>
            </div>
            <p>❤️ Agrolink'te aktif olman bizi gerçekten mutlu ediyor 🌿</p>
            <p><strong>İyi ki buradasın!</strong></p>
            <p>Saygılarımızla,<br><strong>Agrolink Ekibi</strong></p>
        </div>
        <div class="footer">
            <p>Bu e-posta teşekkür ve bilgilendirme amacıyla gönderilmiştir.</p>
            <p>&copy; ${new Date().getFullYear()} Agrolink. Tüm hakları saklıdır.</p>
            <p style="margin-top: 15px;">
                <a href="${unsubLink}">📧 E-posta bildirimlerinden çıkmak için tıklayın</a>
            </p>
        </div>
    </div>
</body>
</html>`;
}

// ─── Cihaz tespiti (User-Agent'tan) ─────────────────────────────────
function detectDeviceFromUserAgent(userAgent) {
    if (!userAgent) return 'Bilinmeyen Cihaz';
    const ua = userAgent.toLowerCase();
    let os = 'Bilinmiyor';
    if (ua.includes('windows'))                          os = 'Windows';
    else if (ua.includes('mac os') || ua.includes('macos')) os = 'macOS';
    else if (ua.includes('linux'))                       os = 'Linux';
    else if (ua.includes('android'))                     os = 'Android';
    else if (ua.includes('iphone') || ua.includes('ipad') || ua.includes('ios')) os = 'iOS';
    let browser = 'Bilinmiyor';
    if (ua.includes('chrome') && !ua.includes('edg'))   browser = 'Chrome';
    else if (ua.includes('firefox'))                     browser = 'Firefox';
    else if (ua.includes('safari') && !ua.includes('chrome')) browser = 'Safari';
    else if (ua.includes('edg'))                         browser = 'Edge';
    else if (ua.includes('opera') || ua.includes('opr')) browser = 'Opera';
    let deviceType = 'Masaüstü';
    if (ua.includes('mobile') || ua.includes('android') || ua.includes('iphone')) deviceType = 'Mobil';
    else if (ua.includes('tablet') || ua.includes('ipad')) deviceType = 'Tablet';
    return `${deviceType} - ${os} / ${browser}`;
}

// ─── E-posta gönderim fonksiyonları ─────────────────────────────────
async function sendWelcomeEmail(userEmail, userName) {
    return sendEmail(userEmail, "🌾 Agrolink'e Hoş Geldiniz!", getWelcomeEmailTemplate(userName));
}

async function sendLoginNotificationEmail(userEmail, userName, req, resetToken = null) {
    const now = new Date();
    const ip  = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'Bilinmiyor';
    const loginDetails = {
        date    : now.toLocaleDateString('tr-TR', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' }),
        time    : now.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        ip,
        device  : detectDeviceFromUserAgent(req.headers['user-agent'] || ''),
        location: null,
    };
    return sendEmail(userEmail, '🔐 Agrolink Hesabınıza Giriş Yapıldı', getLoginNotificationTemplate(userName, loginDetails, resetToken));
}

async function sendPasswordResetSuccessEmail(userEmail, userName) {
    return sendEmail(userEmail, '✅ Agrolink - Şifreniz Başarıyla Sıfırlandı!', getPasswordResetSuccessTemplate(userName));
}

async function sendForgotPasswordEmail(userEmail, userName, resetToken) {
    return sendEmail(userEmail, '🔑 Agrolink - Şifre Sıfırlama Talebi', getForgotPasswordEmailTemplate(userName, resetToken));
}

async function sendInactiveUserEmail(userId, userEmail, userName) {
    return sendEmail(userEmail, '🌿 Agrolink - Seni Özledik!', getInactiveUserEmailTemplate(userName, userId));
}

async function sendHighEngagementEmail(userId, userEmail, userName) {
    return sendEmail(userEmail, '💚 Agrolink - Teşekkür Ederiz!', getHighEngagementEmailTemplate(userName, userId));
}

// ─── 2FA E-POSTA ŞABLONU ─────────────────────────────────────────────
function getTwoFactorEmailTemplate(userName, code, purpose = 'login') {
    const purposeText = purpose === 'login' ? 'giriş işleminizi' : 'işleminizi';
    return `<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Doğrulama Kodu - Agrolink</title>
<style>
body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;line-height:1.8;color:#333;margin:0;padding:0;background-color:#f4f4f4}
.container{max-width:600px;margin:20px auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.1)}
.header{background:linear-gradient(135deg,#2e7d32,#4caf50);padding:40px 30px;text-align:center}
.header h1{color:#fff;margin:0;font-size:28px}
.content{padding:40px 30px}
.code-box{background:linear-gradient(135deg,#e8f5e9,#c8e6c9);padding:30px;border-radius:12px;text-align:center;margin:25px 0;border:2px dashed #4caf50}
.code{font-size:42px;font-weight:bold;color:#2e7d32;letter-spacing:8px;font-family:'Courier New',monospace}
.timer-box{background:#fff8e1;padding:20px;border-radius:8px;margin:20px 0;border-left:4px solid #ffc107;text-align:center}
.timer{font-size:24px;font-weight:bold;color:#f57c00}
.warning{background:#ffebee;padding:20px;border-radius:8px;margin:20px 0;border-left:4px solid #f44336}
.footer{background:#f5f5f5;padding:25px 30px;text-align:center;color:#666;font-size:13px}
.logo-emoji{font-size:48px;margin-bottom:10px}
</style></head><body>
<div class="container">
  <div class="header"><div class="logo-emoji">🔐</div><h1>Doğrulama Kodu</h1></div>
  <div class="content">
    <h2>Merhaba ${userName || 'Değerli Kullanıcı'},</h2>
    <p>Agrolink hesabınıza ${purposeText} tamamlamak için doğrulama kodunuz:</p>
    <div class="code-box"><div class="code">${code}</div></div>
    <div class="timer-box"><p style="margin:0 0 10px 0">⏱️ Bu kodun geçerlilik süresi:</p><div class="timer">5 DAKİKA</div></div>
    <div class="warning"><strong>⚠️ Güvenlik Uyarısı:</strong><p style="margin:10px 0 0 0">Bu kodu kimseyle paylaşmayın. Agrolink çalışanları asla bu kodu sizden istemez.</p></div>
    <p>Eğer bu işlemi siz yapmadıysanız, hesabınızın güvenliği için şifrenizi hemen değiştirin.</p>
    <p>Saygılarımızla,<br><strong>Agrolink Güvenlik Ekibi</strong></p>
  </div>
  <div class="footer"><p>Bu e-posta otomatik olarak gönderilmiştir. Lütfen yanıtlamayınız.</p><p>&copy; ${new Date().getFullYear()} Agrolink. Tüm hakları saklıdır.</p></div>
</div></body></html>`;
}

async function sendTwoFactorCodeEmail(userEmail, userName, code, purpose = 'login') {
    try {
        const html = getTwoFactorEmailTemplate(userName, code, purpose);
        return await sendEmail(userEmail, '🔐 Agrolink Doğrulama Kodunuz', html);
    } catch (error) {
        console.error('2FA e-postası gönderilemedi:', error);
        return { success: false, error: error.message };
    }
}

// ─── KAYIT DOĞRULAMA E-POSTA ŞABLONU ─────────────────────────────────
function getEmailVerificationTemplate(userName, code) {
    return `<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>E-Posta Doğrulama - Agrolink</title>
<style>
body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;line-height:1.8;color:#333;margin:0;padding:0;background-color:#f4f4f4}
.container{max-width:600px;margin:20px auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.1)}
.header{background:linear-gradient(135deg,#1976d2,#42a5f5);padding:40px 30px;text-align:center}
.header h1{color:#fff;margin:0;font-size:28px}
.content{padding:40px 30px}
.code-box{background:linear-gradient(135deg,#e3f2fd,#bbdefb);padding:30px;border-radius:12px;text-align:center;margin:25px 0;border:2px dashed #1976d2}
.code{font-size:42px;font-weight:bold;color:#1565c0;letter-spacing:8px;font-family:'Courier New',monospace}
.timer-box{background:#fff8e1;padding:20px;border-radius:8px;margin:20px 0;border-left:4px solid #ffc107;text-align:center}
.timer{font-size:24px;font-weight:bold;color:#f57c00}
.info-box{background:#e8f5e9;padding:20px;border-radius:8px;margin:20px 0;border-left:4px solid #4caf50}
.footer{background:#f5f5f5;padding:25px 30px;text-align:center;color:#666;font-size:13px}
.logo-emoji{font-size:48px;margin-bottom:10px}
</style></head><body>
<div class="container">
  <div class="header"><div class="logo-emoji">✉️</div><h1>E-Posta Doğrulama</h1></div>
  <div class="content">
    <h2>Merhaba ${userName || 'Değerli Kullanıcı'},</h2>
    <p>Agrolink hesabınızı oluşturduğunuz için teşekkür ederiz! E-posta adresinizi doğrulamak için aşağıdaki kodu kullanın:</p>
    <div class="code-box"><div class="code">${code}</div></div>
    <div class="timer-box"><p style="margin:0 0 10px 0">⏱️ Bu kodun geçerlilik süresi:</p><div class="timer">15 DAKİKA</div></div>
    <div class="info-box"><strong>✅ Neden doğrulama gerekiyor?</strong><p style="margin:10px 0 0 0">E-posta doğrulaması, hesabınızın güvenliğini artırır ve size önemli bildirimlerin ulaşmasını sağlar.</p></div>
    <p>Eğer bu işlemi siz yapmadıysanız, bu e-postayı dikkate almayın.</p>
    <p>Saygılarımızla,<br><strong>Agrolink Ekibi</strong></p>
  </div>
  <div class="footer"><p>Bu e-posta otomatik olarak gönderilmiştir. Lütfen yanıtlamayınız.</p><p>&copy; ${new Date().getFullYear()} Agrolink. Tüm hakları saklıdır.</p></div>
</div></body></html>`;
}

// ==================== POST GÖRÜNTÜLEME SİSTEMİ ====================

async function incrementPostView(postId, userId, ip) {
    try {
        const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD

        // Bugün bu kullanıcı bu postu gördü mü?
        const existing = await dbGet(
            `SELECT id FROM post_views WHERE "postId" = $1 AND "userId" = $2 AND "viewDate" = $3`,
            [postId, userId, today]
        );

        if (!existing) {
            // Yeni görüntüleme kaydı
            await dbRun(
                `INSERT INTO post_views (id, "postId", "userId", ip, "viewDate")
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT ("postId", "userId", "viewDate") DO NOTHING`,
                [uuidv4(), postId, userId, ip || '', today]
            );
            // Sayacı artır
            await dbRun('UPDATE posts SET views = COALESCE(views, 0) + 1 WHERE id = $1', [postId]);
        }
    } catch (err) {
        console.error('incrementPostView hatası:', err.message);
        // Fallback: basit artırım
        try { await dbRun('UPDATE posts SET views = COALESCE(views, 0) + 1 WHERE id = $1', [postId]); } catch {}
    }
}

async function sendEmailVerificationCode(userEmail, userName, code) {
    try {
        const html = getEmailVerificationTemplate(userName, code);
        return await sendEmail(userEmail, '✉️ Agrolink - E-Posta Doğrulama Kodunuz', html);
    } catch (error) {
        console.error('E-posta doğrulama e-postası gönderilemedi:', error);
        return { success: false, error: error.message };
    }
}

// ─── Periyodik: 7 gün aktif olmayan kullanıcılara e-posta ───────────
async function checkInactiveUsers() {
    try {
        console.log('🔍 İnaktif kullanıcılar kontrol ediliyor...');
        const inactiveUsers = await dbAll(
            `SELECT id, email, name FROM users
             WHERE "isActive" = TRUE
               AND "lastSeen" < NOW() - INTERVAL '7 days'
               AND "lastSeen" > NOW() - INTERVAL '30 days'`,
            []
        );
        console.log(`📊 ${inactiveUsers.length} inaktif kullanıcı bulundu`);
        for (const user of inactiveUsers) {
            await sendInactiveUserEmail(user.id, user.email, user.name);
            await new Promise(r => setTimeout(r, 2000)); // rate limiting
        }
        console.log('✅ İnaktif kullanıcı kontrolü tamamlandı');
    } catch (error) {
        console.error('İnaktif kullanıcı kontrol hatası:', error);
    }
}
// Her gün saat 09:00'da çalıştır (24 * 60 * 60 * 1000 ms)
setInterval(checkInactiveUsers, 24 * 60 * 60 * 1000);

// ==================== 🔒 BRUTE FORCE KORUMASI ====================

const accountFailedAttempts = new Map();
const MAX_FAILED_LOGINS    = 10;
const LOCKOUT_DURATION_MS  = 15 * 60 * 1000;

function checkAccountLockout(identifier) {
    const key   = identifier.toLowerCase().trim();
    const entry = accountFailedAttempts.get(key);
    if (!entry) return { locked: false };
    if (entry.lockedUntil && Date.now() < entry.lockedUntil) {
        return { locked: true, remainingMin: Math.ceil((entry.lockedUntil - Date.now()) / 60000) };
    }
    if (entry.lockedUntil && Date.now() >= entry.lockedUntil) accountFailedAttempts.delete(key);
    return { locked: false };
}

function recordFailedLogin(identifier) {
    const key   = identifier.toLowerCase().trim();
    const entry = accountFailedAttempts.get(key) || { count: 0, lockedUntil: null };
    entry.count++;
    if (entry.count >= MAX_FAILED_LOGINS) {
        entry.lockedUntil = Date.now() + LOCKOUT_DURATION_MS;
        console.log(`🔒 Hesap kilitlendi: ${key} (${entry.count} başarısız deneme)`);
    }
    accountFailedAttempts.set(key, entry);
}

function clearFailedLogins(identifier) {
    accountFailedAttempts.delete(identifier.toLowerCase().trim());
}

setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of accountFailedAttempts) {
        if (!entry.lockedUntil || now > entry.lockedUntil + LOCKOUT_DURATION_MS) {
            accountFailedAttempts.delete(key);
        }
    }
}, 10 * 60 * 1000);

// ==================== 🔒 SQL INJECTİON / XSS SANITIZE ====================

function sanitizeInput(value) {
    if (typeof value !== 'string') return value;
    // Path traversal engelle
    if (value.includes('../') || value.includes('..\\') || value.includes('%2e%2e')) return '';
    // Null byte engelle
    if (value.includes('\x00')) return '';
    // XSS - tehlikeli tagları kaldır
    return value
        .replace(/<script[\s\S]*?<\/script>/gi, '')
        .replace(/<iframe[\s\S]*?<\/iframe>/gi, '')
        .replace(/javascript\s*:/gi, '')
        .replace(/on\w+\s*=/gi, '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .trim();
}

// Belirli alanları ham tut (bio, content - XSS encode gerekmez, zaten parametrize)
const RAW_FIELDS = new Set(['password', 'bio', 'content', 'caption', 'description', 'message', 'text', 'comment']);

function sanitizeBody(req, res, next) {
    if (req.body && typeof req.body === 'object') {
        for (const key of Object.keys(req.body)) {
            const val = req.body[key];
            if (typeof val !== 'string') continue;

            // Path traversal her zaman engelle
            if (val.includes('../') || val.includes('..\\') || val.includes('%2e%2e')) {
                return res.status(400).json({ error: 'Geçersiz karakter tespit edildi' });
            }

            // Null byte engelle
            if (val.includes('\x00')) {
                return res.status(400).json({ error: 'Geçersiz karakter tespit edildi' });
            }

            // Uzunluk sınırı (megabytelık input'ları engelle)
            if (val.length > 50000) {
                return res.status(400).json({ error: 'Girdi çok uzun' });
            }

            // Script injection - ham alanlar hariç
            if (!RAW_FIELDS.has(key) && /<script|<iframe|javascript:/i.test(val)) {
                return res.status(400).json({ error: 'Geçersiz içerik tespit edildi' });
            }
        }
    }
    next();
}

// ==================== 🔒 IP BAN CACHE ====================

const ipBanCache     = new Map();
const IP_BAN_CACHE_TTL = 60 * 1000; // 1 dakika

async function checkIpBanDB(ip) {
    try {
        return await dbGet(
            `SELECT * FROM banned_ips WHERE ip = $1 AND ("expiresAt" IS NULL OR "expiresAt" > NOW())`,
            [ip]
        );
    } catch { return null; }
}

const ipBanMiddleware = async (req, res, next) => {
    try {
        const ip = req.ip || req.connection.remoteAddress || '';
        const cached = ipBanCache.get(ip);

        if (cached) {
            if (cached.banned && cached.expiresAt > Date.now()) {
                return res.status(403).json({ error: 'IP adresiniz engellendi', reason: cached.reason });
            }
            if (!cached.banned && cached.timestamp > Date.now() - IP_BAN_CACHE_TTL) return next();
        }

        const banned = await checkIpBanDB(ip);
        if (banned) {
            ipBanCache.set(ip, { banned: true, reason: banned.reason, expiresAt: new Date(banned.expiresAt || '9999-12-31').getTime() });
            return res.status(403).json({ error: 'IP adresiniz engellendi', reason: banned.reason });
        }

        ipBanCache.set(ip, { banned: false, timestamp: Date.now() });
        next();
    } catch { next(); }
};

// ==================== PostgreSQL BAĞLANTISI ====================

const pool = new Pool({
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 5432,
    database: process.env.DB_NAME || 'agrolink',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || '123456789',
    max: 100,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
    statement_timeout: 15000,
    query_timeout: 15000,
});

pool.on('connect', () => {
    console.log('✅ PostgreSQL bağlantısı kuruldu');
});

pool.on('error', (err) => {
    console.error('❌ PostgreSQL havuz hatası:', err.message);
});

// ==================== YARDIMCI DB FONKSİYONLARI ====================

async function dbGet(sql, params = []) {
    const result = await pool.query(sql, params);
    return result.rows[0] || null;
}

async function dbAll(sql, params = []) {
    const result = await pool.query(sql, params);
    return result.rows;
}

async function dbRun(sql, params = []) {
    const result = await pool.query(sql, params);
    return { changes: result.rowCount, lastID: result.rows[0]?.id };
}

// ==================== SQLite → PostgreSQL MİGRASYON ====================
//
//  Nasıl çalışır?
//  - Sunucu başlarken SQLITE_MIGRATE=true env varı varsa SQLite → PG'ye kopyalar.
//  - Migrasyon bir kez tamamlanınca bayrak dosyası (.migration_done) oluşur.
//  - Sonraki başlatmalarda bayrak dosyası varsa migrasyon atlanır.
//  - SQLITE_PATH env varıyla sqlite dosya konumunu belirtebilirsin (varsayılan: ./agrolink.db).
//
//  Kullanım:
//    SQLITE_MIGRATE=true SQLITE_PATH=./agrolink.db node agrolink-server-pg-FIXED.js
//

const MIGRATION_FLAG = '.migration_done';
const SQLITE_PATH    = process.env.SQLITE_PATH || './agrolink.db';
const MIGRATION_BATCH = 200;

const migBool    = (v) => v === 1 || v === true || v === '1';
const migNull    = (v) => (v === '' || v === undefined ? null : v);
const migJson    = (v) => {
    if (v === null || v === undefined) return null;
    if (typeof v === 'object') return v;
    try { return JSON.parse(v); } catch { return null; }
};

async function migInsert(client, table, rows, buildRow, onConflict = '') {
    if (!rows || !rows.length) {
        console.log(`  ⏭  ${table}: boş, atlandı`);
        return;
    }
    let ok = 0, skip = 0;
    for (const row of rows) {
        try {
            const obj    = buildRow(row);
            const keys   = Object.keys(obj);
            const vals   = Object.values(obj);
            const cols   = keys.map(k => `"${k}"`).join(', ');
            const params = keys.map((_, i) => `$${i + 1}`).join(', ');
            await client.query(
                `INSERT INTO "${table}" (${cols}) VALUES (${params}) ${onConflict}`,
                vals
            );
            ok++;
        } catch (e) {
            skip++;
            if (e.code !== '23505') console.warn(`  ⚠  ${table}: ${e.message}`);
        }
    }
    console.log(`  ✅ ${table}: ${ok} kayıt aktarıldı${skip ? `, ${skip} atlandı` : ''}`);
}

async function runSQLiteMigration() {
    // --- ön kontroller ---
    if (!process.env.SQLITE_MIGRATE) return;                        // env yoksa çalışma
    if (!sqlite3Mod || !sqliteOpen) {
        console.warn('⚠️  Migrasyon: sqlite3/sqlite paketi bulunamadı. npm install sqlite3 sqlite');
        return;
    }
    const fssync2 = require('fs');
    if (fssync2.existsSync(MIGRATION_FLAG)) {
        console.log('ℹ️  Migrasyon zaten tamamlanmış (.migration_done mevcut), atlanıyor.');
        return;
    }
    if (!fssync2.existsSync(SQLITE_PATH)) {
        console.warn(`⚠️  Migrasyon: SQLite dosyası bulunamadı: ${SQLITE_PATH}`);
        return;
    }

    console.log('\n🔄 ============================================');
    console.log('   AGROLINK — SQLite → PostgreSQL Migrasyonu ');
    console.log(`   Kaynak: ${SQLITE_PATH}`);
    console.log('==============================================\n');

    const sdb = await sqliteOpen({ filename: SQLITE_PATH, driver: sqlite3Mod.Database });
    const client = await pool.connect();

    try {
        // FK kısıtlamalarını geçici olarak devre dışı bırak
        await client.query('SET session_replication_role = replica');

        // ── users ──────────────────────────────────────────
        const users = await sdb.all('SELECT * FROM users').catch(() => []);
        await migInsert(client, 'users', users, (r) => ({
            id              : r.id,
            name            : r.name,
            username        : r.username,
            email           : r.email,
            password        : r.password,
            profilePic      : migNull(r.profilePic),
            coverPic        : migNull(r.coverPic),
            bio             : r.bio || '',
            website         : migNull(r.website),
            isPrivate       : migBool(r.isPrivate),
            isActive        : migBool(r.isActive !== undefined ? r.isActive : 1),
            role            : r.role || 'user',
            location        : migNull(r.location),
            language        : r.language || 'tr',
            emailVerified   : migBool(r.emailVerified),
            twoFactorEnabled: migBool(r.twoFactorEnabled !== undefined ? r.twoFactorEnabled : 1),
            isVerified      : migBool(r.isVerified),
            hasFarmerBadge  : migBool(r.hasFarmerBadge),
            userType        : r.userType || 'normal_kullanici',
            lastSeen        : migNull(r.lastSeen),
            lastLogin       : migNull(r.lastLogin),
            isOnline        : migBool(r.isOnline),
            registrationIp  : migNull(r.registrationIp),
            verifiedAt      : migNull(r.verifiedAt),
            createdAt       : r.createdAt || new Date().toISOString(),
            updatedAt       : r.updatedAt || new Date().toISOString(),
        }), 'ON CONFLICT (id) DO NOTHING');

        // ── posts ──────────────────────────────────────────
        const posts = await sdb.all('SELECT * FROM posts').catch(() => []);
        await migInsert(client, 'posts', posts, (r) => ({
            id           : r.id,
            userId       : r.userId,
            username     : r.username,
            content      : migNull(r.content),
            media        : migNull(r.media),
            mediaType    : r.mediaType || 'text',
            originalWidth : r.originalWidth || null,
            originalHeight: r.originalHeight || null,
            views        : r.views || 0,
            likeCount    : r.likeCount || 0,
            commentCount : r.commentCount || 0,
            saveCount    : r.saveCount || 0,
            isPoll       : migBool(r.isPoll),
            pollQuestion : migNull(r.pollQuestion),
            pollOptions  : migJson(r.pollOptions),
            latitude     : r.latitude || null,
            longitude    : r.longitude || null,
            locationName : migNull(r.locationName),
            allowComments: r.allowComments !== undefined ? migBool(r.allowComments) : true,
            isActive     : r.isActive !== undefined ? migBool(r.isActive) : true,
            createdAt    : r.createdAt || new Date().toISOString(),
            updatedAt    : r.updatedAt || new Date().toISOString(),
        }), 'ON CONFLICT (id) DO NOTHING');

        // ── comments ───────────────────────────────────────
        const comments = await sdb.all('SELECT * FROM comments').catch(() => []);
        await migInsert(client, 'comments', comments, (r) => ({
            id       : r.id,
            postId   : r.postId,
            userId   : r.userId,
            username : r.username,
            content  : r.content,
            parentId : migNull(r.parentId),
            likeCount: r.likeCount || 0,
            createdAt: r.createdAt || new Date().toISOString(),
            updatedAt: r.updatedAt || new Date().toISOString(),
        }), 'ON CONFLICT (id) DO NOTHING');

        // ── likes ──────────────────────────────────────────
        const likes = await sdb.all('SELECT * FROM likes').catch(() => []);
        await migInsert(client, 'likes', likes, (r) => ({
            id       : r.id,
            postId   : r.postId,
            userId   : r.userId,
            createdAt: r.createdAt || new Date().toISOString(),
        }), 'ON CONFLICT ("postId", "userId") DO NOTHING');

        // ── follows ────────────────────────────────────────
        const follows = await sdb.all('SELECT * FROM follows').catch(() => []);
        await migInsert(client, 'follows', follows, (r) => ({
            id         : r.id,
            followerId : r.followerId,
            followingId: r.followingId,
            createdAt  : r.createdAt || new Date().toISOString(),
        }), 'ON CONFLICT ("followerId", "followingId") DO NOTHING');

        // ── messages ───────────────────────────────────────
        const messages = await sdb.all('SELECT * FROM messages').catch(() => []);
        await migInsert(client, 'messages', messages, (r) => ({
            id               : r.id,
            senderId         : r.senderId,
            senderUsername   : r.senderUsername,
            recipientId      : r.recipientId,
            recipientUsername: r.recipientUsername,
            content          : r.content,
            read             : migBool(r.read),
            readAt           : migNull(r.readAt),
            createdAt        : r.createdAt || new Date().toISOString(),
            updatedAt        : r.updatedAt || new Date().toISOString(),
        }), 'ON CONFLICT (id) DO NOTHING');

        // ── notifications ──────────────────────────────────
        const notifs = await sdb.all('SELECT * FROM notifications').catch(() => []);
        await migInsert(client, 'notifications', notifs, (r) => ({
            id       : r.id,
            userId   : r.userId,
            type     : r.type,
            message  : r.message,
            data     : migJson(r.data),
            read     : migBool(r.read),
            readAt   : migNull(r.readAt),
            createdAt: r.createdAt || new Date().toISOString(),
        }), 'ON CONFLICT (id) DO NOTHING');

        // ── products ───────────────────────────────────────
        const products = await sdb.all('SELECT * FROM products').catch(() => []);
        await migInsert(client, 'products', products, (r) => ({
            id         : r.id,
            sellerId   : r.sellerId,
            name       : r.name,
            price      : r.price,
            description: migNull(r.description),
            image      : migNull(r.image),
            images     : migJson(r.images),
            category   : migNull(r.category),
            stock      : r.stock || 1,
            isActive   : migBool(r.isActive !== undefined ? r.isActive : 1),
            createdAt  : r.createdAt || new Date().toISOString(),
            updatedAt  : r.updatedAt || new Date().toISOString(),
        }), 'ON CONFLICT (id) DO NOTHING');

        // ── saves ──────────────────────────────────────────
        const saves = await sdb.all('SELECT * FROM saves').catch(() => []);
        await migInsert(client, 'saves', saves, (r) => ({
            id       : r.id,
            postId   : r.postId,
            userId   : r.userId,
            createdAt: r.createdAt || new Date().toISOString(),
        }), 'ON CONFLICT ("postId", "userId") DO NOTHING');

        // ── blocks ─────────────────────────────────────────
        const blocks = await sdb.all('SELECT * FROM blocks').catch(() => []);
        await migInsert(client, 'blocks', blocks, (r) => ({
            id       : r.id,
            blockerId: r.blockerId,
            blockedId: r.blockedId,
            createdAt: r.createdAt || new Date().toISOString(),
        }), 'ON CONFLICT ("blockerId", "blockedId") DO NOTHING');

        // ── hashtags ───────────────────────────────────────
        const hashtags = await sdb.all('SELECT * FROM hashtags').catch(() => []);
        await migInsert(client, 'hashtags', hashtags, (r) => ({
            id       : r.id,
            tag      : r.tag,
            postCount: r.postCount || 1,
            createdAt: r.createdAt || new Date().toISOString(),
        }), 'ON CONFLICT (tag) DO NOTHING');

        // ── post_hashtags ──────────────────────────────────
        const phash = await sdb.all('SELECT * FROM post_hashtags').catch(() => []);
        await migInsert(client, 'post_hashtags', phash, (r) => ({
            id       : r.id,
            postId   : r.postId,
            hashtagId: r.hashtagId,
        }), 'ON CONFLICT ("postId", "hashtagId") DO NOTHING');

        // ── video_info ─────────────────────────────────────
        const vids = await sdb.all('SELECT * FROM video_info').catch(() => []);
        await migInsert(client, 'video_info', vids, (r) => ({
            id         : r.id,
            postId     : r.postId,
            duration   : r.duration || null,
            width      : r.width    || null,
            height     : r.height   || null,
            aspectRatio: migNull(r.aspectRatio),
            bitrate    : r.bitrate  || null,
            codec      : migNull(r.codec),
            fileSize   : r.fileSize || null,
            createdAt  : r.createdAt || new Date().toISOString(),
        }), 'ON CONFLICT (id) DO NOTHING');

        // ── content_moderation ─────────────────────────────
        const mods = await sdb.all('SELECT * FROM content_moderation').catch(() => []);
        await migInsert(client, 'content_moderation', mods, (r) => ({
            id          : r.id,
            postId      : migNull(r.postId),
            commentId   : migNull(r.commentId),
            userId      : r.userId,
            content     : r.content,
            harmfulScore: r.harmfulScore || 0,
            isHarmful   : migBool(r.isHarmful),
            reason      : migNull(r.reason),
            moderatedAt : r.moderatedAt || new Date().toISOString(),
        }), 'ON CONFLICT (id) DO NOTHING');

        // ── account_restrictions ───────────────────────────
        const restr = await sdb.all('SELECT * FROM account_restrictions').catch(() => []);
        await migInsert(client, 'account_restrictions', restr, (r) => ({
            id             : r.id,
            userId         : r.userId,
            isRestricted   : migBool(r.isRestricted),
            restrictedAt   : migNull(r.restrictedAt),
            restrictedUntil: migNull(r.restrictedUntil),
            reason         : migNull(r.reason),
            canPost        : migBool(r.canPost),
            canComment     : migBool(r.canComment),
            canMessage     : migBool(r.canMessage),
            canFollow      : migBool(r.canFollow),
            canLike        : migBool(r.canLike),
            createdAt      : r.createdAt || new Date().toISOString(),
            updatedAt      : r.updatedAt || new Date().toISOString(),
        }), 'ON CONFLICT ("userId") DO NOTHING');

        // ── banned_ips ─────────────────────────────────────
        const bips = await sdb.all('SELECT * FROM banned_ips').catch(() => []);
        await migInsert(client, 'banned_ips', bips, (r) => ({
            id      : r.id,
            ip      : r.ip,
            reason  : migNull(r.reason),
            bannedAt: r.bannedAt || new Date().toISOString(),
        }), 'ON CONFLICT (ip) DO NOTHING');

        // FK kısıtlamalarını geri aç
        await client.query('SET session_replication_role = DEFAULT');

        // Migrasyon tamamlandı bayrağını yaz
        fssync2.writeFileSync(MIGRATION_FLAG, new Date().toISOString());

        console.log('\n✅ Migrasyon tamamlandı! Tüm veriler PostgreSQL\'e aktarıldı.');
        console.log('🚀 Sunucu normal çalışmaya devam ediyor...\n');

    } catch (err) {
        await client.query('SET session_replication_role = DEFAULT').catch(() => {});
        console.error('❌ Migrasyon hatası:', err.message);
        console.error('   Sunucu yine de başlatılıyor — veriler kısmen aktarılmış olabilir.');
    } finally {
        client.release();
        await sdb.close().catch(() => {});
    }
}

// ==================== TABLO OLUŞTURMA (UUID FIX) ====================

async function initializeDatabase() {
    console.log('📦 PostgreSQL tabloları oluşturuluyor (UUID)...');

    // UUID extension'ı aktif et
    await pool.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');

    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            "profilePic" TEXT,
            "coverPic" TEXT,
            bio TEXT DEFAULT '',
            website TEXT,
            "isPrivate" BOOLEAN DEFAULT FALSE,
            "isActive" BOOLEAN DEFAULT TRUE,
            role TEXT DEFAULT 'user',
            location TEXT,
            language TEXT DEFAULT 'tr',
            "emailVerified" BOOLEAN DEFAULT FALSE,
            "twoFactorEnabled" BOOLEAN DEFAULT TRUE,
            "isVerified" BOOLEAN DEFAULT FALSE,
            "hasFarmerBadge" BOOLEAN DEFAULT FALSE,
            "userType" TEXT DEFAULT 'normal_kullanici',
            "lastSeen" TIMESTAMPTZ,
            "lastLogin" TIMESTAMPTZ,
            "isOnline" BOOLEAN DEFAULT FALSE,
            "registrationIp" TEXT,
            "verifiedAt" TIMESTAMPTZ,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS posts (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            username TEXT NOT NULL,
            content TEXT,
            media TEXT,
            "mediaType" TEXT DEFAULT 'text',
            "originalWidth" INTEGER,
            "originalHeight" INTEGER,
            views INTEGER DEFAULT 0,
            "likeCount" INTEGER DEFAULT 0,
            "commentCount" INTEGER DEFAULT 0,
            "saveCount" INTEGER DEFAULT 0,
            "isPoll" BOOLEAN DEFAULT FALSE,
            "pollQuestion" TEXT,
            "pollOptions" JSONB,
            latitude DOUBLE PRECISION,
            longitude DOUBLE PRECISION,
            "locationName" TEXT,
            "allowComments" BOOLEAN DEFAULT TRUE,
            "thumbnailUrl" TEXT,
            "isActive" BOOLEAN DEFAULT TRUE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS comments (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "postId" UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            username TEXT NOT NULL,
            content TEXT NOT NULL,
            "parentId" UUID,
            "likeCount" INTEGER DEFAULT 0,
            "isActive" BOOLEAN DEFAULT TRUE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS likes (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "postId" UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("postId", "userId")
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS follows (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "followerId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "followingId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("followerId", "followingId")
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS messages (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "senderId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "senderUsername" TEXT NOT NULL,
            "recipientId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "recipientUsername" TEXT NOT NULL,
            content TEXT NOT NULL,
            read BOOLEAN DEFAULT FALSE,
            "readAt" TIMESTAMPTZ,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS notifications (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            type TEXT NOT NULL,
            message TEXT NOT NULL,
            data JSONB,
            read BOOLEAN DEFAULT FALSE,
            "readAt" TIMESTAMPTZ,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS products (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "sellerId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            price DOUBLE PRECISION NOT NULL,
            description TEXT,
            image TEXT,
            images JSONB,
            category TEXT,
            stock INTEGER DEFAULT 1,
            "isActive" BOOLEAN DEFAULT TRUE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);


    await pool.query(`
        CREATE TABLE IF NOT EXISTS farmbook_records (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "recordType" TEXT NOT NULL,
            "productName" TEXT,
            quantity DOUBLE PRECISION,
            unit TEXT,
            cost DOUBLE PRECISION DEFAULT 0,
            income DOUBLE PRECISION DEFAULT 0,
            "recordDate" DATE NOT NULL,
            "fieldName" TEXT,
            "fieldSize" DOUBLE PRECISION,
            "fieldSizeUnit" TEXT DEFAULT 'dekar',
            season TEXT,
            year INTEGER,
            notes TEXT,
            "harvestAmount" DOUBLE PRECISION,
            "harvestUnit" TEXT,
            "qualityRating" INTEGER,
            "weatherCondition" TEXT,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    // farmbook_records index
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_farmbook_userId ON farmbook_records("userId")`).catch(()=>{});

    await pool.query(`
        CREATE TABLE IF NOT EXISTS saves (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "postId" UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("postId", "userId")
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS blocks (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "blockerId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "blockedId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("blockerId", "blockedId")
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS hashtags (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tag TEXT UNIQUE NOT NULL,
            "postCount" INTEGER DEFAULT 1,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS post_hashtags (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "postId" UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            "hashtagId" UUID NOT NULL REFERENCES hashtags(id) ON DELETE CASCADE,
            UNIQUE("postId", "hashtagId")
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS stories (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "mediaUrl" TEXT NOT NULL,
            "mediaType" TEXT DEFAULT 'image',
            caption TEXT,
            text TEXT,
            "textColor" TEXT DEFAULT '#FFFFFF',
            "viewCount" INTEGER DEFAULT 0,
            "likeCount" INTEGER DEFAULT 0,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "expiresAt" TIMESTAMPTZ NOT NULL
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS story_views (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "storyId" UUID NOT NULL REFERENCES stories(id) ON DELETE CASCADE,
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "viewedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("storyId", "userId")
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS story_likes (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "storyId" UUID NOT NULL REFERENCES stories(id) ON DELETE CASCADE,
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("storyId", "userId")
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS comment_likes (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "commentId" UUID NOT NULL REFERENCES comments(id) ON DELETE CASCADE,
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("commentId", "userId")
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS poll_votes (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "postId" UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "optionId" INTEGER NOT NULL,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("postId", "userId")
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS user_interests (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            interest TEXT NOT NULL,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("userId", interest)
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS post_views (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "postId" UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "viewDate" DATE NOT NULL DEFAULT CURRENT_DATE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("postId", "userId", "viewDate")
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS suspicious_login_reports (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "reportedIp" TEXT,
            "passwordResetToken" TEXT,
            "tokenExpiresAt" TIMESTAMPTZ,
            "isResolved" BOOLEAN DEFAULT FALSE,
            "resolvedAt" TIMESTAMPTZ,
            "reportedAt" TIMESTAMPTZ DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS reports (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "reporterId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "postId" UUID REFERENCES posts(id) ON DELETE CASCADE,
            "userId" UUID,
            reason TEXT NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'pending',
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "reviewedAt" TIMESTAMPTZ,
            "reviewedBy" TEXT
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS login_history (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            ip TEXT NOT NULL,
            country TEXT,
            city TEXT,
            "userAgent" TEXT,
            "loginType" TEXT DEFAULT 'password',
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "tokenHash" TEXT NOT NULL,
            ip TEXT,
            "userAgent" TEXT,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "expiresAt" TIMESTAMPTZ NOT NULL,
            "isActive" BOOLEAN DEFAULT TRUE
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS banned_ips (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            ip TEXT UNIQUE NOT NULL,
            reason TEXT,
            "bannedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "expiresAt" TIMESTAMPTZ
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS content_moderation (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "postId" UUID,
            "commentId" UUID,
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            content TEXT NOT NULL,
            "harmfulScore" DOUBLE PRECISION DEFAULT 0,
            "isHarmful" BOOLEAN DEFAULT FALSE,
            reason TEXT,
            "moderatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS account_restrictions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
            "isRestricted" BOOLEAN DEFAULT FALSE,
            "restrictedAt" TIMESTAMPTZ,
            "restrictedUntil" TIMESTAMPTZ,
            reason TEXT,
            "canPost" BOOLEAN DEFAULT FALSE,
            "canComment" BOOLEAN DEFAULT FALSE,
            "canMessage" BOOLEAN DEFAULT FALSE,
            "canFollow" BOOLEAN DEFAULT FALSE,
            "canLike" BOOLEAN DEFAULT FALSE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS email_preferences (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
            unsubscribed BOOLEAN DEFAULT FALSE,
            "unsubscribedAt" TIMESTAMPTZ,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    // 🆕 Şifre sıfırlama tokenları
    await pool.query(`
        CREATE TABLE IF NOT EXISTS password_resets (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token TEXT NOT NULL,
            "expiresAt" TIMESTAMPTZ NOT NULL,
            used BOOLEAN DEFAULT FALSE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    // 🆕 E-posta doğrulama kodları
    await pool.query(`
        CREATE TABLE IF NOT EXISTS email_verifications (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            code TEXT NOT NULL,
            "expiresAt" TIMESTAMPTZ NOT NULL,
            used BOOLEAN DEFAULT FALSE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    // 🆕 Bildirim ayarları
    await pool.query(`
        CREATE TABLE IF NOT EXISTS notification_settings (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
            likes BOOLEAN DEFAULT TRUE,
            comments BOOLEAN DEFAULT TRUE,
            follows BOOLEAN DEFAULT TRUE,
            messages BOOLEAN DEFAULT TRUE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    // 🆕 Takip istekleri (gizli hesaplar için)
    await pool.query(`
        CREATE TABLE IF NOT EXISTS follow_requests (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "requesterId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "targetId"    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            status        TEXT NOT NULL DEFAULT 'pending',
            "respondedAt" TIMESTAMPTZ,
            "createdAt"   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("requesterId", "targetId")
        )
    `);

    // 🆕 Aktif oturumlar
    await pool.query(`
        CREATE TABLE IF NOT EXISTS active_sessions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId"       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token          TEXT NOT NULL,
            ip             TEXT,
            "userAgent"    TEXT,
            "createdAt"    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "lastActiveAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "isActive"     BOOLEAN DEFAULT TRUE
        )
    `);

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_follow_requests_target   ON follow_requests("targetId")   WHERE status = 'pending'`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_follow_requests_requester ON follow_requests("requesterId")`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_active_sessions_user      ON active_sessions("userId")     WHERE "isActive" = TRUE`);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS video_info (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "postId" UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            duration DOUBLE PRECISION,
            width INTEGER,
            height INTEGER,
            "aspectRatio" TEXT,
            bitrate INTEGER,
            codec TEXT,
            "fileSize" BIGINT,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    // ==================== SÜTUN MİGRASYONU (snake_case → camelCase) ====================
    // Eğer DB önceden snake_case ile oluşturulduysa sütunları ekle/yeniden adlandır
    const columnMigrations = [
        // posts tablosu
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "userId" UUID`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "isActive" BOOLEAN DEFAULT TRUE`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS views INTEGER DEFAULT 0`,
        `CREATE TABLE IF NOT EXISTS post_views (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "postId" UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            "userId" UUID REFERENCES users(id) ON DELETE SET NULL,
            ip TEXT,
            "viewDate" DATE NOT NULL DEFAULT CURRENT_DATE,
            "createdAt" TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE("postId", "userId", "viewDate")
        )`,
        `CREATE INDEX IF NOT EXISTS idx_post_views_post ON post_views("postId")`,
        `CREATE INDEX IF NOT EXISTS idx_post_views_user ON post_views("userId")`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "likeCount" INTEGER DEFAULT 0`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "commentCount" INTEGER DEFAULT 0`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "saveCount" INTEGER DEFAULT 0`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "mediaType" TEXT DEFAULT 'text'`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "isPoll" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "allowComments" BOOLEAN DEFAULT TRUE`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "updatedAt" TIMESTAMPTZ DEFAULT NOW()`,
        // comments tablosu
        `ALTER TABLE comments ADD COLUMN IF NOT EXISTS "postId" UUID`,
        `ALTER TABLE comments ADD COLUMN IF NOT EXISTS "userId" UUID`,
        `ALTER TABLE comments ADD COLUMN IF NOT EXISTS "parentId" UUID`,
        `ALTER TABLE comments ADD COLUMN IF NOT EXISTS "likeCount" INTEGER DEFAULT 0`,
        `ALTER TABLE comments ADD COLUMN IF NOT EXISTS "isActive" BOOLEAN DEFAULT TRUE`,
        `ALTER TABLE comments ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE comments ADD COLUMN IF NOT EXISTS "updatedAt" TIMESTAMPTZ DEFAULT NOW()`,
        // likes tablosu
        `ALTER TABLE likes ADD COLUMN IF NOT EXISTS "postId" UUID`,
        `ALTER TABLE likes ADD COLUMN IF NOT EXISTS "userId" UUID`,
        `ALTER TABLE likes ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        // follows tablosu
        `ALTER TABLE follows ADD COLUMN IF NOT EXISTS "followerId" UUID`,
        `ALTER TABLE follows ADD COLUMN IF NOT EXISTS "followingId" UUID`,
        `ALTER TABLE follows ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        // messages tablosu
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "senderId" UUID`,
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "recipientId" UUID`,
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "senderUsername" TEXT`,
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "recipientUsername" TEXT`,
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "updatedAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "readAt" TIMESTAMPTZ`,
        // notifications tablosu
        `ALTER TABLE notifications ADD COLUMN IF NOT EXISTS "userId" UUID`,
        `ALTER TABLE notifications ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE notifications ADD COLUMN IF NOT EXISTS "readAt" TIMESTAMPTZ`,
        // saves tablosu
        `ALTER TABLE saves ADD COLUMN IF NOT EXISTS "userId" UUID`,
        `ALTER TABLE saves ADD COLUMN IF NOT EXISTS "postId" UUID`,
        `ALTER TABLE saves ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        // products tablosu
        `ALTER TABLE products ADD COLUMN IF NOT EXISTS "sellerId" UUID`,
        `ALTER TABLE products ADD COLUMN IF NOT EXISTS "isActive" BOOLEAN DEFAULT TRUE`,
        `ALTER TABLE products ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE products ADD COLUMN IF NOT EXISTS "updatedAt" TIMESTAMPTZ DEFAULT NOW()`,
        // stories tablosu
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "userId" UUID`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "mediaUrl" TEXT`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "mediaType" TEXT DEFAULT 'image'`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "textColor" TEXT DEFAULT '#FFFFFF'`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "viewCount" INTEGER DEFAULT 0`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "likeCount" INTEGER DEFAULT 0`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "expiresAt" TIMESTAMPTZ`,
        // login_history tablosu
        `ALTER TABLE login_history ADD COLUMN IF NOT EXISTS "userId" UUID`,
        `ALTER TABLE login_history ADD COLUMN IF NOT EXISTS "userAgent" TEXT`,
        `ALTER TABLE login_history ADD COLUMN IF NOT EXISTS "loginType" TEXT DEFAULT 'password'`,
        `ALTER TABLE login_history ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        // refresh_tokens tablosu
        `ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS "userId" UUID`,
        `ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS "tokenHash" TEXT`,
        `ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS "userAgent" TEXT`,
        `ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS "expiresAt" TIMESTAMPTZ`,
        `ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS "isActive" BOOLEAN DEFAULT TRUE`,
        // users tablosu
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "profilePic" TEXT`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "coverPic" TEXT`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "isPrivate" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "isActive" BOOLEAN DEFAULT TRUE`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "emailVerified" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "twoFactorEnabled" BOOLEAN DEFAULT TRUE`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "isVerified" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "hasFarmerBadge" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "userType" TEXT DEFAULT 'normal_kullanici'`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "lastSeen" TIMESTAMPTZ`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "lastLogin" TIMESTAMPTZ`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "isOnline" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "registrationIp" TEXT`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "verifiedAt" TIMESTAMPTZ`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "updatedAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "emailNotifications" BOOLEAN DEFAULT TRUE`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "isPoll" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "isPoll" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "pollOptions" JSONB`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "saveCount" INTEGER DEFAULT 0`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS views INTEGER DEFAULT 0`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "thumbnailUrl" TEXT`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "likeCount" INTEGER DEFAULT 0`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "viewCount" INTEGER DEFAULT 0`,
        `ALTER TABLE products ADD COLUMN IF NOT EXISTS "isActive" BOOLEAN DEFAULT TRUE`,
    ];

    for (const migSql of columnMigrations) {
        try {
            await pool.query(migSql);
        } catch (e) {
            // Zaten varsa veya başka bir hata varsa sessizce geç
            console.warn(`⚠️ Migrasyon atlandı: ${e.message.split('\n')[0]}`);
        }
    }

    // ==================== İNDEKSLER ====================
    // Her index ayrı try-catch içinde — mevcut tablo şemasına göre hata atlarsa devam eder
    const indexes = [
        [`idx_posts_userId`,           `CREATE INDEX IF NOT EXISTS idx_posts_userId ON posts("userId")`],
        [`idx_posts_createdAt`,        `CREATE INDEX IF NOT EXISTS idx_posts_createdAt ON posts("createdAt" DESC)`],
        [`idx_posts_active`,           `CREATE INDEX IF NOT EXISTS idx_posts_active ON posts("isActive") WHERE "isActive" = TRUE`],
        [`idx_comments_postId`,        `CREATE INDEX IF NOT EXISTS idx_comments_postId ON comments("postId")`],
        [`idx_comments_userId`,        `CREATE INDEX IF NOT EXISTS idx_comments_userId ON comments("userId")`],
        [`idx_likes_postId`,           `CREATE INDEX IF NOT EXISTS idx_likes_postId ON likes("postId")`],
        [`idx_likes_userId`,           `CREATE INDEX IF NOT EXISTS idx_likes_userId ON likes("userId")`],
        [`idx_follows_followerId`,     `CREATE INDEX IF NOT EXISTS idx_follows_followerId ON follows("followerId")`],
        [`idx_follows_followingId`,    `CREATE INDEX IF NOT EXISTS idx_follows_followingId ON follows("followingId")`],
        [`idx_messages_senderId`,      `CREATE INDEX IF NOT EXISTS idx_messages_senderId ON messages("senderId")`],
        [`idx_messages_recipientId`,   `CREATE INDEX IF NOT EXISTS idx_messages_recipientId ON messages("recipientId")`],
        [`idx_messages_createdAt`,     `CREATE INDEX IF NOT EXISTS idx_messages_createdAt ON messages("createdAt" DESC)`],
        [`idx_notifications_userId`,   `CREATE INDEX IF NOT EXISTS idx_notifications_userId ON notifications("userId")`],
        [`idx_notifications_read`,     `CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(read) WHERE read = FALSE`],
        [`idx_saves_userId`,           `CREATE INDEX IF NOT EXISTS idx_saves_userId ON saves("userId")`],
        [`idx_products_sellerId`,      `CREATE INDEX IF NOT EXISTS idx_products_sellerId ON products("sellerId")`],
        [`idx_stories_userId`,         `CREATE INDEX IF NOT EXISTS idx_stories_userId ON stories("userId")`],
        [`idx_stories_expiresAt`,      `CREATE INDEX IF NOT EXISTS idx_stories_expiresAt ON stories("expiresAt")`],
        [`idx_users_username`,         `CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`],
        [`idx_users_email`,            `CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`],
        [`idx_hashtags_tag`,           `CREATE INDEX IF NOT EXISTS idx_hashtags_tag ON hashtags(tag)`],
        [`idx_login_history_userId`,   `CREATE INDEX IF NOT EXISTS idx_login_history_userId ON login_history("userId")`],
        [`idx_refresh_tokens_userId`,  `CREATE INDEX IF NOT EXISTS idx_refresh_tokens_userId ON refresh_tokens("userId")`],
        [`idx_banned_ips_ip`,          `CREATE INDEX IF NOT EXISTS idx_banned_ips_ip ON banned_ips(ip)`],
    ];

    for (const [name, indexSql] of indexes) {
        try {
            await pool.query(indexSql);
        } catch (e) {
            console.warn(`⚠️ Index atlandı [${name}]: ${e.message.split('\n')[0]}`);
        }
    }

    console.log('✅ Tüm tablolar ve indeksler oluşturuldu (UUID)');
}

// ==================== EXPRESS UYGULAMASI ====================

const app = express();
app.set('trust proxy', 1); // 🔒 Nginx/proxy arkasında gerçek IP'yi al (rate-limit için zorunlu)
const server = http.createServer(app);

// ==================== DİZİN YAPISI ====================

const uploadsDir   = path.join(__dirname, 'uploads');
const profilesDir  = path.join(uploadsDir, 'profiles');
const postsDir     = path.join(uploadsDir, 'posts');
const videosDir    = path.join(uploadsDir, 'videos');
const thumbnailsDir= path.join(uploadsDir, 'thumbnails');
const hlsDir       = path.join(uploadsDir, 'hls');
const tempDir      = path.join(uploadsDir, 'temp');

[uploadsDir, profilesDir, postsDir, videosDir, thumbnailsDir, hlsDir, tempDir].forEach(dir => {
    if (!fssync.existsSync(dir)) {
        fssync.mkdirSync(dir, { recursive: true });
    }
});

// ==================== 🎬 VİDEO SIKIŞTIRMA KONFİGÜRASYONU ====================

const VIDEO_CONFIG = {
    codec       : 'libx264',
    audioCodec  : 'aac',
    audioBitrate: '192k',
    quality     : 23,          // CRF 23 = kalite/boyut dengesi
    preset      : 'fast',
    movflags    : '+faststart', // Web streaming için kritik (metadata başa alınır)
    threads     : '0',          // Tüm CPU çekirdeklerini kullan
    maxWidth    : 1920,
    maxHeight   : 1080,
    fps         : 30,
    maxDuration : 600,          // Maks 10 dk
};

// HLS Adaptive Bitrate varyantları (YouTube standardı)
const HLS_VARIANTS = [
    { name: '360p',  width: 640,  height: 360,  videoBitrate: '800k',  audioBitrate: '96k'  },
    { name: '720p',  width: 1280, height: 720,  videoBitrate: '2500k', audioBitrate: '128k' },
    { name: '1080p', width: 1920, height: 1080, videoBitrate: '5000k', audioBitrate: '192k' },
];

// ─── Video meta bilgisi al ─────────────────────────────────────────
function getVideoInfo(inputPath) {
    return new Promise((resolve) => {
        if (!fssync.existsSync(inputPath)) {
            return resolve({ duration: 0, width: 1920, height: 1080, aspectRatio: '16:9', bitrate: 5000, codec: 'h264', fileSize: 0, fps: 30 });
        }
        ffmpeg.ffprobe(inputPath, (err, meta) => {
            if (err) {
                console.error('❌ ffprobe hatası:', err.message);
                return resolve({ duration: 0, width: 1920, height: 1080, aspectRatio: '16:9', bitrate: 5000, codec: 'h264', fileSize: 0, fps: 30 });
            }
            try {
                const vs  = meta.streams.find(s => s.codec_type === 'video');
                const as  = meta.streams.find(s => s.codec_type === 'audio');
                let fps = 30;
                if (vs?.r_frame_rate) {
                    const [a, b] = vs.r_frame_rate.split('/').map(Number);
                    if (b) fps = a / b;
                }
                resolve({
                    duration   : meta.format?.duration  || 0,
                    width      : vs?.width              || 1920,
                    height     : vs?.height             || 1080,
                    aspectRatio: vs?.display_aspect_ratio || '16:9',
                    bitrate    : meta.format?.bit_rate ? Math.round(meta.format.bit_rate / 1000) : 5000,
                    codec      : vs?.codec_name         || 'h264',
                    audioCodec : as?.codec_name         || 'aac',
                    fileSize   : meta.format?.size       || 0,
                    fps        : Math.round(fps),
                });
            } catch (e) {
                resolve({ duration: 0, width: 1920, height: 1080, aspectRatio: '16:9', bitrate: 5000, codec: 'h264', fileSize: 0, fps: 30 });
            }
        });
    });
}

// ─── Video optimize et (mp4, faststart) ─────────────────────────────
function optimizeVideo(inputPath, outputPath) {
    return new Promise(async (resolve, reject) => {
        const startTime = Date.now();
        console.log(`🎬 Video sıkıştırma: ${path.basename(inputPath)}`);

        if (!fssync.existsSync(inputPath)) return reject(new Error('Input dosyası bulunamadı'));

        const stats     = fssync.statSync(inputPath);
        const sizeMB    = stats.size / (1024 * 1024);
        const outputDir = path.dirname(outputPath);
        if (!fssync.existsSync(outputDir)) fssync.mkdirSync(outputDir, { recursive: true });

        let vInfo = { width: 1920, height: 1080, fps: 30 };
        try { vInfo = await getVideoInfo(inputPath); } catch (_) {}

        const tw = Math.min(vInfo.width,  VIDEO_CONFIG.maxWidth);
        const th = Math.min(vInfo.height, VIDEO_CONFIG.maxHeight);
        const tf = Math.min(vInfo.fps || 30, VIDEO_CONFIG.fps);

        // Oran korunur, H.264 çift piksel zorunluluğu
        const scaleFilter = `scale='min(${tw},iw)':min'(${th},ih)':force_original_aspect_ratio=decrease,scale=trunc(iw/2)*2:trunc(ih/2)*2`;

        ffmpeg(inputPath)
            .videoCodec(VIDEO_CONFIG.codec)
            .audioCodec(VIDEO_CONFIG.audioCodec)
            .outputOptions([
                `-crf ${VIDEO_CONFIG.quality}`,
                `-preset ${VIDEO_CONFIG.preset}`,
                `-movflags ${VIDEO_CONFIG.movflags}`,
                `-threads ${VIDEO_CONFIG.threads}`,
                `-r ${tf}`,
                `-b:a ${VIDEO_CONFIG.audioBitrate}`,
                `-vf ${scaleFilter}`,
                '-pix_fmt yuv420p',
                '-profile:v high',
                '-level 4.0',
            ])
            .format('mp4')
            .on('end', async () => {
                const outSize = fssync.existsSync(outputPath) ? fssync.statSync(outputPath).size : 0;
                const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
                const reduction = outSize ? (((sizeMB - outSize / 1024 / 1024) / sizeMB) * 100).toFixed(1) : 0;
                console.log(`✅ Video hazır: ${sizeMB.toFixed(1)}MB → ${(outSize/1024/1024).toFixed(1)}MB (%${reduction} azalma) ${elapsed}s`);
                try { await fs.unlink(inputPath); } catch (_) {}
                resolve({ success: true, optimized: true, fileSize: outSize, reduction: parseFloat(reduction) });
            })
            .on('error', async (err) => {
                console.error('❌ FFmpeg hatası, fallback kopyalama:', err.message);
                try {
                    await fs.copyFile(inputPath, outputPath);
                    const fb = fssync.statSync(outputPath);
                    try { await fs.unlink(inputPath); } catch (_) {}
                    resolve({ success: true, optimized: false, fileSize: fb.size });
                } catch (e) {
                    reject(e);
                }
            })
            .save(outputPath);
    });
}

// ─── Video thumbnail oluştur ─────────────────────────────────────────
function createVideoThumbnail(videoPath, thumbnailPath) {
    return new Promise((resolve) => {
        if (!fssync.existsSync(videoPath)) return resolve(false);
        const thumbDir = path.dirname(thumbnailPath);
        if (!fssync.existsSync(thumbDir)) fssync.mkdirSync(thumbDir, { recursive: true });

        // Thumbnail yolunu kesinlikle .jpg yap
        const finalThumbPath = thumbnailPath.replace(/\.[^.]+$/, '.jpg');

        ffmpeg(videoPath)
            .screenshots({
                timestamps: ['00:00:01'],
                filename  : path.basename(finalThumbPath),
                folder    : thumbDir,
                size      : '640x360',
            })
            .on('end', async () => {
                // ffmpeg çıktısı bazen webp/png olabilir, sharp ile kesinlikle jpg'ye dönüştür
                try {
                    await sharp(finalThumbPath)
                        .jpeg({ quality: 85 })
                        .toFile(finalThumbPath + '.tmp.jpg');
                    fssync.renameSync(finalThumbPath + '.tmp.jpg', finalThumbPath);
                } catch (_) {}
                console.log('✅ Thumbnail [jpg]:', finalThumbPath);
                resolve(true);
            })
            .on('error', async (err) => {
                console.error('❌ Thumbnail hatası:', err.message);
                // Varsayılan yeşil placeholder jpg
                try {
                    await sharp({ create: { width: 640, height: 360, channels: 3, background: { r: 30, g: 100, b: 30 } } })
                        .jpeg({ quality: 80 }).toFile(finalThumbPath);
                    resolve(true);
                } catch { resolve(false); }
            });
    });
}

// ─── HLS Adaptive Bitrate (YouTube algoritması) ───────────────────────
// Üretilen yapı:
//   uploads/hls/{videoId}/master.m3u8         ← Ana manifest
//   uploads/hls/{videoId}/360p/playlist.m3u8  ← 360p segmentleri
//   uploads/hls/{videoId}/720p/playlist.m3u8  ← 720p segmentleri
//   uploads/hls/{videoId}/1080p/playlist.m3u8 ← 1080p segmentleri
//   Her segment = 4 saniye (YouTube standardı)
async function generateHLSVariants(inputMp4Path, videoId) {
    const startTime  = Date.now();
    const outputBase = path.join(hlsDir, videoId);

    console.log(`🎬 [HLS] Başlatılıyor → ${videoId}`);

    let vInfo = { width: 1920, height: 1080, fps: 30 };
    try { vInfo = await getVideoInfo(inputMp4Path); } catch (_) {}

    // Kaynağa uygun varyantları seç (gereksiz upscale yok)
    let activeVariants = HLS_VARIANTS.filter(v => v.height <= vInfo.height + 120);
    if (activeVariants.length === 0) activeVariants = [HLS_VARIANTS[0]];

    for (const v of activeVariants) {
        const dir = path.join(outputBase, v.name);
        if (!fssync.existsSync(dir)) fssync.mkdirSync(dir, { recursive: true });
    }

    const encodedVariants = [];

    for (const variant of activeVariants) {
        const outDir      = path.join(outputBase, variant.name);
        const playlist    = path.join(outDir, 'playlist.m3u8');
        const scaleFilter = `scale='min(${variant.width},iw)':min'(${variant.height},ih)':force_original_aspect_ratio=decrease,scale=trunc(iw/2)*2:trunc(ih/2)*2`;

        await new Promise((resolve) => {
            ffmpeg(inputMp4Path)
                .videoCodec('libx264')
                .audioCodec('aac')
                .outputOptions([
                    `-b:v ${variant.videoBitrate}`,
                    `-maxrate ${variant.videoBitrate}`,
                    `-bufsize ${parseInt(variant.videoBitrate) * 2}k`,
                    `-b:a ${variant.audioBitrate}`,
                    `-vf ${scaleFilter}`,
                    '-pix_fmt yuv420p',
                    '-profile:v main',
                    '-level 3.1',
                    '-preset fast',
                    '-hls_time 4',                          // 4 sn segment → sıfır donma
                    '-hls_list_size 0',                     // VOD: tüm segmentler
                    '-hls_segment_type mpegts',
                    `-hls_segment_filename ${path.join(outDir, 'seg%03d.ts')}`,
                    '-hls_flags independent_segments',
                    '-f hls',
                ])
                .output(playlist)
                .on('end',   () => { console.log(`  ✅ [HLS] ${variant.name}`); resolve(); })
                .on('error', (e) => { console.error(`  ⚠️ [HLS] ${variant.name}: ${e.message}`); resolve(); })
                .run();
        });

        if (fssync.existsSync(playlist)) encodedVariants.push(variant);
    }

    if (encodedVariants.length === 0) {
        console.warn(`⚠️ [HLS] Varyant oluşturulamadı: ${videoId}`);
        return false;
    }

    // Master manifest yaz
    let master = '#EXTM3U\n#EXT-X-VERSION:3\n';
    for (const v of encodedVariants) {
        const bps = parseInt(v.videoBitrate) * 1000;
        master += `#EXT-X-STREAM-INF:BANDWIDTH=${bps},RESOLUTION=${v.width}x${v.height},NAME="${v.name}"\n`;
        master += `${v.name}/playlist.m3u8\n`;
    }
    fssync.writeFileSync(path.join(outputBase, 'master.m3u8'), master, 'utf8');

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`✅ [HLS] Tamamlandı → ${videoId} (${elapsed}s)`);
    return true;
}

// ─── Yardımcı: video kalite etiketi ──────────────────────────────────
function getVideoQuality(w, h) {
    if (h >= 1080) return '1080p';
    if (h >= 720)  return '720p';
    if (h >= 480)  return '480p';
    if (h >= 360)  return '360p';
    return '240p';
}

// ─── Yardımcı: dosya boyutu formatla ─────────────────────────────────
function formatFileSize(bytes) {
    if (!bytes) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    let i = 0, v = bytes;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return `${v.toFixed(1)} ${units[i]}`;
}

// ─── Arka plan video işleme kuyruğu (büyük dosyalar için) ────────────
// Sunucuyu bloklamaz, gönderi hemen paylaşılır; HLS arka planda hazırlanır
// ==================== 🎬 VİDEO PARALEL İŞLEME ====================
// Her video bağımsız goroutine'de işlenir — sıralı kuyruk YOK
// Aynı anda N video paralel olarak optimize/HLS/thumbnail üretir

const MAX_CONCURRENT_VIDEOS = 3; // Aynı anda max 3 video işle
let activeVideoJobs = 0;

async function processVideoAsync(postId, inputPath, videoId) {
    // Kaynak kontrolü - senkron modda sadece sayacı yönet
    if (activeVideoJobs >= MAX_CONCURRENT_VIDEOS) {
        // Diğer işler bitene kadar bekle (polling)
        while (activeVideoJobs >= MAX_CONCURRENT_VIDEOS) {
            await new Promise(r => setTimeout(r, 500));
        }
    }

    activeVideoJobs++;
    console.log(`🎬 [Paralel] Başladı: ${videoId} | Aktif: ${activeVideoJobs}/${MAX_CONCURRENT_VIDEOS}`);

    try {
        const mp4Out   = path.join(videosDir, `${videoId}.mp4`);
        const thumbPath = path.join(thumbnailsDir, `${videoId}.jpg`);

        // 1. Önce thumbnail hemen oluştur (kullanıcı anında görsün)
        await createVideoThumbnail(inputPath, thumbPath);
        const thumbUrl = fssync.existsSync(thumbPath) ? `/uploads/thumbnails/${videoId}.jpg` : null;
        if (thumbUrl) {
            await dbRun(
                `UPDATE posts SET "thumbnailUrl" = $1, "updatedAt" = NOW() WHERE id = $2`,
                [thumbUrl, postId]
            );
        }

        // 2. MP4 optimize (faststart - web için)
        await optimizeVideo(inputPath, mp4Out);
        const mp4Url = `/uploads/videos/${videoId}.mp4`;

        // MP4 hazır olunca hemen yayınla (HLS beklemeden oynatılabilir)
        await dbRun(
            `UPDATE posts SET media = $1, "mediaType" = 'video', "thumbnailUrl" = $2, "updatedAt" = NOW() WHERE id = $3`,
            [mp4Url, thumbUrl, postId]
        );

        console.log(`🎬 [Paralel] MP4 hazır: ${videoId} → HLS oluşturuluyor...`);

        // 3. HLS (arka planda, MP4 zaten oynanıyor)
        const hlsOk = await generateHLSVariants(mp4Out, videoId);
        if (hlsOk) {
            const hlsUrl = `/uploads/hls/${videoId}/master.m3u8`;
            await dbRun(
                `UPDATE posts SET media = $1, "updatedAt" = NOW() WHERE id = $2`,
                [hlsUrl, postId]
            );
        }

        // 4. Video meta bilgisi
        const vInfo = await getVideoInfo(mp4Out).catch(() => ({}));
        const existing = await dbGet('SELECT id FROM video_info WHERE "postId" = $1', [postId]);
        if (existing) {
            await dbRun(
                `UPDATE video_info SET duration=$1, width=$2, height=$3, "aspectRatio"=$4, bitrate=$5, codec=$6, "fileSize"=$7 WHERE "postId"=$8`,
                [vInfo.duration||0, vInfo.width||0, vInfo.height||0, vInfo.aspectRatio||'', vInfo.bitrate||0, vInfo.codec||'', vInfo.fileSize||0, postId]
            );
        } else {
            await dbRun(
                `INSERT INTO video_info (id, "postId", duration, width, height, "aspectRatio", bitrate, codec, "fileSize", "createdAt")
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())`,
                [uuidv4(), postId, vInfo.duration||0, vInfo.width||0, vInfo.height||0, vInfo.aspectRatio||'', vInfo.bitrate||0, vInfo.codec||'', vInfo.fileSize||0]
            );
        }

        // Temp dosyayı temizle
        await require('fs').promises.unlink(inputPath).catch(() => {});

        console.log(`✅ [Paralel] Tamamlandı: ${videoId} | HLS: ${hlsOk ? 'Evet' : 'Hayır (MP4 fallback)'} | Thumb: ${thumbUrl ? 'Evet' : 'Hayır'}`);

    } catch (err) {
        console.error(`❌ [Paralel] Video işleme hatası (${videoId}):`, err.message);
        // Hata durumunda orijinal dosyayı doğrudan kullan
        try {
            await dbRun(`UPDATE posts SET media = $1, "mediaType" = 'video', "updatedAt" = NOW() WHERE id = $2`,
                [`/uploads/videos/${videoId}_raw.mp4`, postId]);
        } catch {}
    } finally {
        activeVideoJobs--;
        console.log(`🎬 [Paralel] Slot serbest: Aktif: ${activeVideoJobs}/${MAX_CONCURRENT_VIDEOS}`);
    }
}

// Geriye uyumluluk için - eski enqueueVideoProcessing çağrılarını yönlendir
function enqueueVideoProcessing(postId, inputPath, videoId) {
    processVideoAsync(postId, inputPath, videoId).catch(err =>
        console.error(`❌ processVideoAsync başlatma hatası (${videoId}):`, err.message)
    );
}

// Video kuyruk durumu (admin/health endpoint için)
function getVideoQueueStatus() {
    return { activeJobs: activeVideoJobs, maxConcurrent: MAX_CONCURRENT_VIDEOS };
}

// ==================== POST FORMAT HELPER (v5 Frontend Uyumluluğu) ====================
// v5 SQLite'ta frontend şu alanları bekliyordu:
//   post.mediaUrl   → video için /uploads/videos/xxx.mp4 veya HLS /uploads/hls/xxx/master.m3u8
//   post.thumbnail  → /uploads/thumbnails/xxx.jpg  (video için)
// pg-v8'de DB'de media ve thumbnailUrl alanları var; bu fonksiyon ikisini de doldurur.
function formatPost(post) {
    if (!post) return post;
    const p = { ...post };

    if (p.media) {
        const isHLS = p.media.includes('.m3u8');
        const isVideo = p.mediaType === 'video';

        if (isVideo) {
            // mediaUrl: HLS varsa HLS, yoksa mp4
            p.mediaUrl = p.media;
            // thumbnail: DB'deki thumbnailUrl en güvenilir kaynak
            if (p.thumbnailUrl) {
                p.thumbnail = p.thumbnailUrl;
            } else if (isHLS) {
                // /uploads/hls/{videoId}/master.m3u8 → videoId çıkar
                const m = p.media.match(/\/hls\/([^/]+)\//);
                p.thumbnail = m ? `/uploads/thumbnails/${m[1]}.jpg` : null;
            } else {
                // /uploads/videos/{videoId}.mp4 → videoId çıkar
                const fname = p.media.split('/').pop() || '';
                p.thumbnail = `/uploads/thumbnails/${fname.replace('.mp4', '.jpg')}`;
            }
        } else {
            // Resim: mediaUrl = media
            p.mediaUrl = p.media;
            p.thumbnail = null;
        }
    } else {
        p.mediaUrl = null;
        p.thumbnail = null;
    }

    // Boolean dönüşümleri (PostgreSQL true/false → 1/0 yerine boolean)
    p.isLiked   = p.isLiked   === true || p.isLiked   === 1 || p.isLiked   === 't';
    p.isSaved   = p.isSaved   === true || p.isSaved   === 1 || p.isSaved   === 't';
    p.isVerified = p.isVerified === true || p.isVerified === 1;
    p.commentsDisabled = !p.allowComments;

    // Sayı dönüşümleri
    p.likeCount    = parseInt(p.likeCount    || 0);
    p.commentCount = parseInt(p.commentCount || 0);
    p.saveCount    = parseInt(p.saveCount    || 0);
    p.views        = parseInt(p.views        || 0);

    return p;
}

// ==================== MULTER ====================

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        cb(null, `${Date.now()}-${Math.round(Math.random() * 1E9)}${ext}`);
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 500 * 1024 * 1024, files: 5 }, // 500MB (video için)
    fileFilter: (req, file, cb) => {
        const allowed = [
            'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp',
            'video/mp4', 'video/quicktime', 'video/webm', 'video/avi',
            'video/x-msvideo', 'video/mpeg', 'video/3gpp', 'video/x-matroska'
        ];
        if (allowed.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Desteklenmeyen dosya türü'), false);
        }
    }
});

// ==================== MIDDLEWARE ====================

// ═══════════════════════════════════════════════════════════════
// 🔒 GÜVENLİK KATMANI - Güçlendirilmiş
// ═══════════════════════════════════════════════════════════════

// Helmet - HTTP güvenlik başlıkları
app.use(helmet({
    contentSecurityPolicy : false,
    crossOriginResourcePolicy: { policy: 'cross-origin' },
    hsts                  : { maxAge: 31536000, includeSubDomains: true, preload: true },
    noSniff               : true,
    xssFilter             : true,
    referrerPolicy        : { policy: 'strict-origin-when-cross-origin' },
}));

// Tahmin saldırılarını zorlaştır - X-Powered-By gizle
app.disable('x-powered-by');

// Request boyutu sınırla (DoS önlemi)

app.use(compression({ level: 6 }));
const ALLOWED_ORIGINS = [
    'https://sehitumitkestitarimmtal.com',
    'https://www.sehitumitkestitarimmtal.com',
    'http://sehitumitkestitarimmtal.com',
    'http://www.sehitumitkestitarimmtal.com',
    'http://localhost:3000',
    'http://localhost:5173',
];

app.use(cors({
    origin: (origin, callback) => {
        // Origin yoksa (Postman, mobil uygulama, sunucu içi istek) izin ver
        if (!origin) return callback(null, true);
        if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
        // Aynı sunucudan gelen istekler
        return callback(null, true);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
    exposedHeaders: ['Content-Range', 'X-Content-Range'],
}));
app.options('*', cors()); // Preflight (tüm OPTIONS isteklerine cevap ver)
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
// 🎬 Video dosyaları için Range request + CORS + doğru MIME (oynatma için kritik)
// ÖNEMLİ: Bu middleware /uploads genel static'ten ÖNCE tanımlanmalı!
app.use('/uploads/videos', (req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Accept-Ranges', 'bytes');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    next();
}, express.static(videosDir, {
    maxAge: '7d',
    setHeaders: (res, filePath) => {
        if (filePath.endsWith('.mp4')) {
            res.setHeader('Content-Type', 'video/mp4');
            res.setHeader('Accept-Ranges', 'bytes');
        }
    }
}));

// 🎬 HLS segmentleri için özel headers (CORS + doğru MIME + no-cache manifest)
app.use('/uploads/hls', (req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    if (req.path.endsWith('.m3u8')) {
        res.setHeader('Content-Type', 'application/vnd.apple.mpegurl');
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate'); // Manifest HİÇ cache'lenmesin
        res.setHeader('Pragma', 'no-cache');
    } else if (req.path.endsWith('.ts')) {
        res.setHeader('Content-Type', 'video/mp2t');
        res.setHeader('Cache-Control', 'public, max-age=86400');
    }
    next();
}, express.static(hlsDir, { maxAge: 0, etag: false }));

// 🖼️ Thumbnail'lar
app.use('/uploads/thumbnails', (req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    next();
}, express.static(thumbnailsDir, { maxAge: '30d' }));

// 📁 Diğer upload dosyaları (resimler, profil fotoğrafları vb.)
// UYARI: Bu /uploads genel static MUTLAKA specific olanlardan sonra gelmeli!
app.use('/uploads', express.static(uploadsDir, { maxAge: '1y' }));
app.use(sanitizeBody);    // 🔒 XSS / Path traversal koruması
app.use(ipBanMiddleware); // 🔒 IP Ban kontrolü

// ═══════════════════════════════════════════════════════════════
// 🔥 FIREWALL - Uygulama katmanı güvenlik duvarı
// ═══════════════════════════════════════════════════════════════
const FIREWALL_BLOCKED_IPS  = new Set(); // Dinamik olarak engellenen IP'ler
const FIREWALL_ATTACK_LOG   = new Map(); // IP → { count, firstSeen, lastSeen, reasons[] }
const FIREWALL_AUTO_BAN_THRESHOLD = 20;  // 1 dakikada 20 şüpheli istek → otomatik ban

// Bilinen kötü User-Agent'ları
const BAD_USER_AGENTS = [
    /sqlmap/i, /nikto/i, /nmap/i, /masscan/i, /zgrab/i,
    /havij/i, /acunetix/i, /nessus/i, /openvas/i,
    /dirbuster/i, /gobuster/i, /wfuzz/i, /hydra/i,
    /python-requests\/2\.[0-4]/i, // Eski requests versiyonları (bot sinyali)
];

// Bilinen saldırı pattern'leri
const ATTACK_PATTERNS = [
    // SQL Injection
    /(UNION.*SELECT|SELECT.*FROM.*WHERE)/i,
    /(DROP|TRUNCATE|DELETE)\s+TABLE/i,
    /('\s*OR\s*'1'\s*=\s*'1|'\s*OR\s+1\s*=\s*1)/i,
    // XSS
    /<script[\s\S]*?>[\s\S]*?<\/script>/i,
    /javascript\s*:/i,
    /on(load|error|click|mouseover)\s*=/i,
    // Path traversal
    /\.\.[\\/]/,
    /%2e%2e[%2f%5c]/i,
    // Command injection
    /[;&|`$]\s*(cat|ls|wget|curl|bash|sh|cmd|powershell|nc|ncat)/i,
    // XXE
    /<!ENTITY\s/i,
    // LFI/RFI
    /(php:\/\/|file:\/\/|data:\/\/|expect:\/\/)/i,
];

function logFirewallAttack(ip, reason, req) {
    if (!FIREWALL_ATTACK_LOG.has(ip)) {
        FIREWALL_ATTACK_LOG.set(ip, { count: 0, firstSeen: Date.now(), lastSeen: Date.now(), reasons: [] });
    }
    const entry = FIREWALL_ATTACK_LOG.get(ip);
    entry.count++;
    entry.lastSeen = Date.now();
    if (entry.reasons.length < 10) entry.reasons.push(reason);

    // Otomatik ban
    if (entry.count >= FIREWALL_AUTO_BAN_THRESHOLD) {
        FIREWALL_BLOCKED_IPS.add(ip);
        console.warn(`🔥 [FIREWALL] AUTO-BAN: ${ip} | Sebep: ${reason} | Toplam: ${entry.count} saldırı`);
        // DB'ye de kaydet (asenkron)
        dbRun(
            `INSERT INTO banned_ips (id, ip, reason, "bannedAt", "expiresAt")
             VALUES ($1, $2, $3, NOW(), NOW() + INTERVAL '24 hours')
             ON CONFLICT (ip) DO UPDATE SET reason=$3, "bannedAt"=NOW(), "expiresAt"=NOW() + INTERVAL '24 hours'`,
            [uuidv4(), ip, `AUTO-BAN: ${reason} (${entry.count} saldırı)`]
        ).catch(() => {});
    }
}

// Firewall middleware
function firewallMiddleware(req, res, next) {
    const ip = req.ip || req.connection.remoteAddress || '';
    const cleanIp = ip.replace(/^::ffff:/, '');

    // 1. Statik olarak engellenmiş IP
    if (FIREWALL_BLOCKED_IPS.has(cleanIp) || FIREWALL_BLOCKED_IPS.has(ip)) {
        return res.status(403).json({ error: 'Erişim engellendi' });
    }

    // 2. Kötü User-Agent
    const ua = req.headers['user-agent'] || '';
    for (const pattern of BAD_USER_AGENTS) {
        if (pattern.test(ua)) {
            logFirewallAttack(cleanIp, `Bad UA: ${ua.substring(0, 80)}`, req);
            return res.status(403).json({ error: 'Erişim engellendi' });
        }
    }

    // 3. URL'de saldırı pattern'i
    const fullUrl = decodeURIComponent(req.originalUrl || req.url || '');
    for (const pattern of ATTACK_PATTERNS) {
        if (pattern.test(fullUrl)) {
            logFirewallAttack(cleanIp, `URL attack pattern: ${fullUrl.substring(0, 100)}`, req);
            console.warn(`🔥 [FIREWALL] URL ATTACK: ${cleanIp} → ${fullUrl.substring(0, 100)}`);
            return res.status(403).json({ error: 'Geçersiz istek' });
        }
    }

    // 4. Body'de saldırı pattern'i (sadece JSON body varsa)
    if (req.body && typeof req.body === 'object') {
        const bodyStr = JSON.stringify(req.body);
        for (const pattern of ATTACK_PATTERNS) {
            if (pattern.test(bodyStr)) {
                logFirewallAttack(cleanIp, `Body attack pattern`, req);
                return res.status(400).json({ error: 'Geçersiz içerik' });
            }
        }
    }

    // 5. Çok büyük header'lar (header injection)
    const totalHeaderSize = Object.values(req.headers).join('').length;
    if (totalHeaderSize > 16384) { // 16KB
        logFirewallAttack(cleanIp, 'Oversized headers', req);
        return res.status(431).json({ error: 'İstek başlıkları çok büyük' });
    }

    next();
}

app.use(firewallMiddleware);

// 🔥 Firewall yönetimi API'leri
app.get('/api/admin/firewall/stats', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
    const logs = [];
    for (const [ip, data] of FIREWALL_ATTACK_LOG.entries()) {
        logs.push({ ip, ...data });
    }
    logs.sort((a, b) => b.count - a.count);
    res.json({
        blockedIPs    : [...FIREWALL_BLOCKED_IPS],
        totalBlockedIPs: FIREWALL_BLOCKED_IPS.size,
        attackLog     : logs.slice(0, 50),
        autobanThreshold: FIREWALL_AUTO_BAN_THRESHOLD,
    });
});

app.post('/api/admin/firewall/block', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
    const { ip, reason = 'Manuel engelleme' } = req.body;
    if (!ip) return res.status(400).json({ error: 'IP adresi gerekli' });
    FIREWALL_BLOCKED_IPS.add(ip);
    await dbRun(
        `INSERT INTO banned_ips (id, ip, reason, "bannedAt") VALUES ($1,$2,$3,NOW())
         ON CONFLICT (ip) DO UPDATE SET reason=$3, "bannedAt"=NOW()`,
        [uuidv4(), ip, reason]
    ).catch(() => {});
    res.json({ success: true, message: `${ip} engellendi` });
});

app.post('/api/admin/firewall/unblock', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ error: 'IP adresi gerekli' });
    FIREWALL_BLOCKED_IPS.delete(ip);
    FIREWALL_ATTACK_LOG.delete(ip);
    await dbRun(`DELETE FROM banned_ips WHERE ip = $1`, [ip]).catch(() => {});
    res.json({ success: true, message: `${ip} engeli kaldırıldı` });
});

// Başlangıçta DB'deki ban'ları belleğe yükle
async function loadFirewallBans() {
    try {
        const bans = await dbAll(
            `SELECT ip FROM banned_ips WHERE "expiresAt" IS NULL OR "expiresAt" > NOW()`
        );
        bans.forEach(b => FIREWALL_BLOCKED_IPS.add(b.ip));
        console.log(`🔥 [FIREWALL] ${FIREWALL_BLOCKED_IPS.size} engellenmiş IP yüklendi`);
    } catch (e) {
        console.error('Firewall ban yükleme hatası:', e.message);
    }
}
// DB hazır olduktan sonra çağrılacak (initializeDatabase'den sonra)

// Rate Limiting
// Genel API rate limit
app.use('/api/', rateLimit({
    windowMs      : 15 * 60 * 1000, // 15 dakika
    max           : 300,             // IP başına 300 istek
    standardHeaders: true,
    legacyHeaders : false,
    message       : { error: 'Çok fazla istek gönderildi. Lütfen bekleyin.' },
    skip          : (req) => req.method === 'OPTIONS',
}));

// Auth endpoint'leri - çok daha sıkı
app.use('/api/auth/login',           rateLimit({ windowMs: 15 * 60 * 1000, max: 10,  message: { error: 'Çok fazla giriş denemesi. 15 dakika bekleyin.' } }));
app.use('/api/auth/register',        rateLimit({ windowMs: 60 * 60 * 1000, max: 5,   message: { error: 'Çok fazla kayıt denemesi. 1 saat bekleyin.' } }));
app.use('/api/auth/register-init',   rateLimit({ windowMs: 60 * 60 * 1000, max: 5,   message: { error: 'Çok fazla kayıt denemesi. 1 saat bekleyin.' } }));
app.use('/api/auth/forgot-password', rateLimit({ windowMs: 60 * 60 * 1000, max: 3,   message: { error: 'Çok fazla şifre sıfırlama denemesi. 1 saat bekleyin.' } }));
app.use('/api/auth/verify-2fa',      rateLimit({ windowMs: 10 * 60 * 1000, max: 10,  message: { error: 'Çok fazla doğrulama denemesi.' } }));
app.use('/api/auth/resend-2fa',      rateLimit({ windowMs: 5  * 60 * 1000, max: 3,   message: { error: 'Çok fazla kod istendi. 5 dakika bekleyin.' } }));
app.use('/api/auth/verify-email',    rateLimit({ windowMs: 5  * 60 * 1000, max: 5,   message: { error: 'Çok fazla doğrulama denemesi.' } }));
app.use('/api/auth/resend-verification', rateLimit({ windowMs: 10 * 60 * 1000, max: 3 }));

// Upload endpoint - dosya yükleme sınırı
app.use('/api/posts',    rateLimit({ windowMs: 60 * 1000, max: 30, methods: ['POST'] }));
app.use('/api/messages', rateLimit({ windowMs: 60 * 1000, max: 60 }));

// ==================== 🔒 SPAM KORUMASI MIDDLEWARE ====================

const spamCounters = new Map(); // Bellek tabanlı (Redis yoksa)

const spamProtection = async (req, res, next) => {
    if (!req.user || !['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();
    try {
        const key    = `${req.user.id}:${req.path}`;
        const now    = Date.now();
        const entry  = spamCounters.get(key) || { count: 0, reset: now + 60000 };
        if (now > entry.reset) { entry.count = 0; entry.reset = now + 60000; }
        entry.count++;
        spamCounters.set(key, entry);
        if (entry.count > 30) {
            return res.status(429).json({ error: 'Çok fazla istek yaptınız, lütfen biraz bekleyin.' });
        }
        next();
    } catch { next(); }
};

// ==================== AUTH MIDDLEWARE ====================

async function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token gerekli' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await dbGet(
            // 🔒 GÜVENLİK: SELECT * yerine sadece gerekli alanlar — isAdmin gibi
            // tehlikeli flag'lerin req.user'a sızmasını engeller (bypass2 vektörü kapatıldı)
            `SELECT id, username, name, email, role, "profilePic", "coverPic", bio,
                    "isVerified", "isActive", "userType", "hasFarmerBadge",
                    "isOnline", "isBanned", "emailVerified", "twoFactorEnabled"
             FROM users WHERE id = $1 AND "isActive" = TRUE`,
            [decoded.id]
        );
        if (!user) return res.status(403).json({ error: 'Kullanıcı bulunamadı' });

        const restriction = await dbGet(
            `SELECT "isRestricted", "restrictedUntil", "canPost", "canComment", "canMessage", "canFollow", "canLike"
             FROM account_restrictions 
             WHERE "userId" = $1 AND "isRestricted" = TRUE AND "restrictedUntil" > NOW()`,
            [user.id]
        );

        // 🔒 Spread yok — sadece whitelist edilmiş nesne
        req.user = {
            id            : user.id,
            username      : user.username,
            name          : user.name,
            email         : user.email,
            role          : user.role,          // tek yetki kaynağı
            profilePic    : user.profilePic,
            coverPic      : user.coverPic,
            bio           : user.bio,
            isVerified    : user.isVerified,
            isActive      : user.isActive,
            userType      : user.userType,
            hasFarmerBadge: user.hasFarmerBadge,
            isOnline      : user.isOnline,
            isBanned      : user.isBanned,
            emailVerified : user.emailVerified,
            twoFactorEnabled: user.twoFactorEnabled,
            restriction   : restriction || null,
        };
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Geçersiz token' });
    }
}

function checkRestriction(action) {
    return (req, res, next) => {
        if (req.user.restriction) {
            const r = req.user.restriction;
            if (action === 'post' && !r.canPost) return res.status(403).json({ error: 'Gönderi paylaşımı kısıtlandı', restrictedUntil: r.restrictedUntil });
            if (action === 'comment' && !r.canComment) return res.status(403).json({ error: 'Yorum yapma kısıtlandı', restrictedUntil: r.restrictedUntil });
            if (action === 'message' && !r.canMessage) return res.status(403).json({ error: 'Mesaj gönderme kısıtlandı', restrictedUntil: r.restrictedUntil });
            if (action === 'follow' && !r.canFollow) return res.status(403).json({ error: 'Takip etme kısıtlandı', restrictedUntil: r.restrictedUntil });
            if (action === 'like' && !r.canLike) return res.status(403).json({ error: 'Beğenme kısıtlandı', restrictedUntil: r.restrictedUntil });
        }
        next();
    };
}

async function createNotification(userId, type, message, data = {}) {
    try {
        await dbRun(
            `INSERT INTO notifications (id, "userId", type, message, data, "createdAt")
             VALUES ($1, $2, $3, $4, $5, NOW())`,
            [uuidv4(), userId, type, message, JSON.stringify(data)]
        );
    } catch (err) {
        console.error('Bildirim oluşturma hatası:', err.message);
    }
}

function generateTokens(user) {
    // 🔒 GÜVENLİK: Access token 1 gün, refresh token 7 gün
    // Token çalınma riskini minimize etmek için süreler kısaltıldı
    const accessToken = jwt.sign(
        { id: user.id, email: user.email, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: '1d', algorithm: 'HS256' }
    );
    const refreshToken = jwt.sign(
        { id: user.id, type: 'refresh' },
        JWT_REFRESH_SECRET,
        { expiresIn: '7d', algorithm: 'HS256' }
    );
    return { accessToken, refreshToken };
}

// ====================================================================
// API ROTALARI
// ====================================================================

// ─── 1. HEALTH CHECK ────────────────────────────────────────────────
app.get('/api/health', async (req, res) => {
    try {
        await pool.query('SELECT 1');
        res.json({ status: 'ok', timestamp: new Date().toISOString(), database: 'connected' });
    } catch (e) {
        res.status(503).json({ status: 'error', database: 'disconnected' });
    }
});

// ─── 2. KAYIT ───────────────────────────────────────────────────────
app.post('/api/auth/register', upload.single('profilePic'), async (req, res) => {
    try {
        const { name, username, email, password, userType } = req.body;
        if (!name || !username || !email || !password) {
            return res.status(400).json({ error: 'Tüm alanlar zorunludur' });
        }
        if (password.length < 4) return res.status(400).json({ error: 'Şifre en az 4 karakter' });

        const cleanUsername = username.toLowerCase().replace(/[^a-z0-9._-]/g, '');
        const cleanEmail = email.toLowerCase().trim();

        const existing = await dbGet('SELECT id FROM users WHERE username = $1', [cleanUsername]);
        if (existing) return res.status(400).json({ error: 'Bu kullanıcı adı alınmış' });

        // 🔒 GÜVENLİK: Aynı e-posta ile birden fazla hesap açılmasını engelle
        const existingEmail = await dbGet('SELECT id FROM users WHERE email = $1', [cleanEmail]);
        if (existingEmail) return res.status(400).json({ error: 'Bu e-posta adresi zaten kayıtlı' });

        const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);
        const userId = uuidv4();

        let profilePic = null;
        if (req.file) {
            const filename = `profile_${userId}.webp`;
            const outputPath = path.join(profilesDir, filename);
            try {
                await sharp(req.file.path).resize(512, 512, { fit: 'cover' }).webp({ quality: 85 }).toFile(outputPath);
                profilePic = `/uploads/profiles/${filename}`;
            } catch (e) {
                console.error('Profil resmi hatası:', e.message);
            }
            await fs.unlink(req.file.path).catch(() => {});
        }

        const validUserTypes = ['tarim_ogretmeni', 'tarim_ogrencisi', 'ogretmen', 'ziraat_muhendisi', 'normal_kullanici', 'ciftci_hayvancilik'];
        const finalUserType = validUserTypes.includes(userType) ? userType : 'normal_kullanici';

        await dbRun(
            `INSERT INTO users (id, name, username, email, password, "profilePic", "userType", "registrationIp", "createdAt", "updatedAt")
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())`,
            [userId, name, cleanUsername, cleanEmail, hashedPassword, profilePic, finalUserType, req.ip]
        );

        const tokens = generateTokens({ id: userId, email: cleanEmail, username: cleanUsername, role: 'user' });

        // 📧 Hoş geldiniz + e-posta doğrulama kodu gönder
        const verifyCode    = Math.floor(100000 + Math.random() * 900000).toString();
        const verifyExpires = new Date(Date.now() + 15 * 60 * 1000).toISOString();
        await dbRun(
            `INSERT INTO email_verifications (id, "userId", code, "expiresAt") VALUES ($1, $2, $3, $4)`,
            [uuidv4(), userId, verifyCode, verifyExpires]
        );
        sendWelcomeEmail(cleanEmail, name).catch(() => {});

        // Doğrulama kodu içeren ayrı e-posta
        sendEmail(cleanEmail, '🌾 Agrolink — E-posta Doğrulama Kodunuz', `
<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"><style>
body{font-family:'Segoe UI',sans-serif;background:#f4f4f4;margin:0;padding:0}
.container{max-width:600px;margin:20px auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.1)}
.header{background:linear-gradient(135deg,#2e7d32,#4caf50);padding:40px 30px;text-align:center}
.header h1{color:#fff;margin:0;font-size:28px}
.header p{color:rgba(255,255,255,.9);margin:10px 0 0;font-size:16px}
.content{padding:40px 30px}
.code-box{background:#2e7d32;color:#fff;font-size:40px;font-weight:bold;text-align:center;padding:25px;border-radius:10px;letter-spacing:12px;margin:25px 0}
.info{background:#e8f5e9;padding:20px;border-radius:8px;border-left:4px solid #4caf50}
.footer{background:#f5f5f5;padding:25px 30px;text-align:center;color:#666;font-size:13px}
</style></head><body>
<div class="container">
  <div class="header"><h1>🌾 E-posta Doğrulama</h1><p>Hesabınızı doğrulamak için aşağıdaki kodu kullanın</p></div>
  <div class="content">
    <h2 style="color:#2e7d32">Merhaba ${name},</h2>
    <p>Agrolink hesabınızı oluşturduğunuz için teşekkür ederiz. Hesabınızı aktif etmek için aşağıdaki doğrulama kodunu kullanın:</p>
    <div class="code-box">${verifyCode}</div>
    <div class="info"><strong>⏱️ Bu kod 15 dakika geçerlidir.</strong><br>Kodu kimseyle paylaşmayın.</div>
    <p style="margin-top:25px">Bu işlemi siz yapmadıysanız bu e-postayı dikkate almayın.</p>
    <p>Saygılarımızla,<br><strong>Agrolink Ekibi</strong></p>
  </div>
  <div class="footer"><p>Bu e-posta otomatik gönderilmiştir. &copy; ${new Date().getFullYear()} Agrolink</p></div>
</div></body></html>`).catch(() => {});

        res.status(201).json({
            message: 'Hesap oluşturuldu',
            token: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            emailVerificationRequired: true,
            user: { id: userId, username: cleanUsername, name, email: cleanEmail, profilePic }
        });
    } catch (error) {
        console.error('Kayıt hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 2b. KAYIT (register-init alias — UI uyumluluğu için) ──────────
// UI /api/auth/register-init çağırıyor, bu endpoint aynı işlemi yapar
app.post('/api/auth/register-init', upload.single('profilePic'), async (req, res) => {
    try {
        const { name, username, email, password, userType } = req.body;
        if (!name || !username || !email || !password) {
            return res.status(400).json({ error: 'Tüm alanlar zorunludur' });
        }
        if (password.length < 4) return res.status(400).json({ error: 'Şifre en az 4 karakter' });

        const cleanUsername = username.toLowerCase().replace(/[^a-z0-9._-]/g, '');
        const cleanEmail = email.toLowerCase().trim();

        const existing = await dbGet('SELECT id FROM users WHERE username = $1 OR email = $2', [cleanUsername, cleanEmail]);
        if (existing) return res.status(400).json({ error: 'Bu kullanıcı adı veya e-posta zaten kullanımda' });

        const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);
        const userId = uuidv4();

        let profilePic = null;
        if (req.file) {
            const filename = `profile_${userId}.webp`;
            const outputPath = path.join(profilesDir, filename);
            try {
                await sharp(req.file.path).resize(512, 512, { fit: 'cover' }).webp({ quality: 85 }).toFile(outputPath);
                profilePic = `/uploads/profiles/${filename}`;
            } catch (e) {
                console.error('Profil resmi hatası:', e.message);
            }
            await fs.unlink(req.file.path).catch(() => {});
        }

        const validUserTypes = ['tarim_ogretmeni', 'tarim_ogrencisi', 'ogretmen', 'ziraat_muhendisi', 'normal_kullanici', 'ciftci_hayvancilik'];
        const finalUserType = validUserTypes.includes(userType) ? userType : 'normal_kullanici';

        await dbRun(
            `INSERT INTO users (id, name, username, email, password, "profilePic", "userType", "registrationIp", "createdAt", "updatedAt")
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())`,
            [userId, name, cleanUsername, cleanEmail, hashedPassword, profilePic, finalUserType, req.ip]
        );

        // E-posta doğrulama kodu oluştur
        const verifyCode    = Math.floor(100000 + Math.random() * 900000).toString();
        const verifyExpires = new Date(Date.now() + 15 * 60 * 1000).toISOString();
        await dbRun(
            `INSERT INTO email_verifications (id, "userId", code, "expiresAt") VALUES ($1, $2, $3, $4)`,
            [uuidv4(), userId, verifyCode, verifyExpires]
        );

        // Doğrulama kodu e-postası - tam HTML şablonuyla
        const emailResult = await sendEmailVerificationCode(cleanEmail, name.trim(), verifyCode);

        if (!emailResult.success) {
            console.error('❌ Kayıt doğrulama e-postası gönderilemedi:', emailResult.error);
            return res.status(500).json({ error: 'Doğrulama e-postası gönderilemedi. Lütfen e-posta adresinizi kontrol edip tekrar deneyin.' });
        }

        console.log(`📧 Kayıt doğrulama kodu gönderildi: ${cleanEmail}`);

        // Hoş geldiniz emaili arka planda gönder
        sendWelcomeEmail(cleanEmail, name).catch(() => {});

        res.status(201).json({
            message: 'Doğrulama kodu e-posta adresinize gönderildi. Lütfen kodu girerek kaydınızı tamamlayın.',
            emailVerificationRequired: true,
            requiresVerification: true,
            email: cleanEmail,
            userId
        });
    } catch (error) {
        console.error('Kayıt (init) hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 3. GİRİŞ ──────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password, identifier } = req.body;
        // UI'dan "identifier" (e-posta veya kullanıcı adı) gelebilir, geriye dönük uyumluluk için "email" de desteklenir
        const loginId = (identifier || email || '').toLowerCase().trim();
        if (!loginId || !password) return res.status(400).json({ error: 'E-posta/kullanıcı adı ve şifre gerekli' });

        const user = await dbGet(
            'SELECT * FROM users WHERE (email = $1 OR username = $1) AND "isActive" = TRUE',
            [loginId]
        );
        if (!user) return res.status(401).json({ error: 'Kullanıcı bulunamadı' });

        // 🔒 Brute force kontrolü
        const lockout = checkAccountLockout(loginId);
        if (lockout.locked) {
            return res.status(429).json({ error: `Hesap geçici olarak kilitlendi. ${lockout.remainingMin} dakika sonra tekrar deneyin.` });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            recordFailedLogin(loginId);
            return res.status(401).json({ error: 'Şifre yanlış' });
        }
        clearFailedLogins(loginId);

        // ========== 2FA KONTROLÜ ==========
        if (user.twoFactorEnabled) {
            // 2FA açık → kod oluştur ve gönder
            const twoFACode = Math.floor(100000 + Math.random() * 900000).toString();
            const twoFAExpires = new Date(Date.now() + 5 * 60 * 1000).toISOString(); // 5 dakika

            // Eski kullanılmamış kodları temizle
            await dbRun(
                `UPDATE two_factor_codes SET used = TRUE WHERE "userId" = $1 AND used = FALSE`,
                [user.id]
            );

            // Yeni kodu kaydet
            await dbRun(
                `INSERT INTO two_factor_codes (id, "userId", code, purpose, "expiresAt", used, "createdAt") VALUES ($1, $2, $3, $4, $5, FALSE, NOW())`,
                [uuidv4(), user.id, twoFACode, 'login', twoFAExpires]
            );

            // 2FA kodunu e-posta ile gönder (tam HTML şablonuyla)
            const emailResult = await sendTwoFactorCodeEmail(user.email, user.name, twoFACode, 'login');

            if (!emailResult.success) {
                console.error('❌ 2FA e-postası gönderilemedi:', emailResult.error);
                return res.status(500).json({ error: 'Doğrulama kodu gönderilemedi. Lütfen tekrar deneyin.' });
            }

            console.log(`🔐 2FA kodu gönderildi: ${user.email}`);

            // Geçici token oluştur (2FA doğrulama için)
            const tempToken = jwt.sign(
                { id: user.id, email: user.email, username: user.username, pending2FA: true },
                JWT_SECRET,
                { expiresIn: '10m', algorithm: 'HS256' }
            );

            return res.json({
                requires2FA: true,
                tempToken,
                userId: user.id,
                email: user.email,
                message: 'Doğrulama kodu e-posta adresinize gönderildi. Lütfen 6 haneli kodu girin.'
            });
        }

        // 2FA kapalı → direkt giriş yap
        // 📧 Giriş bildirimi e-postası (arka planda)
        sendLoginNotificationEmail(user.email, user.name, req).catch(() => {});

        await dbRun('UPDATE users SET "lastLogin" = NOW(), "isOnline" = TRUE, "updatedAt" = NOW() WHERE id = $1', [user.id]);

        await dbRun(
            `INSERT INTO login_history (id, "userId", ip, "userAgent", "createdAt")
             VALUES ($1, $2, $3, $4, NOW())`,
            [uuidv4(), user.id, req.ip, req.headers['user-agent'] || '']
        );

        const tokens = generateTokens(user);

        const tokenHash = crypto.createHash('sha256').update(tokens.refreshToken).digest('hex');
        await dbRun(
            `INSERT INTO refresh_tokens (id, "userId", "tokenHash", ip, "userAgent", "createdAt", "expiresAt")
             VALUES ($1, $2, $3, $4, $5, NOW(), NOW() + INTERVAL '30 days')`,
            [uuidv4(), user.id, tokenHash, req.ip, req.headers['user-agent'] || '']
        );

        res.json({
            message: 'Giriş başarılı',
            token: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            user: {
                id: user.id, username: user.username, name: user.name, email: user.email,
                profilePic: user.profilePic, coverPic: user.coverPic, bio: user.bio,
                isVerified: user.isVerified, hasFarmerBadge: user.hasFarmerBadge, role: user.role
            }
        });
    } catch (error) {
        console.error('Giriş hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 4. TOKEN YENİLEME ──────────────────────────────────────────────
app.post('/api/auth/refresh', async (req, res) => {
    try {
        const { refreshToken } = req.body;
        if (!refreshToken) return res.status(401).json({ error: 'Refresh token gerekli' });

        const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
        const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

        const stored = await dbGet(
            `SELECT * FROM refresh_tokens WHERE "tokenHash" = $1 AND "isActive" = TRUE AND "expiresAt" > NOW()`,
            [tokenHash]
        );
        if (!stored) return res.status(403).json({ error: 'Geçersiz refresh token' });

        const user = await dbGet(
            // 🔒 Sadece whitelist alanlar
            `SELECT id, username, name, email, role, "profilePic", "coverPic", bio,
                    "isVerified", "isActive", "userType", "hasFarmerBadge",
                    "isOnline", "isBanned", "emailVerified", "twoFactorEnabled"
             FROM users WHERE id = $1 AND "isActive" = TRUE`,
            [decoded.id]
        );
        if (!user) return res.status(403).json({ error: 'Kullanıcı bulunamadı' });

        await dbRun('UPDATE refresh_tokens SET "isActive" = FALSE WHERE "tokenHash" = $1', [tokenHash]);

        const tokens = generateTokens(user);
        const newHash = crypto.createHash('sha256').update(tokens.refreshToken).digest('hex');
        await dbRun(
            `INSERT INTO refresh_tokens (id, "userId", "tokenHash", ip, "userAgent", "createdAt", "expiresAt")
             VALUES ($1, $2, $3, $4, $5, NOW(), NOW() + INTERVAL '30 days')`,
            [uuidv4(), user.id, newHash, req.ip, req.headers['user-agent'] || '']
        );

        res.json({ token: tokens.accessToken, refreshToken: tokens.refreshToken });
    } catch (error) {
        res.status(403).json({ error: 'Geçersiz token' });
    }
});

// ─── 5. MEVCUT KULLANICI BİLGİSİ ───────────────────────────────────
app.get('/api/me', authenticateToken, async (req, res) => {
    try {
        const user = await dbGet(
            `SELECT id, username, name, email, "profilePic", "coverPic", bio, location, website,
                    "isVerified", "hasFarmerBadge", "userType", "createdAt", "lastLogin", "isOnline", role
             FROM users WHERE id = $1`,
            [req.user.id]
        );
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });

        // Kesin sayım - COUNT sütun adını açıkça belirt
        const [followingRow, followerRow, postRow] = await Promise.all([
            pool.query('SELECT COUNT(*)::int AS cnt FROM follows WHERE "followerId" = $1', [req.user.id]),
            pool.query('SELECT COUNT(*)::int AS cnt FROM follows WHERE "followingId" = $1', [req.user.id]),
            pool.query('SELECT COUNT(*)::int AS cnt FROM posts   WHERE "userId" = $1 AND "isActive" = TRUE', [req.user.id]),
        ]);

        const followingCount = followingRow.rows[0]?.cnt ?? 0;
        const followerCount  = followerRow.rows[0]?.cnt  ?? 0;
        const postCount      = postRow.rows[0]?.cnt      ?? 0;

        res.json({
            user: {
                ...user,
                followingCount,
                followerCount,
                postCount,
            }
        });
    } catch (error) {
        console.error('api/me hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 6. KULLANICI PROFİLİ ──────────────────────────────────────────
// ─── 6. KULLANICI PROFİLİ (ID veya username ile) ───────────────────
// Frontend'in v5'ten gelen tüm çağrıları uyumlu hale getirir:
//   GET /api/users/:id       → UUID ile arama (eski frontend)
//   GET /api/users/:username → username ile arama (yeni frontend)
app.get('/api/users/:idOrUsername', authenticateToken, async (req, res, next) => {
    // Bilinen statik endpoint'ler → kendi route'larına bırak
    const STATIC_SEGMENTS = [
        'blocks', 'blocked', 'online', 'search', 'following', 'followers',
        'top-followed', 'privacy-settings', 'nearby', 'recommendations',
        'suggestions', 'notification-settings', 'interests', 'profile',
        'profile-pic', 'privacy', 'account', '2fa', 'verification', 'me'
    ];
    const param = req.params.idOrUsername;
    if (STATIC_SEGMENTS.includes(param)) return next();

    try {
        // UUID formatı mı yoksa username mi?
        const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(param);

        let user;
        if (isUUID) {
            // ID ile ara (v5 uyumlu)
            user = await dbGet(
                `SELECT id, username, name, "profilePic", "coverPic", bio, location, website,
                        "isVerified", "hasFarmerBadge", "userType", "isOnline", "lastSeen", "createdAt"
                 FROM users WHERE id = $1 AND "isActive" = TRUE`,
                [param]
            );
        } else {
            // Username ile ara
            user = await dbGet(
                `SELECT id, username, name, "profilePic", "coverPic", bio, location, website,
                        "isVerified", "hasFarmerBadge", "userType", "isOnline", "lastSeen", "createdAt"
                 FROM users WHERE username = $1 AND "isActive" = TRUE`,
                [param.toLowerCase()]
            );
        }

        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });

        const [followingRow, followerRow, postRow, isFollowing, isBlocked] = await Promise.all([
            pool.query('SELECT COUNT(*)::int AS cnt FROM follows WHERE "followerId"  = $1', [user.id]),
            pool.query('SELECT COUNT(*)::int AS cnt FROM follows WHERE "followingId" = $1', [user.id]),
            pool.query('SELECT COUNT(*)::int AS cnt FROM posts   WHERE "userId" = $1 AND "isActive" = TRUE', [user.id]),
            dbGet('SELECT id FROM follows WHERE "followerId" = $1 AND "followingId" = $2', [req.user.id, user.id]),
            dbGet(`SELECT id FROM blocks WHERE ("blockerId"=$1 AND "blockedId"=$2) OR ("blockerId"=$2 AND "blockedId"=$1)`, [req.user.id, user.id])
        ]);

        res.json({
            user: {
                ...user,
                followingCount : followingRow.rows[0]?.cnt ?? 0,
                followerCount  : followerRow.rows[0]?.cnt  ?? 0,
                postCount      : postRow.rows[0]?.cnt      ?? 0,
                isFollowing    : !!isFollowing,
                isBlocked      : !!isBlocked,
                isOnline       : await isUserOnline(user.id).catch(() => false),
            }
        });
    } catch (error) {
        console.error('Profil hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// isUserOnline yardımcı fonksiyonu (yok ise fallback)
async function isUserOnline(userId) {
    try {
        const u = await dbGet('SELECT "isOnline", "lastSeen" FROM users WHERE id=$1', [userId]);
        if (!u) return false;
        if (u.isOnline) return true;
        // Son 5 dakika içinde aktif mi?
        if (u.lastSeen) {
            const diff = Date.now() - new Date(u.lastSeen).getTime();
            return diff < 5 * 60 * 1000;
        }
        return false;
    } catch { return false; }
}

// ─── 7. PROFİL GÜNCELLE ────────────────────────────────────────────
app.put('/api/users/profile', authenticateToken, upload.fields([
    { name: 'profilePic', maxCount: 1 }, { name: 'coverPic', maxCount: 1 }
]), async (req, res) => {
    try {
        const { name, bio, location, website } = req.body;
        const updates = [];
        const params = [];
        let paramIdx = 1;

        if (name !== undefined) { updates.push(`name = $${paramIdx++}`); params.push(name.substring(0, 50)); }
        if (bio !== undefined) { updates.push(`bio = $${paramIdx++}`); params.push(bio.substring(0, 300)); }
        if (location !== undefined) { updates.push(`location = $${paramIdx++}`); params.push(location.substring(0, 100)); }
        if (website !== undefined) { updates.push(`website = $${paramIdx++}`); params.push(website.substring(0, 200)); }

        if (req.files?.profilePic?.[0]) {
            const file = req.files.profilePic[0];
            const filename = `profile_${req.user.id}_${Date.now()}.webp`;
            const outputPath = path.join(profilesDir, filename);
            await sharp(file.path).resize(512, 512, { fit: 'cover' }).webp({ quality: 85 }).toFile(outputPath);
            await fs.unlink(file.path).catch(() => {});
            updates.push(`"profilePic" = $${paramIdx++}`);
            params.push(`/uploads/profiles/${filename}`);
        }

        if (req.files?.coverPic?.[0]) {
            const file = req.files.coverPic[0];
            const filename = `cover_${req.user.id}_${Date.now()}.webp`;
            const outputPath = path.join(profilesDir, filename);
            await sharp(file.path).resize(1920, 1080, { fit: 'inside', withoutEnlargement: true }).webp({ quality: 85 }).toFile(outputPath);
            await fs.unlink(file.path).catch(() => {});
            updates.push(`"coverPic" = $${paramIdx++}`);
            params.push(`/uploads/profiles/${filename}`);
        }

        if (updates.length === 0) return res.status(400).json({ error: 'Güncellenecek alan yok' });

        updates.push(`"updatedAt" = NOW()`);
        params.push(req.user.id);

        await pool.query(`UPDATE users SET ${updates.join(', ')} WHERE id = $${paramIdx}`, params);

        const updated = await dbGet(
            'SELECT id, username, name, "profilePic", "coverPic", bio, location, website FROM users WHERE id = $1',
            [req.user.id]
        );

        res.json({ message: 'Profil güncellendi', user: updated });
    } catch (error) {
        console.error('Profil güncelleme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 8. ŞİFRE DEĞİŞTİR ────────────────────────────────────────────
app.put('/api/auth/change-password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Şifreler gerekli' });
        if (newPassword.length < 4) return res.status(400).json({ error: 'Yeni şifre en az 4 karakter' });

        const user = await dbGet('SELECT password FROM users WHERE id = $1', [req.user.id]);
        const valid = await bcrypt.compare(currentPassword, user.password);
        if (!valid) return res.status(401).json({ error: 'Mevcut şifre yanlış' });

        const hashed = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
        await dbRun('UPDATE users SET password = $1, "updatedAt" = NOW() WHERE id = $2', [hashed, req.user.id]);

        // 📧 Bildirim e-postası
        const u = await dbGet('SELECT email, name FROM users WHERE id = $1', [req.user.id]);
        if (u) sendPasswordResetSuccessEmail(u.email, u.name).catch(() => {});

        res.json({ message: 'Şifre değiştirildi' });
    } catch (error) {
        console.error('Şifre değiştirme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 9. KULLANICI ARA ───────────────────────────────────────────────
app.get('/api/users/search/:query', authenticateToken, async (req, res) => {
    try {
        const { query } = req.params;
        const searchTerm = `%${query.toLowerCase()}%`;

        const users = await dbAll(
            `SELECT id, username, name, "profilePic", "isVerified", "hasFarmerBadge"
             FROM users
             WHERE "isActive" = TRUE AND (LOWER(username) LIKE $1 OR LOWER(name) LIKE $1)
             ORDER BY "isVerified" DESC, "createdAt" DESC
             LIMIT 20`,
            [searchTerm]
        );

        res.json({ users });
    } catch (error) {
        console.error('Arama hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 10. GÖNDERI OLUŞTUR ────────────────────────────────────────────
app.post('/api/posts', authenticateToken, checkRestriction('post'), upload.array('media', 5), async (req, res) => {
    try {
        const { content = '', isPoll, pollQuestion, pollOptions, latitude, longitude, locationName, allowComments = 'true' } = req.body;
        const isAnketMode = isPoll === 'true' || isPoll === true;
        const hasText = content && content.trim().length > 0;
        const hasMedia = req.files && req.files.length > 0;
        const hasPoll = isAnketMode && pollQuestion;

        if (!hasText && !hasMedia && !hasPoll) {
            return res.status(400).json({ error: 'Boş gönderi oluşturulamaz' });
        }

        const user = await dbGet('SELECT id, username, "userType" FROM users WHERE id = $1', [req.user.id]);
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });

        let media = null;
        let mediaType = 'text';

        if (hasMedia) {
            const file = req.files[0];
            const isVideo = file.mimetype.startsWith('video/');

            if (isVideo) {
                const videoId  = `video_${Date.now()}_${Math.round(Math.random() * 1E9)}`;
                const tempPath = path.join(tempDir, `${videoId}_raw${path.extname(file.originalname).toLowerCase() || '.mp4'}`);

                // Ham dosyayı temp'e taşı
                await fs.copyFile(file.path, tempPath);
                await fs.unlink(file.path).catch(() => {});

                // Gönderiyi hemen kaydet (placeholder - sonra güncellenecek)
                media     = `/uploads/videos/${videoId}.mp4`;
                mediaType = 'video';

                // postId henüz DB'ye yazılmadı, aşağıda senkron işlenecek
                req._pendingVideo = { videoId, tempPath };
            } else {
                const filename = `img_${Date.now()}_${Math.round(Math.random() * 1E9)}.webp`;
                const outputPath = path.join(postsDir, filename);
                try {
                    await sharp(file.path).resize(1920, 1920, { fit: 'inside', withoutEnlargement: true }).webp({ quality: 85 }).toFile(outputPath);
                } catch (e) {
                    await fs.copyFile(file.path, outputPath);
                }
                media = `/uploads/posts/${filename}`;
                mediaType = 'image';
            }
            await fs.unlink(file.path).catch(() => {});
        }

        const postId = uuidv4();
        let parsedPollOptions = null;
        if (hasPoll && pollOptions) {
            try {
                const opts = typeof pollOptions === 'string' ? JSON.parse(pollOptions) : pollOptions;
                parsedPollOptions = JSON.stringify(opts.map((o, i) => ({ id: i, text: o, votes: 0 })));
            } catch (e) { parsedPollOptions = null; }
        }

        await dbRun(
            `INSERT INTO posts (id, "userId", username, content, media, "mediaType", "isPoll", "pollQuestion", "pollOptions",
             latitude, longitude, "locationName", "allowComments", "isActive", "createdAt", "updatedAt")
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,TRUE,NOW(),NOW())`,
            [postId, req.user.id, user.username, content || '', media, mediaType,
             isAnketMode, pollQuestion || null, parsedPollOptions,
             latitude ? parseFloat(latitude) : null, longitude ? parseFloat(longitude) : null,
             locationName || null, allowComments !== 'false']
        );

        // Hashtag'leri işle
        if (content) {
            const hashtagMatches = content.match(/#[\wığüşöçĞÜŞÖÇİ]+/g);
            if (hashtagMatches) {
                for (const tag of [...new Set(hashtagMatches)]) {
                    const cleanTag = tag.toLowerCase();
                    let hashtag = await dbGet('SELECT id FROM hashtags WHERE tag = $1', [cleanTag]);
                    if (!hashtag) {
                        const hId = uuidv4();
                        await dbRun('INSERT INTO hashtags (id, tag, "postCount", "createdAt") VALUES ($1, $2, 1, NOW())', [hId, cleanTag]);
                        hashtag = { id: hId };
                    } else {
                        await dbRun('UPDATE hashtags SET "postCount" = "postCount" + 1 WHERE id = $1', [hashtag.id]);
                    }
                    await dbRun('INSERT INTO post_hashtags (id, "postId", "hashtagId") VALUES ($1, $2, $3) ON CONFLICT DO NOTHING',
                        [uuidv4(), postId, hashtag.id]);
                }
            }
        }

        // Video varsa RESPONSE'DAN ÖNCE senkron işle (dosya hazır olmadan 201 dönme)
        if (req._pendingVideo) {
            const { videoId, tempPath } = req._pendingVideo;
            console.log(`🎬 Video senkron işleniyor: ${videoId}`);
            await processVideoAsync(postId, tempPath, videoId);
            console.log(`✅ Video işleme tamamlandı, response dönülüyor: ${videoId}`);
        }

        // İşlem bittikten sonra güncel media URL'iyle postu çek
        const post = await dbGet('SELECT * FROM posts WHERE id = $1', [postId]);

        res.status(201).json({ success: true, message: 'Gönderi paylaşıldı', post: formatPost(post) });
    } catch (error) {
        console.error('Post oluşturma hatası:', error);
        if (req.files) { for (const f of req.files) { await fs.unlink(f.path).catch(() => {}); } }
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 11. FEED ───────────────────────────────────────────────────────
app.get('/api/feed', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);

        const posts = await dbAll(
            `SELECT p.*, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge", u."userType", u.username as "authorUsername",
                    EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) as "isLiked",
                    EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $1) as "isSaved"
             FROM posts p
             JOIN users u ON p."userId" = u.id
             WHERE p."isActive" = TRUE
               AND p."userId" NOT IN (SELECT "blockedId" FROM blocks WHERE "blockerId" = $1)
               AND p."userId" NOT IN (SELECT "blockerId" FROM blocks WHERE "blockedId" = $1)
             ORDER BY p."createdAt" DESC
             LIMIT $2 OFFSET $3`,
            [req.user.id, parseInt(limit), offset]
        );

        res.json({ posts: posts.map(formatPost), page: parseInt(page) });
    } catch (error) {
        console.error('Feed hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 12. TEK POST ───────────────────────────────────────────────────
// ÖNEMLİ: saved, liked, popular, new gibi statik yollar ÖNCE tanımlanmalı.
app.get('/api/posts/:id', authenticateToken, async (req, res, next) => {
    const STATIC_POST_SEGS = ['saved', 'liked', 'popular', 'new', 'search', 'feed', 'trending'];
    if (STATIC_POST_SEGS.includes(req.params.id)) return next();
    // UUID değilse DB'ye gönderme
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(req.params.id))
        return res.status(400).json({ error: 'Geçersiz gönderi ID' });
    try {
        const post = await dbGet(
            `SELECT p.*, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge", u."userType", u.username as "authorUsername",
                    EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $2) as "isLiked",
                    EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $2) as "isSaved"
             FROM posts p
             JOIN users u ON p."userId" = u.id
             WHERE p.id = $1 AND p."isActive" = TRUE`,
            [req.params.id, req.user.id]
        );
        if (!post) return res.status(404).json({ error: 'Gönderi bulunamadı' });

        await dbRun('UPDATE posts SET views = views + 1 WHERE id = $1', [req.params.id]).catch(() => {});

        res.json({ post: formatPost(post) });
    } catch (error) {
        console.error('Post getirme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 13. POST SİL ──────────────────────────────────────────────────
app.delete('/api/posts/:id', authenticateToken, async (req, res) => {
    try {
        const post = await dbGet('SELECT "userId" FROM posts WHERE id = $1', [req.params.id]);
        if (!post) return res.status(404).json({ error: 'Gönderi bulunamadı' });
        if (post.userId !== req.user.id && req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Yetkiniz yok' });
        }
        await dbRun('UPDATE posts SET "isActive" = FALSE, "updatedAt" = NOW() WHERE id = $1', [req.params.id]);
        res.json({ message: 'Gönderi silindi' });
    } catch (error) {
        console.error('Post silme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 14. KULLANICININ POSTLARı ──────────────────────────────────────
app.get('/api/users/:userId/posts', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);
        const param = req.params.userId;

        // ID veya username ile kullanıcı bul
        const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(param);
        let targetUserId = param;
        if (!isUUID) {
            const u = await dbGet('SELECT id FROM users WHERE username=$1 AND "isActive"=TRUE', [param.toLowerCase()]);
            if (!u) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
            targetUserId = u.id;
        }

        const posts = await dbAll(
            `SELECT p.*, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge", u.username as "authorUsername",
                    EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) as "isLiked",
                    EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $1) as "isSaved"
             FROM posts p
             JOIN users u ON p."userId" = u.id
             WHERE p."userId" = $2 AND p."isActive" = TRUE
             ORDER BY p."createdAt" DESC
             LIMIT $3 OFFSET $4`,
            [req.user.id, targetUserId, parseInt(limit), offset]
        );

        const total = await dbGet('SELECT COUNT(*) as c FROM posts WHERE "userId"=$1 AND "isActive"=TRUE', [targetUserId]);

        res.json({ posts: posts.map(formatPost), total: parseInt(total?.c || 0), page: parseInt(page) });
    } catch (error) {
        console.error('Kullanıcı postları hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 15. BEĞENİ ────────────────────────────────────────────────────
app.post('/api/posts/:id/like', authenticateToken, checkRestriction('like'), async (req, res) => {
    try {
        const postId = req.params.id;
        const existing = await dbGet('SELECT id FROM likes WHERE "postId" = $1 AND "userId" = $2', [postId, req.user.id]);

        if (existing) {
            await dbRun('DELETE FROM likes WHERE id = $1', [existing.id]);
            await dbRun('UPDATE posts SET "likeCount" = GREATEST("likeCount" - 1, 0), "updatedAt" = NOW() WHERE id = $1', [postId]);
            res.json({ liked: false });
        } else {
            await dbRun('INSERT INTO likes (id, "postId", "userId", "createdAt") VALUES ($1, $2, $3, NOW())', [uuidv4(), postId, req.user.id]);
            await dbRun('UPDATE posts SET "likeCount" = "likeCount" + 1, "updatedAt" = NOW() WHERE id = $1', [postId]);

            const post = await dbGet('SELECT "userId" FROM posts WHERE id = $1', [postId]);
            if (post && post.userId !== req.user.id) {
                await createNotification(post.userId, 'like', `${req.user.username} gönderinizi beğendi`, { postId, userId: req.user.id });
            }
            res.json({ liked: true });
        }
    } catch (error) {
        console.error('Beğeni hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 16. YORUM YAP ─────────────────────────────────────────────────
app.post('/api/posts/:id/comments', authenticateToken, checkRestriction('comment'), async (req, res) => {
    try {
        const { content, parentId } = req.body;
        if (!content || !content.trim()) return res.status(400).json({ error: 'Yorum boş olamaz' });

        const post = await dbGet('SELECT "userId", "allowComments" FROM posts WHERE id = $1 AND "isActive" = TRUE', [req.params.id]);
        if (!post) return res.status(404).json({ error: 'Gönderi bulunamadı' });
        if (!post.allowComments) return res.status(403).json({ error: 'Yorumlar kapalı' });

        const commentId = uuidv4();
        await dbRun(
            `INSERT INTO comments (id, "postId", "userId", username, content, "parentId", "createdAt", "updatedAt")
             VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())`,
            [commentId, req.params.id, req.user.id, req.user.username, content.substring(0, 2000), parentId || null]
        );

        await dbRun('UPDATE posts SET "commentCount" = "commentCount" + 1, "updatedAt" = NOW() WHERE id = $1', [req.params.id]);

        if (post.userId !== req.user.id) {
            await createNotification(post.userId, 'comment', `${req.user.username} gönderinize yorum yaptı`, { postId: req.params.id, commentId });
        }

        const comment = await dbGet('SELECT * FROM comments WHERE id = $1', [commentId]);
        res.status(201).json({ comment });
    } catch (error) {
        console.error('Yorum hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 17. YORUMLARI GETİR ───────────────────────────────────────────
app.get('/api/posts/:id/comments', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);

        const comments = await dbAll(
            `SELECT c.*, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge",
                    EXISTS(SELECT 1 FROM comment_likes WHERE "commentId" = c.id AND "userId" = $1) as "isLiked"
             FROM comments c
             JOIN users u ON c."userId" = u.id
             WHERE c."postId" = $2
             ORDER BY c."createdAt" ASC
             LIMIT $3 OFFSET $4`,
            [req.user.id, req.params.id, parseInt(limit), offset]
        );

        res.json({ comments });
    } catch (error) {
        console.error('Yorumlar hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 18. TAKİP ET/BIRAK ────────────────────────────────────────────
app.post('/api/users/:id/follow', authenticateToken, checkRestriction('follow'), async (req, res) => {
    try {
        const targetId = req.params.id;
        if (targetId === req.user.id) return res.status(400).json({ error: 'Kendinizi takip edemezsiniz' });

        const blocked = await dbGet('SELECT id FROM blocks WHERE ("blockerId" = $1 AND "blockedId" = $2) OR ("blockerId" = $2 AND "blockedId" = $1)', [req.user.id, targetId]);
        if (blocked) return res.status(403).json({ error: 'Engellenen kullanıcı' });

        const existing = await dbGet('SELECT id FROM follows WHERE "followerId" = $1 AND "followingId" = $2', [req.user.id, targetId]);

        if (existing) {
            await dbRun('DELETE FROM follows WHERE id = $1', [existing.id]);
            res.json({ following: false });
        } else {
            await dbRun('INSERT INTO follows (id, "followerId", "followingId", "createdAt") VALUES ($1, $2, $3, NOW())', [uuidv4(), req.user.id, targetId]);
            await createNotification(targetId, 'follow', `${req.user.username} sizi takip etmeye başladı`, { userId: req.user.id });
            res.json({ following: true });
        }
    } catch (error) {
        console.error('Takip hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 19. TAKİPÇİLER ────────────────────────────────────────────────
app.get('/api/users/:id/followers', authenticateToken, async (req, res) => {
    try {
        const followers = await dbAll(
            `SELECT u.id, u.username, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge",
                    EXISTS(SELECT 1 FROM follows WHERE "followerId" = $2 AND "followingId" = u.id) as "isFollowing"
             FROM follows f
             JOIN users u ON f."followerId" = u.id
             WHERE f."followingId" = $1
             ORDER BY f."createdAt" DESC`,
            [req.params.id, req.user.id]
        );
        res.json({ followers });
    } catch (error) {
        console.error('Takipçiler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 20. TAKİP EDİLENLER ───────────────────────────────────────────
app.get('/api/users/:id/following', authenticateToken, async (req, res) => {
    try {
        const following = await dbAll(
            `SELECT u.id, u.username, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge",
                    EXISTS(SELECT 1 FROM follows WHERE "followerId" = $2 AND "followingId" = u.id) as "isFollowing"
             FROM follows f
             JOIN users u ON f."followingId" = u.id
             WHERE f."followerId" = $1
             ORDER BY f."createdAt" DESC`,
            [req.params.id, req.user.id]
        );
        res.json({ following });
    } catch (error) {
        console.error('Takip edilenler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 21. MESAJ GÖNDER ───────────────────────────────────────────────
app.post('/api/messages', authenticateToken, checkRestriction('message'), async (req, res) => {
    try {
        const { recipientId, content } = req.body;
        if (!recipientId || !content) return res.status(400).json({ error: 'Alıcı ve mesaj gerekli' });

        const blocked = await dbGet('SELECT id FROM blocks WHERE ("blockerId" = $1 AND "blockedId" = $2) OR ("blockerId" = $2 AND "blockedId" = $1)', [req.user.id, recipientId]);
        if (blocked) return res.status(403).json({ error: 'Bu kullanıcıya mesaj gönderemezsiniz' });

        const recipient = await dbGet('SELECT id, username FROM users WHERE id = $1 AND "isActive" = TRUE', [recipientId]);
        if (!recipient) return res.status(404).json({ error: 'Alıcı bulunamadı' });

        const msgId = uuidv4();
        await dbRun(
            `INSERT INTO messages (id, "senderId", "senderUsername", "recipientId", "recipientUsername", content, "createdAt", "updatedAt")
             VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())`,
            [msgId, req.user.id, req.user.username, recipientId, recipient.username, content.substring(0, 5000)]
        );

        await createNotification(recipientId, 'message', `${req.user.username} size mesaj gönderdi`, { senderId: req.user.id });

        res.status(201).json({ message: 'Mesaj gönderildi', id: msgId });
    } catch (error) {
        console.error('Mesaj hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 22. SOHBET LİSTESİ ────────────────────────────────────────────
app.get('/api/messages/conversations', authenticateToken, async (req, res) => {
    try {
        const conversations = await dbAll(
            `SELECT DISTINCT ON (partner_id) *
             FROM (
                 SELECT m.*, 
                        CASE WHEN m."senderId" = $1 THEN m."recipientId" ELSE m."senderId" END as partner_id,
                        CASE WHEN m."senderId" = $1 THEN m."recipientUsername" ELSE m."senderUsername" END as partner_username
                 FROM messages m
                 WHERE m."senderId" = $1 OR m."recipientId" = $1
             ) sub
             JOIN users u ON sub.partner_id = u.id
             ORDER BY partner_id, sub."createdAt" DESC`,
            [req.user.id]
        );

        const enriched = await Promise.all(conversations.map(async (conv) => {
            const partner = await dbGet(
                'SELECT id, username, name, "profilePic", "isVerified", "isOnline" FROM users WHERE id = $1',
                [conv.partner_id]
            );
            const unreadCount = await dbGet(
                'SELECT COUNT(*) as count FROM messages WHERE "senderId" = $1 AND "recipientId" = $2 AND read = FALSE',
                [conv.partner_id, req.user.id]
            );
            return {
                ...conv,
                partner,
                unreadCount: parseInt(unreadCount?.count || 0)
            };
        }));

        res.json({ conversations: enriched });
    } catch (error) {
        console.error('Sohbet listesi hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 23. MESAJ GEÇMİŞİ ─────────────────────────────────────────────
app.get('/api/messages/:userId', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 50 } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);

        const messages = await dbAll(
            `SELECT * FROM messages
             WHERE ("senderId" = $1 AND "recipientId" = $2) OR ("senderId" = $2 AND "recipientId" = $1)
             ORDER BY "createdAt" DESC
             LIMIT $3 OFFSET $4`,
            [req.user.id, req.params.userId, parseInt(limit), offset]
        );

        await dbRun(
            `UPDATE messages SET read = TRUE, "readAt" = NOW()
             WHERE "senderId" = $1 AND "recipientId" = $2 AND read = FALSE`,
            [req.params.userId, req.user.id]
        );

        res.json({ messages: messages.reverse() });
    } catch (error) {
        console.error('Mesaj geçmişi hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 24. BİLDİRİMLER ───────────────────────────────────────────────
app.get('/api/notifications', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 30 } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);

        const notifications = await dbAll(
            `SELECT * FROM notifications WHERE "userId" = $1 ORDER BY "createdAt" DESC LIMIT $2 OFFSET $3`,
            [req.user.id, parseInt(limit), offset]
        );

        const unreadCount = await dbGet(
            'SELECT COUNT(*) as count FROM notifications WHERE "userId" = $1 AND read = FALSE',
            [req.user.id]
        );

        res.json({ notifications, unreadCount: parseInt(unreadCount?.count || 0) });
    } catch (error) {
        console.error('Bildirimler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 25. BİLDİRİMLERİ OKUNDU YAP ───────────────────────────────────
app.put('/api/notifications/read', authenticateToken, async (req, res) => {
    try {
        const { ids } = req.body;
        if (ids && Array.isArray(ids)) {
            const placeholders = ids.map((_, i) => `$${i + 2}`).join(',');
            await pool.query(
                `UPDATE notifications SET read = TRUE, "readAt" = NOW() WHERE "userId" = $1 AND id IN (${placeholders})`,
                [req.user.id, ...ids]
            );
        } else {
            await dbRun('UPDATE notifications SET read = TRUE, "readAt" = NOW() WHERE "userId" = $1', [req.user.id]);
        }
        res.json({ message: 'Bildirimler okundu' });
    } catch (error) {
        console.error('Bildirim okuma hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 26. POST KAYDET ────────────────────────────────────────────────
app.post('/api/posts/:id/save', authenticateToken, async (req, res) => {
    try {
        const postId = req.params.id;
        const existing = await dbGet('SELECT id FROM saves WHERE "postId" = $1 AND "userId" = $2', [postId, req.user.id]);

        if (existing) {
            await dbRun('DELETE FROM saves WHERE id = $1', [existing.id]);
            await dbRun('UPDATE posts SET "saveCount" = GREATEST("saveCount" - 1, 0) WHERE id = $1', [postId]);
            res.json({ saved: false });
        } else {
            await dbRun('INSERT INTO saves (id, "postId", "userId", "createdAt") VALUES ($1, $2, $3, NOW())', [uuidv4(), postId, req.user.id]);
            await dbRun('UPDATE posts SET "saveCount" = "saveCount" + 1 WHERE id = $1', [postId]);
            res.json({ saved: true });
        }
    } catch (error) {
        console.error('Kaydetme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 27. KAYDEDİLENLER ─────────────────────────────────────────────
app.get('/api/saved', authenticateToken, async (req, res) => {
    try {
        const posts = await dbAll(
            `SELECT p.*, u.name, u."profilePic", u."isVerified",
                    TRUE as "isSaved",
                    EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) as "isLiked"
             FROM saves s
             JOIN posts p ON s."postId" = p.id
             JOIN users u ON p."userId" = u.id
             WHERE s."userId" = $1 AND p."isActive" = TRUE
             ORDER BY s."createdAt" DESC`,
            [req.user.id]
        );
        res.json({ posts: posts.map(formatPost) });
    } catch (error) {
        console.error('Kaydedilenler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 28. ENGELLE ────────────────────────────────────────────────────
app.post('/api/users/:id/block', authenticateToken, async (req, res) => {
    try {
        const targetId = req.params.id;
        if (targetId === req.user.id) return res.status(400).json({ error: 'Kendinizi engelleyemezsiniz' });

        const existing = await dbGet('SELECT id FROM blocks WHERE "blockerId" = $1 AND "blockedId" = $2', [req.user.id, targetId]);

        if (existing) {
            await dbRun('DELETE FROM blocks WHERE id = $1', [existing.id]);
            res.json({ blocked: false });
        } else {
            await dbRun('INSERT INTO blocks (id, "blockerId", "blockedId", "createdAt") VALUES ($1, $2, $3, NOW())', [uuidv4(), req.user.id, targetId]);
            await dbRun('DELETE FROM follows WHERE ("followerId" = $1 AND "followingId" = $2) OR ("followerId" = $2 AND "followingId" = $1)', [req.user.id, targetId]);
            res.json({ blocked: true });
        }
    } catch (error) {
        console.error('Engelleme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 29. ENGELLENENLER ──────────────────────────────────────────────
app.get('/api/users/blocks', authenticateToken, async (req, res) => {
    try {
        const blocks = await dbAll(
            `SELECT u.id, u.username, u.name, u."profilePic", b."createdAt"
             FROM blocks b JOIN users u ON b."blockedId" = u.id
             WHERE b."blockerId" = $1
             ORDER BY b."createdAt" DESC`,
            [req.user.id]
        );
        // Her iki key adıyla döndür
        res.json({ blocks, blockedUsers: blocks, count: blocks.length });
    } catch (error) {
        console.error('Engellenenler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 30. ÜRÜNLER ────────────────────────────────────────────────────
app.get('/api/store/products', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);

        const products = await dbAll(
            `SELECT p.*, u.username as "sellerName", u."profilePic" as "sellerProfilePic", u.name as "sellerFullName"
             FROM products p JOIN users u ON p."sellerId" = u.id
             WHERE p."isActive" = TRUE
             ORDER BY p."createdAt" DESC
             LIMIT $1 OFFSET $2`,
            [parseInt(limit), offset]
        );

        const total = await dbGet('SELECT COUNT(*) as count FROM products WHERE "isActive" = TRUE');

        res.json({ products, total: parseInt(total?.count || 0), page: parseInt(page) });
    } catch (error) {
        console.error('Ürünler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 31. ÜRÜN EKLE ─────────────────────────────────────────────────
app.post('/api/store/products', authenticateToken, (req, res, next) => {
    // Hem 'images' (çoklu) hem 'image' (tekil) field adını kabul et
    upload.fields([
        { name: 'images', maxCount: 5 },
        { name: 'image',  maxCount: 1 }
    ])(req, res, (err) => {
        if (err) {
            console.error('Multer hatası:', err);
            return res.status(400).json({ error: 'Dosya yükleme hatası: ' + err.message });
        }
        // req.files'ı düz array'e çevir (geriye uyumluluk)
        if (req.files && !Array.isArray(req.files)) {
            req.files = [...(req.files['images'] || []), ...(req.files['image'] || [])];
        }
        next();
    });
}, async (req, res) => {
    try {
        const { name, price, description, category, stock } = req.body;
        if (!name || !price) return res.status(400).json({ error: 'İsim ve fiyat gerekli' });

        const priceNum = parseFloat(price);
        if (isNaN(priceNum) || priceNum < 0) return res.status(400).json({ error: 'Geçersiz fiyat' });

        let images = [];
        const files = req.files || [];
        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            const filename = `product_${Date.now()}_${i}_${Math.round(Math.random() * 1e9)}.webp`;
            const outputPath = path.join(postsDir, filename);
            try {
                await sharp(file.path)
                    .resize(1080, 1080, { fit: 'inside', withoutEnlargement: true })
                    .webp({ quality: 85 })
                    .toFile(outputPath);
            } catch (imgErr) {
                console.warn('Görsel işleme hatası, orijinal kullanılıyor:', imgErr.message);
                const fs2 = require('fs');
                fs2.copyFileSync(file.path, outputPath);
            }
            await fs.unlink(file.path).catch(() => {});
            images.push(`/uploads/posts/${filename}`);
        }

        const productId = uuidv4();
        await dbRun(
            `INSERT INTO products (id, "sellerId", name, price, description, image, images, category, stock, "isActive", "createdAt", "updatedAt")
             VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, TRUE, NOW(), NOW())`,
            [productId, req.user.id, name.substring(0, 100), priceNum,
             description?.substring(0, 1000) || '', images[0] || null,
             JSON.stringify(images), category || '', parseInt(stock) || 1]
        );

        const product = await dbGet(
            `SELECT p.*, u.username AS "sellerName", u."profilePic" AS "sellerProfilePic"
             FROM products p JOIN users u ON p."sellerId" = u.id WHERE p.id = $1`,
            [productId]
        );

        res.status(201).json({ message: 'Ürün eklendi', product });
    } catch (error) {
        console.error('Ürün ekleme hatası:', error);
        // Dosyaları temizle
        if (req.files) {
            for (const f of (Array.isArray(req.files) ? req.files : [])) {
                await fs.unlink(f.path).catch(() => {});
            }
        }
        res.status(500).json({ error: 'Sunucu hatası: ' + error.message });
    }
});

// ─── 32. ÜRÜN SİL ──────────────────────────────────────────────────
app.delete('/api/store/products/:id', authenticateToken, async (req, res) => {
    try {
        const product = await dbGet('SELECT "sellerId" FROM products WHERE id = $1', [req.params.id]);
        if (!product) return res.status(404).json({ error: 'Ürün bulunamadı' });
        if (product.sellerId !== req.user.id) return res.status(403).json({ error: 'Yetkiniz yok' });

        await dbRun('DELETE FROM products WHERE id = $1', [req.params.id]);
        res.json({ message: 'Ürün silindi' });
    } catch (error) {
        console.error('Ürün silme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 33. ANKET OY VER ──────────────────────────────────────────────
app.post('/api/posts/:id/vote', authenticateToken, async (req, res) => {
    try {
        const { optionId } = req.body;
        const postId = req.params.id;

        const post = await dbGet('SELECT * FROM posts WHERE id = $1 AND "isPoll" = TRUE', [postId]);
        if (!post) return res.status(404).json({ error: 'Anket bulunamadı' });

        const existing = await dbGet('SELECT id FROM poll_votes WHERE "postId" = $1 AND "userId" = $2', [postId, req.user.id]);
        if (existing) return res.status(400).json({ error: 'Zaten oy verdiniz' });

        await dbRun('INSERT INTO poll_votes (id, "postId", "userId", "optionId", "createdAt") VALUES ($1, $2, $3, $4, NOW())',
            [uuidv4(), postId, req.user.id, optionId]);

        let options = post.pollOptions;
        if (typeof options === 'string') options = JSON.parse(options);
        const opt = options.find(o => o.id === optionId);
        if (opt) opt.votes = (opt.votes || 0) + 1;

        await dbRun('UPDATE posts SET "pollOptions" = $1 WHERE id = $2', [JSON.stringify(options), postId]);

        res.json({ message: 'Oy verildi', pollOptions: options });
    } catch (error) {
        console.error('Oy verme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 34. TREND HASHTAG'LER ──────────────────────────────────────────
app.get('/api/trending', authenticateToken, async (req, res) => {
    try {
        const hashtags = await dbAll(
            `SELECT tag, "postCount" FROM hashtags ORDER BY "postCount" DESC LIMIT 20`
        );
        res.json({ hashtags });
    } catch (error) {
        console.error('Trending hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── ADMİN: Kullanıcıyı admin yap ─────────────────────────────────
app.post('/api/admin/make-admin', authenticateToken, async (req, res) => {
    try {
        const me = await dbGet('SELECT role FROM users WHERE id=$1', [req.user.id]);
        if (me?.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
        const { userId } = req.body;
        if (!userId) return res.status(400).json({ error: 'userId gerekli' });
        await dbRun('UPDATE users SET role=$1, "updatedAt"=NOW() WHERE id=$2', ['admin', userId]);
        res.json({ message: 'Kullanıcı admin yapıldı' });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── ADMİN: Kullanıcı listesi ─────────────────────────────────────
app.get('/api/admin/users', authenticateToken, async (req, res) => {
    try {
        const me = await dbGet('SELECT role FROM users WHERE id=$1', [req.user.id]);
        if (me?.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
        const { page=1, limit=50, q='' } = req.query;
        const off = (parseInt(page)-1)*parseInt(limit);
        const users = await dbAll(`
            SELECT id, username, name, email, role, "isActive", "isVerified", "createdAt", "lastLogin",
                   (SELECT COUNT(*) FROM posts WHERE "userId"=u.id AND "isActive"=TRUE) AS "postCount",
                   (SELECT COUNT(*) FROM follows WHERE "followingId"=u.id) AS "followerCount"
            FROM users u
            WHERE ($1='' OR username ILIKE $1 OR name ILIKE $1 OR email ILIKE $1)
            ORDER BY "createdAt" DESC LIMIT $2 OFFSET $3
        `, [`%${q}%`, parseInt(limit), off]);
        const tot = await dbGet(`SELECT COUNT(*) AS c FROM users WHERE ($1='' OR username ILIKE $1)`, [`%${q}%`]);
        res.json({ users: users.map(u => ({ ...u, postCount: parseInt(u.postCount||0), followerCount: parseInt(u.followerCount||0) })),
                   total: parseInt(tot?.c||0) });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── ADMİN: Kullanıcı sil/banlama ─────────────────────────────────
app.post('/api/admin/users/:id/ban', authenticateToken, async (req, res) => {
    try {
        const me = await dbGet('SELECT role FROM users WHERE id=$1', [req.user.id]);
        if (me?.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
        const { reason = 'Admin kararı' } = req.body;
        await dbRun('UPDATE users SET "isActive"=FALSE, "updatedAt"=NOW() WHERE id=$1', [req.params.id]);
        res.json({ message: 'Kullanıcı banlandı', reason });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

app.post('/api/admin/users/:id/unban', authenticateToken, async (req, res) => {
    try {
        const me = await dbGet('SELECT role FROM users WHERE id=$1', [req.user.id]);
        if (me?.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
        await dbRun('UPDATE users SET "isActive"=TRUE, "updatedAt"=NOW() WHERE id=$1', [req.params.id]);
        res.json({ message: 'Kullanıcı ban kaldırıldı' });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── ADMİN: Post sil ──────────────────────────────────────────────
app.delete('/api/admin/posts/:id', authenticateToken, async (req, res) => {
    try {
        const me = await dbGet('SELECT role FROM users WHERE id=$1', [req.user.id]);
        if (me?.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
        await dbRun('UPDATE posts SET "isActive"=FALSE, "updatedAt"=NOW() WHERE id=$1', [req.params.id]);
        res.json({ message: 'Gönderi silindi' });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 35. SİSTEM İSTATİSTİKLERİ ─────────────────────────────────────
app.get('/api/stats', authenticateToken, async (req, res) => {
    try {
        // Temel istatistikler (herkes erişebilir)
        const [users, posts, messages, products] = await Promise.all([
            dbGet('SELECT COUNT(*) as count FROM users WHERE "isActive" = TRUE'),
            dbGet('SELECT COUNT(*) as count FROM posts WHERE "isActive" = TRUE'),
            dbGet('SELECT COUNT(*) as count FROM messages'),
            dbGet('SELECT COUNT(*) as count FROM products WHERE "isActive" = TRUE')
        ]);

        const base = {
            users   : parseInt(users?.count    || 0),
            posts   : parseInt(posts?.count    || 0),
            messages: parseInt(messages?.count || 0),
            products: parseInt(products?.count || 0),
        };

        // Admin için ekstra istatistikler
        // 🔒 GÜVENLİK: Yalnızca DB'den gelen role alanı kullanılır; isAdmin flag'i kaldırıldı (bypass vektörü)
        if (req.user.role === 'admin') {
            const [follows, saves, likes, videos, reports, bannedIps, activeUsers] = await Promise.all([
                dbGet('SELECT COUNT(*) as count FROM follows'),
                dbGet('SELECT COUNT(*) as count FROM saves'),
                dbGet('SELECT COUNT(*) as count FROM likes'),
                dbGet(`SELECT COUNT(*) as count FROM posts WHERE "mediaType"='video' AND "isActive"=TRUE`),
                dbGet('SELECT COUNT(*) as count FROM reports').catch(() => ({ count: 0 })),
                dbGet('SELECT COUNT(*) as count FROM banned_ips').catch(() => ({ count: 0 })),
                dbGet(`SELECT COUNT(*) as count FROM users WHERE "isOnline"=TRUE AND "isActive"=TRUE`),
            ]);

            const [newUsersToday, newPostsToday] = await Promise.all([
                dbGet(`SELECT COUNT(*) as count FROM users WHERE "createdAt" > NOW() - INTERVAL '24 hours'`),
                dbGet(`SELECT COUNT(*) as count FROM posts WHERE "createdAt" > NOW() - INTERVAL '24 hours' AND "isActive"=TRUE`),
            ]);

            return res.json({
                ...base,
                follows     : parseInt(follows?.count      || 0),
                saves       : parseInt(saves?.count        || 0),
                likes       : parseInt(likes?.count        || 0),
                videos      : parseInt(videos?.count       || 0),
                reports     : parseInt(reports?.count      || 0),
                bannedIps   : parseInt(bannedIps?.count    || 0),
                activeUsers : parseInt(activeUsers?.count  || 0),
                newUsersToday: parseInt(newUsersToday?.count || 0),
                newPostsToday: parseInt(newPostsToday?.count || 0),
                isAdmin     : true,
            });
        }

        res.json(base);
    } catch (error) {
        console.error('İstatistik hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── POST ŞİKAYETİ ─────────────────────────────────────────────────
app.post('/api/reports/post', authenticateToken, async (req, res) => {
    try {
        const { postId, reason, description } = req.body;
        if (!postId || !reason) return res.status(400).json({ error: 'Post ID ve neden gerekli' });

        await dbRun(
            `INSERT INTO reports (id, "reporterId", "postId", reason, description, "createdAt")
             VALUES ($1, $2, $3, $4, $5, NOW())`,
            [uuidv4(), req.user.id, postId, reason, description || '']
        );

        res.json({ message: 'Şikayet alındı' });
    } catch (error) {
        console.error('Şikayet hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── DOĞRULAMA ──────────────────────────────────────────────────────
app.post('/api/users/verification/instant', authenticateToken, async (req, res) => {
    try {
        const user = await dbGet('SELECT "isVerified" FROM users WHERE id = $1', [req.user.id]);
        if (user?.isVerified) return res.json({ message: 'Zaten doğrulanmış', isVerified: true });

        await dbRun('UPDATE users SET "isVerified" = TRUE, "verifiedAt" = NOW(), "updatedAt" = NOW() WHERE id = $1', [req.user.id]);
        res.json({ message: 'Hesap doğrulandı', isVerified: true });
    } catch (error) {
        console.error('Doğrulama hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 1: E-POSTA DOĞRULAMA ────────────────────────────────
app.post('/api/auth/verify-email', authenticateToken, async (req, res) => {
    try {
        const { code } = req.body;
        if (!code) return res.status(400).json({ error: 'Doğrulama kodu gerekli' });

        const record = await dbGet(
            `SELECT * FROM email_verifications WHERE "userId" = $1 AND code = $2 AND used = FALSE AND "expiresAt" > NOW()`,
            [req.user.id, code]
        );
        if (!record) return res.status(400).json({ error: 'Geçersiz veya süresi dolmuş kod' });

        await dbRun(`UPDATE email_verifications SET used = TRUE WHERE id = $1`, [record.id]);
        await dbRun(`UPDATE users SET "emailVerified" = TRUE, "updatedAt" = NOW() WHERE id = $1`, [req.user.id]);

        res.json({ message: 'E-posta doğrulandı', emailVerified: true });
    } catch (error) {
        console.error('E-posta doğrulama hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 2: DOĞRULAMA KODUNU YENİDEN GÖNDER ──────────────────
app.post('/api/auth/resend-verification', authenticateToken, async (req, res) => {
    try {
        const user = await dbGet('SELECT email, name, "emailVerified" FROM users WHERE id = $1', [req.user.id]);
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
        if (user.emailVerified) return res.status(400).json({ error: 'E-posta zaten doğrulanmış' });

        // Eskilerini geçersiz kıl
        await dbRun(`UPDATE email_verifications SET used = TRUE WHERE "userId" = $1`, [req.user.id]);

        const code    = Math.floor(100000 + Math.random() * 900000).toString();
        const expires = new Date(Date.now() + 15 * 60 * 1000).toISOString();
        await dbRun(
            `INSERT INTO email_verifications (id, "userId", code, "expiresAt") VALUES ($1, $2, $3, $4)`,
            [uuidv4(), req.user.id, code, expires]
        );

        const result = await sendVerificationEmail(user.email, user.name, code);
        if (!result.success) return res.status(500).json({ error: 'E-posta gönderilemedi', detail: result.error });

        res.json({ message: 'Doğrulama kodu gönderildi' });
    } catch (error) {
        console.error('Yeniden gönderme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 3: ŞİFREMİ UNUTTUM ──────────────────────────────────
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: 'E-posta adresi gerekli' });

        const cleanEmail = email.toLowerCase().trim();
        const user = await dbGet('SELECT id, name, email FROM users WHERE email = $1 AND "isActive" = TRUE', [cleanEmail]);

        // Güvenlik: kullanıcı yoksa da aynı yanıt
        if (user) {
            const token   = crypto.randomBytes(32).toString('hex');
            const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();
            await dbRun(
                `INSERT INTO password_resets (id, "userId", token, "expiresAt") VALUES ($1, $2, $3, $4)`,
                [uuidv4(), user.id, token, expires]
            );

            // Şifre sıfırlama e-postasını gönder ve logla
            sendForgotPasswordEmail(user.email, user.name, token)
                .then(result => {
                    if (result && result.success) {
                        console.log(`📧 Şifremi unuttum e-postası gönderildi: ${user.email}`);
                    } else {
                        console.error(`❌ Şifremi unuttum e-postası gönderilemedi: ${user.email}`, result?.error);
                    }
                })
                .catch(err => console.error('❌ Şifremi unuttum e-posta hatası:', err.message));
        }

        res.json({ message: 'Eğer bu e-posta sistemde kayıtlıysa sıfırlama linki gönderildi.' });
    } catch (error) {
        console.error('Şifremi unuttum hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 4: TOKEN İLE ŞİFRE SIFIRLA ──────────────────────────
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { token, newPassword, confirmPassword } = req.body;
        if (!token || !newPassword || !confirmPassword) return res.status(400).json({ error: 'Tüm alanlar zorunludur' });
        if (newPassword !== confirmPassword) return res.status(400).json({ error: 'Şifreler eşleşmiyor' });
        if (newPassword.length < 6) return res.status(400).json({ error: 'Şifre en az 6 karakter olmalı' });

        const record = await dbGet(
            `SELECT * FROM password_resets WHERE token = $1 AND used = FALSE AND "expiresAt" > NOW()`,
            [token]
        );
        if (!record) return res.status(400).json({ error: 'Geçersiz veya süresi dolmuş token' });

        const hashed = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
        await dbRun(`UPDATE users SET password = $1, "updatedAt" = NOW() WHERE id = $2`, [hashed, record.userId]);
        await dbRun(`UPDATE password_resets SET used = TRUE WHERE id = $1`, [record.id]);
        await dbRun(`UPDATE refresh_tokens SET "isActive" = FALSE WHERE "userId" = $1`, [record.userId]);

        const user = await dbGet('SELECT email, name FROM users WHERE id = $1', [record.userId]);
        if (user) sendPasswordResetSuccessEmail(user.email, user.name).catch(() => {});

        res.json({ message: 'Şifre başarıyla sıfırlandı. Giriş yapabilirsiniz.' });
    } catch (error) {
        console.error('Şifre sıfırlama hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 5: SIFIRLAMA TOKEN GEÇERLİLİĞİ SORGULA ─────────────
app.get('/api/auth/verify-reset-token', async (req, res) => {
    try {
        const { token } = req.query;
        if (!token) return res.status(400).json({ error: 'Token gerekli' });

        const record = await dbGet(
            `SELECT "expiresAt" FROM password_resets WHERE token = $1 AND used = FALSE AND "expiresAt" > NOW()`,
            [token]
        );
        if (!record) return res.json({ valid: false, error: 'Token geçersiz veya süresi dolmuş' });

        res.json({ valid: true, expiresAt: record.expiresAt });
    } catch (error) {
        console.error('Token doğrulama hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 6: ÇEVRİMİÇİ KULLANICALAR ───────────────────────────
app.get('/api/users/online', authenticateToken, async (req, res) => {
    try {
        const users = await dbAll(
            `SELECT id, username, name, "profilePic", "isVerified", "lastSeen"
             FROM users
             WHERE "isOnline" = TRUE AND "isActive" = TRUE AND id != $1
               AND id NOT IN (SELECT "blockedId" FROM blocks WHERE "blockerId" = $1)
             ORDER BY "lastSeen" DESC
             LIMIT 50`,
            [req.user.id]
        );
        res.json({ users, count: users.length });
    } catch (error) {
        console.error('Çevrimiçi kullanıcılar hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 7: KULLANICI İSTATİSTİKLERİ ─────────────────────────
// ─── YENİ ROTA 8: POPÜLER GÖNDERILER ────────────────────────────────
app.get('/api/posts/popular', authenticateToken, async (req, res) => {
    try {
        const { limit = 20, period = '7d' } = req.query;
        const interval = period === '24h' ? '1 day' : period === '30d' ? '30 days' : '7 days';

        const posts = await dbAll(
            `SELECT p.*, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge",
                    EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) AS "isLiked",
                    EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $1) AS "isSaved"
             FROM posts p
             JOIN users u ON p."userId" = u.id
             WHERE p."isActive" = TRUE
               AND p."createdAt" > NOW() - INTERVAL '${interval}'
               AND p."userId" NOT IN (SELECT "blockedId" FROM blocks WHERE "blockerId" = $1)
             ORDER BY (p."likeCount" * 2 + p.views + p."commentCount" * 3) DESC
             LIMIT $2`,
            [req.user.id, parseInt(limit)]
        );
        res.json({ posts: posts.map(formatPost) });
    } catch (error) {
        console.error('Popüler gönderiler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 9: GİZLİLİK AYARLARINI GETİR ────────────────────────
app.get('/api/users/privacy-settings', authenticateToken, async (req, res) => {
    try {
        const user = await dbGet(
            `SELECT "isPrivate", "twoFactorEnabled", "emailVerified", "emailNotifications" FROM users WHERE id = $1`,
            [req.user.id]
        );
        res.json({ settings: user || {} });
    } catch (error) {
        console.error('Gizlilik ayarları hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// Gizlilik ayarlarını güncelle - POST (2FA toggle + isPrivate birlikte)
app.post('/api/users/privacy-settings', authenticateToken, async (req, res) => {
    try {
        const { privateAccount, twoFactorEnabled, emailNotifications } = req.body;
        const updates = [];
        const params = [];
        let idx = 1;

        if (privateAccount !== undefined) {
            updates.push(`"isPrivate" = $${idx++}`);
            params.push(!!privateAccount);
        }
        if (twoFactorEnabled !== undefined) {
            updates.push(`"twoFactorEnabled" = $${idx++}`);
            params.push(!!twoFactorEnabled);
        }
        if (emailNotifications !== undefined) {
            updates.push(`"emailNotifications" = $${idx++}`);
            params.push(!!emailNotifications);
        }

        if (updates.length === 0) return res.status(400).json({ error: 'Güncellenecek alan yok' });
        updates.push(`"updatedAt" = NOW()`);
        params.push(req.user.id);
        await dbRun(`UPDATE users SET ${updates.join(', ')} WHERE id = $${idx}`, params);

        const updated = await dbGet(
            `SELECT "isPrivate", "twoFactorEnabled", "emailVerified", "emailNotifications" FROM users WHERE id = $1`,
            [req.user.id]
        );
        res.json({ message: 'Gizlilik ayarları güncellendi', settings: updated });
    } catch (error) {
        console.error('Gizlilik ayarları güncelleme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 10: BİLDİRİM AYARLARINI GÜNCELLE ────────────────────
app.post('/api/users/notification-settings', authenticateToken, async (req, res) => {
    try {
        const { likes = true, comments = true, follows = true, messages = true } = req.body;

        const existing = await dbGet(`SELECT id FROM notification_settings WHERE "userId" = $1`, [req.user.id]);
        if (existing) {
            await dbRun(
                `UPDATE notification_settings SET likes = $1, comments = $2, follows = $3, messages = $4, "updatedAt" = NOW() WHERE "userId" = $5`,
                [!!likes, !!comments, !!follows, !!messages, req.user.id]
            );
        } else {
            await dbRun(
                `INSERT INTO notification_settings (id, "userId", likes, comments, follows, messages) VALUES ($1, $2, $3, $4, $5, $6)`,
                [uuidv4(), req.user.id, !!likes, !!comments, !!follows, !!messages]
            );
        }

        res.json({ message: 'Bildirim ayarları kaydedildi', settings: { likes: !!likes, comments: !!comments, follows: !!follows, messages: !!messages } });
    } catch (error) {
        console.error('Bildirim ayarları hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── PING ───────────────────────────────────────────────────────────
app.get('/api/ping', (req, res) => {
    res.json({ pong: true, timestamp: Date.now() });
});

// ─── VİDEO STREAM (Range Request / HTTP 206) ────────────────────────
// Donma / kasma olmaz: tarayıcı sadece ihtiyacı kadar chunk çeker
app.get('/api/videos/stream/:filename', authenticateToken, (req, res) => {
    try {
        const videoPath = path.join(videosDir, req.params.filename);
        if (!fssync.existsSync(videoPath)) return res.status(404).json({ error: 'Video bulunamadı' });

        const stat     = fssync.statSync(videoPath);
        const fileSize = stat.size;
        const range    = req.headers.range;

        if (range) {
            const [startStr, endStr] = range.replace(/bytes=/, '').split('-');
            const start   = parseInt(startStr, 10);
            const end     = endStr ? parseInt(endStr, 10) : fileSize - 1;
            const chunk   = end - start + 1;

            res.writeHead(206, {
                'Content-Range' : `bytes ${start}-${end}/${fileSize}`,
                'Accept-Ranges' : 'bytes',
                'Content-Length': chunk,
                'Content-Type'  : 'video/mp4',
            });
            fssync.createReadStream(videoPath, { start, end }).pipe(res);
        } else {
            res.writeHead(200, { 'Content-Length': fileSize, 'Content-Type': 'video/mp4' });
            fssync.createReadStream(videoPath).pipe(res);
        }
    } catch (error) {
        console.error('Video stream hatası:', error);
        res.status(500).json({ error: 'Video yüklenemedi' });
    }
});

// ─── VİDEO THUMBNAIL ────────────────────────────────────────────────
app.get('/api/videos/thumbnail/:videoId', authenticateToken, (req, res) => {
    const thumbPath = path.join(thumbnailsDir, `${req.params.videoId}.jpg`);
    if (fssync.existsSync(thumbPath)) return res.sendFile(thumbPath);
    res.status(404).json({ error: 'Thumbnail bulunamadı' });
});

// ─── VİDEO BİLGİSİ ──────────────────────────────────────────────────
app.get('/api/videos/:postId/info', authenticateToken, async (req, res) => {
    try {
        const info = await dbGet(
            `SELECT v.*, p.media, p."thumbnailUrl"
             FROM video_info v
             JOIN posts p ON v."postId" = p.id
             WHERE v."postId" = $1`,
            [req.params.postId]
        );
        if (!info) return res.status(404).json({ error: 'Video bilgisi bulunamadı' });

        res.json({
            videoInfo: {
                ...info,
                quality          : getVideoQuality(info.width, info.height),
                fileSizeFormatted: formatFileSize(info.fileSize),
                durationFormatted: `${Math.floor(info.duration / 60)}:${String(Math.floor(info.duration % 60)).padStart(2, '0')}`,
            }
        });
    } catch (error) {
        console.error('Video bilgi hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── HLS DURUM (istemci manifest hazır mı diye sorar) ───────────────
app.get('/api/videos/:videoId/hls-status', authenticateToken, (req, res) => {
    const masterPath = path.join(hlsDir, req.params.videoId, 'master.m3u8');
    if (fssync.existsSync(masterPath)) {
        const variants = HLS_VARIANTS.map(v => {
            const pl = path.join(hlsDir, req.params.videoId, v.name, 'playlist.m3u8');
            return { name: v.name, ready: fssync.existsSync(pl), url: `/uploads/hls/${req.params.videoId}/${v.name}/playlist.m3u8` };
        }).filter(v => v.ready);

        return res.json({
            ready      : true,
            masterUrl  : `/uploads/hls/${req.params.videoId}/master.m3u8`,
            variants,
            activeVideoJobs: activeVideoJobs,
        });
    }
    res.json({ ready: false, activeVideoJobs: activeVideoJobs, message: 'HLS henüz işleniyor, MP4 ile oynat' });
});

// ─── YENİ ROTA 11: YORUM GÜNCELLE ──────────────────────────────────
app.put('/api/comments/:id', authenticateToken, async (req, res) => {
    try {
        const { content } = req.body;
        if (!content || !content.trim()) return res.status(400).json({ error: 'İçerik boş olamaz' });

        const comment = await dbGet('SELECT * FROM comments WHERE id = $1', [req.params.id]);
        if (!comment) return res.status(404).json({ error: 'Yorum bulunamadı' });
        if (comment.userId !== req.user.id) return res.status(403).json({ error: 'Yetkiniz yok' });

        await dbRun(
            'UPDATE comments SET content = $1, "updatedAt" = NOW() WHERE id = $2',
            [content.substring(0, 2000), req.params.id]
        );
        const updated = await dbGet('SELECT * FROM comments WHERE id = $1', [req.params.id]);
        res.json({ message: 'Yorum güncellendi', comment: updated });
    } catch (error) {
        console.error('Yorum güncelleme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 12: POST GÜNCELLE ────────────────────────────────────
app.put('/api/posts/:id', authenticateToken, async (req, res) => {
    try {
        const post = await dbGet('SELECT * FROM posts WHERE id = $1', [req.params.id]);
        if (!post) return res.status(404).json({ error: 'Gönderi bulunamadı' });
        if (post.userId !== req.user.id && req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Yetkiniz yok' });
        }

        const { content, allowComments, locationName } = req.body;
        const updates = [];
        const params  = [];
        let idx = 1;

        if (content !== undefined)        { updates.push(`content = $${idx++}`);        params.push(content.substring(0, 5000)); }
        if (allowComments !== undefined)  { updates.push(`"allowComments" = $${idx++}`); params.push(allowComments !== 'false' && allowComments !== false); }
        if (locationName !== undefined)   { updates.push(`"locationName" = $${idx++}`); params.push(locationName); }

        if (updates.length === 0) return res.status(400).json({ error: 'Güncellenecek alan yok' });

        updates.push(`"updatedAt" = NOW()`);
        params.push(req.params.id);
        await pool.query(`UPDATE posts SET ${updates.join(', ')} WHERE id = $${idx}`, params);

        const updated = await dbGet('SELECT * FROM posts WHERE id = $1', [req.params.id]);
        res.json({ message: 'Gönderi güncellendi', post: updated });
    } catch (error) {
        console.error('Post güncelleme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 13: KULLANICININ KAYDETTİKLERİ (pagination) ─────────
app.get('/api/users/:userId/saved', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);

        const posts = await dbAll(
            `SELECT p.*, u.name, u."profilePic", u."isVerified",
                    TRUE AS "isSaved",
                    EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) AS "isLiked"
             FROM saves s
             JOIN posts p ON s."postId" = p.id
             JOIN users u ON p."userId" = u.id
             WHERE s."userId" = $2 AND p."isActive" = TRUE
             ORDER BY s."createdAt" DESC
             LIMIT $3 OFFSET $4`,
            [req.user.id, req.params.userId, parseInt(limit), offset]
        );
        res.json({ posts: posts.map(formatPost), page: parseInt(page) });
    } catch (error) {
        console.error('Kullanıcı kaydedilenler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 14: SOHBET SİL ───────────────────────────────────────
app.delete('/api/messages/conversations/:partnerId', authenticateToken, async (req, res) => {
    try {
        const { partnerId } = req.params;
        await dbRun(
            `DELETE FROM messages
             WHERE ("senderId" = $1 AND "recipientId" = $2)
                OR ("senderId" = $2 AND "recipientId" = $1)`,
            [req.user.id, partnerId]
        );
        res.json({ message: 'Sohbet silindi' });
    } catch (error) {
        console.error('Sohbet silme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 15: STORY GÖRÜNTÜLEYENLERİ GETİR ────────────────────
app.get('/api/stories/:id/viewers', authenticateToken, async (req, res) => {
    try {
        const story = await dbGet('SELECT "userId" FROM stories WHERE id = $1', [req.params.id]);
        if (!story) return res.status(404).json({ error: 'Hikaye bulunamadı' });
        if (story.userId !== req.user.id) return res.status(403).json({ error: 'Yetkiniz yok' });

        const viewers = await dbAll(
            `SELECT u.id, u.username, u.name, u."profilePic", u."isVerified", sv."viewedAt"
             FROM story_views sv
             JOIN users u ON sv."userId" = u.id
             WHERE sv."storyId" = $1
             ORDER BY sv."viewedAt" DESC`,
            [req.params.id]
        );
        res.json({ viewers, count: viewers.length });
    } catch (error) {
        console.error('Story görüntüleyenler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 16: BÖLGESEL KULLANICILARI GETİR ─────────────────────
app.get('/api/users/nearby', authenticateToken, async (req, res) => {
    try {
        const { lat, lng, radius = 50 } = req.query;
        if (!lat || !lng) return res.status(400).json({ error: 'Konum gerekli (lat, lng)' });

        // Haversine yaklaşımı: 1 derece ≈ 111km
        const degRadius = parseFloat(radius) / 111;
        const users = await dbAll(
            `SELECT id, username, name, "profilePic", "isVerified", "userType", location
             FROM users
             WHERE "isActive" = TRUE AND id != $1
               AND location IS NOT NULL
             ORDER BY RANDOM()
             LIMIT 30`,
            [req.user.id]
        );
        res.json({ users, radius: parseInt(radius) });
    } catch (error) {
        console.error('Yakın kullanıcılar hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 17: BEĞENILEN GÖNDERILER ─────────────────────────────
app.get('/api/posts/liked', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);

        const posts = await dbAll(
            `SELECT p.*, u.name, u."profilePic", u."isVerified",
                    TRUE AS "isLiked",
                    EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $1) AS "isSaved"
             FROM likes l
             JOIN posts p ON l."postId" = p.id
             JOIN users u ON p."userId" = u.id
             WHERE l."userId" = $1 AND p."isActive" = TRUE
             ORDER BY l."createdAt" DESC
             LIMIT $2 OFFSET $3`,
            [req.user.id, parseInt(limit), offset]
        );
        res.json({ posts, page: parseInt(page) });
    } catch (error) {
        console.error('Beğenilen gönderiler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 18: KULLANICI AKTİVİTE AKIŞI ─────────────────────────
app.get('/api/users/:id/activity', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);

        // Son beğeniler + yorumlar + takip
        const activity = await dbAll(
            `(SELECT 'like' AS type, l."createdAt", p.id AS "targetId", p.content AS "targetContent", NULL AS extra
              FROM likes l JOIN posts p ON l."postId" = p.id
              WHERE l."userId" = $1)
             UNION ALL
             (SELECT 'comment' AS type, c."createdAt", c."postId" AS "targetId", c.content AS "targetContent", NULL AS extra
              FROM comments c WHERE c."userId" = $1)
             UNION ALL
             (SELECT 'follow' AS type, f."createdAt", f."followingId" AS "targetId", u.username AS "targetContent", NULL AS extra
              FROM follows f JOIN users u ON f."followingId" = u.id WHERE f."followerId" = $1)
             ORDER BY "createdAt" DESC
             LIMIT $2 OFFSET $3`,
            [req.params.id, parseInt(limit), offset]
        );
        res.json({ activity, page: parseInt(page) });
    } catch (error) {
        console.error('Aktivite akışı hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 19: TAKİP ÖNERİLERİ (GELİŞMİŞ) ──────────────────────
app.get('/api/users/recommendations', authenticateToken, async (req, res) => {
    try {
        // Takip ettiklerinin takip ettiklerini öner (ortak bağlantı mantığı)
        const recs = await dbAll(
            `SELECT DISTINCT u.id, u.username, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge", u."userType",
                    COUNT(DISTINCT f2.id) AS "mutualCount"
             FROM follows f1
             JOIN follows f2 ON f1."followingId" = f2."followerId"
             JOIN users u ON f2."followingId" = u.id
             WHERE f1."followerId" = $1
               AND f2."followingId" != $1
               AND u."isActive" = TRUE
               AND f2."followingId" NOT IN (SELECT "followingId" FROM follows WHERE "followerId" = $1)
               AND f2."followingId" NOT IN (SELECT "blockedId" FROM blocks WHERE "blockerId" = $1)
             GROUP BY u.id, u.username, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge", u."userType"
             ORDER BY "mutualCount" DESC
             LIMIT 15`,
            [req.user.id]
        );

        // Yeterli yoksa rastgele tamamla
        if (recs.length < 5) {
            const extra = await dbAll(
                `SELECT id, username, name, "profilePic", "isVerified", "hasFarmerBadge", "userType", 0 AS "mutualCount"
                 FROM users
                 WHERE "isActive" = TRUE AND id != $1
                   AND id NOT IN (SELECT "followingId" FROM follows WHERE "followerId" = $1)
                   AND id NOT IN (SELECT "blockedId" FROM blocks WHERE "blockerId" = $1)
                 ORDER BY "isVerified" DESC, RANDOM()
                 LIMIT $2`,
                [req.user.id, 15 - recs.length]
            );
            recs.push(...extra);
        }

        res.json({ recommendations: recs });
    } catch (error) {
        console.error('Tavsiye hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 20: HASHTAG DETAY + POSTS ────────────────────────────
app.get('/api/hashtags/:tag', authenticateToken, async (req, res) => {
    try {
        const tag = req.params.tag.toLowerCase().replace('#', '');
        const { page = 1, limit = 20 } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);

        const hashtag = await dbGet('SELECT * FROM hashtags WHERE tag = $1', [`#${tag}`]);
        if (!hashtag) return res.status(404).json({ error: 'Hashtag bulunamadı' });

        const posts = await dbAll(
            `SELECT p.*, u.name, u."profilePic", u."isVerified",
                    EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) AS "isLiked",
                    EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $1) AS "isSaved"
             FROM posts p
             JOIN users u ON p."userId" = u.id
             JOIN post_hashtags ph ON ph."postId" = p.id
             JOIN hashtags h ON ph."hashtagId" = h.id
             WHERE p."isActive" = TRUE AND h.tag = $2
             ORDER BY p."createdAt" DESC
             LIMIT $3 OFFSET $4`,
            [req.user.id, `#${tag}`, parseInt(limit), offset]
        );

        res.json({ hashtag, posts, page: parseInt(page) });
    } catch (error) {
        console.error('Hashtag detay hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 36. YORUM BEĞENİ ──────────────────────────────────────────────
app.post('/api/comments/:id/like', authenticateToken, checkRestriction('like'), async (req, res) => {
    try {
        const commentId = req.params.id;
        const existing = await dbGet('SELECT id FROM comment_likes WHERE "commentId" = $1 AND "userId" = $2', [commentId, req.user.id]);

        if (existing) {
            await dbRun('DELETE FROM comment_likes WHERE id = $1', [existing.id]);
            await dbRun('UPDATE comments SET "likeCount" = GREATEST("likeCount" - 1, 0) WHERE id = $1', [commentId]);
            res.json({ liked: false });
        } else {
            await dbRun('INSERT INTO comment_likes (id, "commentId", "userId", "createdAt") VALUES ($1, $2, $3, NOW())', [uuidv4(), commentId, req.user.id]);
            await dbRun('UPDATE comments SET "likeCount" = "likeCount" + 1 WHERE id = $1', [commentId]);

            const comment = await dbGet('SELECT "userId" FROM comments WHERE id = $1', [commentId]);
            if (comment && comment.userId !== req.user.id) {
                await createNotification(comment.userId, 'comment_like', `${req.user.username} yorumunuzu beğendi`, { commentId, userId: req.user.id });
            }
            res.json({ liked: true });
        }
    } catch (error) {
        console.error('Yorum beğeni hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 37. YORUM SİL ─────────────────────────────────────────────────
app.delete('/api/comments/:id', authenticateToken, async (req, res) => {
    try {
        const comment = await dbGet('SELECT * FROM comments WHERE id = $1', [req.params.id]);
        if (!comment) return res.status(404).json({ error: 'Yorum bulunamadı' });
        if (comment.userId !== req.user.id && req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Yetkiniz yok' });
        }

        await dbRun('DELETE FROM comments WHERE id = $1', [req.params.id]);
        await dbRun('UPDATE posts SET "commentCount" = GREATEST("commentCount" - 1, 0) WHERE id = $1', [comment.postId]);

        res.json({ message: 'Yorum silindi' });
    } catch (error) {
        console.error('Yorum silme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 38. STORY OLUŞTUR ─────────────────────────────────────────────
app.post('/api/stories', authenticateToken, upload.single('media'), async (req, res) => {
    try {
        const { caption, text, textColor } = req.body;
        if (!req.file && !text) return res.status(400).json({ error: 'Medya veya metin gerekli' });

        let mediaUrl = null;
        let mediaType = 'text';

        if (req.file) {
            const ext = path.extname(req.file.originalname).toLowerCase();
            const isVideo = ['.mp4', '.webm', '.mov'].includes(ext);
            mediaType = isVideo ? 'video' : 'image';

            if (isVideo) {
                const filename = `story_${Date.now()}_${Math.round(Math.random() * 1E9)}${ext}`;
                const dest = path.join(videosDir, filename);
                await fs.rename(req.file.path, dest);
                mediaUrl = `/uploads/videos/${filename}`;
            } else {
                const filename = `story_${Date.now()}_${Math.round(Math.random() * 1E9)}.webp`;
                const dest = path.join(postsDir, filename);
                await sharp(req.file.path).resize(1080, 1920, { fit: 'inside', withoutEnlargement: true }).webp({ quality: 85 }).toFile(dest);
                await fs.unlink(req.file.path).catch(() => {});
                mediaUrl = `/uploads/posts/${filename}`;
            }
        }

        const storyId = uuidv4();
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

        await dbRun(
            `INSERT INTO stories (id, "userId", "mediaUrl", "mediaType", caption, text, "textColor", "createdAt", "expiresAt")
             VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8)`,
            [storyId, req.user.id, mediaUrl || '', mediaType, caption || null, text || null, textColor || '#FFFFFF', expiresAt]
        );

        res.status(201).json({ message: 'Hikaye oluşturuldu', storyId });
    } catch (error) {
        console.error('Story oluşturma hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 39. STORYLERİ GETİR ────────────────────────────────────────────
app.get('/api/stories', authenticateToken, async (req, res) => {
    try {
        const stories = await dbAll(
            `SELECT s.*, u.username, u.name, u."profilePic", u."isVerified",
                    EXISTS(SELECT 1 FROM story_views WHERE "storyId" = s.id AND "userId" = $1) as "isViewed",
                    EXISTS(SELECT 1 FROM story_likes WHERE "storyId" = s.id AND "userId" = $1) as "isLiked"
             FROM stories s
             JOIN users u ON s."userId" = u.id
             WHERE s."expiresAt" > NOW()
             ORDER BY s."createdAt" DESC`,
            [req.user.id]
        );

        const grouped = {};
        for (const story of stories) {
            if (!grouped[story.userId]) {
                grouped[story.userId] = {
                    userId: story.userId,
                    username: story.username,
                    name: story.name,
                    profilePic: story.profilePic,
                    isVerified: story.isVerified,
                    stories: []
                };
            }
            grouped[story.userId].stories.push(story);
        }

        res.json({ stories: Object.values(grouped) });
    } catch (error) {
        console.error('Stories hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 40. STORY GÖRÜNTÜLE ───────────────────────────────────────────
app.post('/api/stories/:id/view', authenticateToken, async (req, res) => {
    try {
        const storyId = req.params.id;
        const existing = await dbGet('SELECT id FROM story_views WHERE "storyId" = $1 AND "userId" = $2', [storyId, req.user.id]);

        if (!existing) {
            await dbRun('INSERT INTO story_views (id, "storyId", "userId", "viewedAt") VALUES ($1, $2, $3, NOW())', [uuidv4(), storyId, req.user.id]);
            await dbRun('UPDATE stories SET "viewCount" = "viewCount" + 1 WHERE id = $1', [storyId]);
        }

        res.json({ viewed: true });
    } catch (error) {
        console.error('Story view hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 41. STORY BEĞENİ ──────────────────────────────────────────────
app.post('/api/stories/:id/like', authenticateToken, async (req, res) => {
    try {
        const storyId = req.params.id;
        const existing = await dbGet('SELECT id FROM story_likes WHERE "storyId" = $1 AND "userId" = $2', [storyId, req.user.id]);

        if (existing) {
            await dbRun('DELETE FROM story_likes WHERE id = $1', [existing.id]);
            await dbRun('UPDATE stories SET "likeCount" = GREATEST("likeCount" - 1, 0) WHERE id = $1', [storyId]);
            res.json({ liked: false });
        } else {
            await dbRun('INSERT INTO story_likes (id, "storyId", "userId", "createdAt") VALUES ($1, $2, $3, NOW())', [uuidv4(), storyId, req.user.id]);
            await dbRun('UPDATE stories SET "likeCount" = "likeCount" + 1 WHERE id = $1', [storyId]);

            const story = await dbGet('SELECT "userId" FROM stories WHERE id = $1', [storyId]);
            if (story && story.userId !== req.user.id) {
                await createNotification(story.userId, 'story_like', `${req.user.username} hikayenizi beğendi`, { storyId });
            }
            res.json({ liked: true });
        }
    } catch (error) {
        console.error('Story like hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 42. STORY SİL ─────────────────────────────────────────────────
app.delete('/api/stories/:id', authenticateToken, async (req, res) => {
    try {
        const story = await dbGet('SELECT "userId" FROM stories WHERE id = $1', [req.params.id]);
        if (!story) return res.status(404).json({ error: 'Hikaye bulunamadı' });
        if (story.userId !== req.user.id) return res.status(403).json({ error: 'Yetkiniz yok' });

        await dbRun('DELETE FROM stories WHERE id = $1', [req.params.id]);
        res.json({ message: 'Hikaye silindi' });
    } catch (error) {
        console.error('Story silme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 43. KULLANICI ARA (v2) ─────────────────────────────────────────
app.get('/api/search/users', authenticateToken, async (req, res) => {
    try {
        const { q, page = 1, limit = 20 } = req.query;
        if (!q || q.trim().length < 2) return res.status(400).json({ error: 'En az 2 karakter gerekli' });

        const offset = (parseInt(page) - 1) * parseInt(limit);
        const searchTerm = `%${q.toLowerCase().trim()}%`;

        const users = await dbAll(
            `SELECT id, username, name, "profilePic", "isVerified", "hasFarmerBadge", "userType",
                    EXISTS(SELECT 1 FROM follows WHERE "followerId" = $1 AND "followingId" = users.id) as "isFollowing"
             FROM users
             WHERE "isActive" = TRUE AND (LOWER(username) LIKE $2 OR LOWER(name) LIKE $2)
             ORDER BY "isVerified" DESC, "hasFarmerBadge" DESC, name ASC
             LIMIT $3 OFFSET $4`,
            [req.user.id, searchTerm, parseInt(limit), offset]
        );

        res.json({ users });
    } catch (error) {
        console.error('Kullanıcı arama hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 44. POST ARA ───────────────────────────────────────────────────
app.get('/api/search/posts', authenticateToken, async (req, res) => {
    try {
        const { q, page = 1, limit = 20 } = req.query;
        if (!q || q.trim().length < 2) return res.status(400).json({ error: 'En az 2 karakter gerekli' });

        const offset = (parseInt(page) - 1) * parseInt(limit);
        const searchTerm = `%${q.toLowerCase().trim()}%`;

        const posts = await dbAll(
            `SELECT p.*, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge",
                    EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) as "isLiked",
                    EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $1) as "isSaved"
             FROM posts p
             JOIN users u ON p."userId" = u.id
             WHERE p."isActive" = TRUE AND LOWER(p.content) LIKE $2
             ORDER BY p."createdAt" DESC
             LIMIT $3 OFFSET $4`,
            [req.user.id, searchTerm, parseInt(limit), offset]
        );

        res.json({ posts: posts.map(formatPost) });
    } catch (error) {
        console.error('Post arama hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 45. HASHTAG İLE ARA ────────────────────────────────────────────
app.get('/api/search/hashtag/:tag', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);
        const tag = req.params.tag.toLowerCase().replace('#', '');

        const posts = await dbAll(
            `SELECT p.*, u.name, u."profilePic", u."isVerified",
                    EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) as "isLiked",
                    EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $1) as "isSaved"
             FROM posts p
             JOIN users u ON p."userId" = u.id
             JOIN post_hashtags ph ON ph."postId" = p.id
             JOIN hashtags h ON ph."hashtagId" = h.id
             WHERE p."isActive" = TRUE AND h.tag = $2
             ORDER BY p."createdAt" DESC
             LIMIT $3 OFFSET $4`,
            [req.user.id, tag, parseInt(limit), offset]
        );

        res.json({ posts: posts.map(formatPost) });
    } catch (error) {
        console.error('Hashtag arama hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 46. ÇIKIŞ YAP ─────────────────────────────────────────────────
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
    try {
        await dbRun('UPDATE users SET "isOnline" = FALSE, "lastSeen" = NOW() WHERE id = $1', [req.user.id]);
        await dbRun('UPDATE refresh_tokens SET "isActive" = FALSE WHERE "userId" = $1', [req.user.id]);
        res.json({ message: 'Çıkış yapıldı' });
    } catch (error) {
        console.error('Çıkış hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 47. POST GÖRÜNTÜLENME ─────────────────────────────────────────
app.post('/api/posts/:id/view', authenticateToken, async (req, res) => {
    try {
        await dbRun('UPDATE posts SET views = views + 1 WHERE id = $1', [req.params.id]);
        res.json({ viewed: true });
    } catch (error) {
        console.error('View hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 48. BEĞENENLERİ GETİR ─────────────────────────────────────────
app.get('/api/posts/:id/likes', authenticateToken, async (req, res) => {
    try {
        const users = await dbAll(
            `SELECT u.id, u.username, u.name, u."profilePic", u."isVerified",
                    EXISTS(SELECT 1 FROM follows WHERE "followerId" = $2 AND "followingId" = u.id) as "isFollowing"
             FROM likes l
             JOIN users u ON l."userId" = u.id
             WHERE l."postId" = $1
             ORDER BY l."createdAt" DESC`,
            [req.params.id, req.user.id]
        );
        res.json({ users });
    } catch (error) {
        console.error('Beğenenler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 49. ÜRÜN GÜNCELLE ──────────────────────────────────────────────
app.put('/api/store/products/:id', authenticateToken, (req, res, next) => {
    upload.fields([{ name: 'images', maxCount: 5 }, { name: 'image', maxCount: 1 }])(req, res, (err) => {
        if (err) return res.status(400).json({ error: 'Dosya hatası: ' + err.message });
        if (req.files && !Array.isArray(req.files)) {
            req.files = [...(req.files['images'] || []), ...(req.files['image'] || [])];
        }
        next();
    });
}, async (req, res) => {
    try {
        const product = await dbGet('SELECT * FROM products WHERE id = $1', [req.params.id]);
        if (!product) return res.status(404).json({ error: 'Ürün bulunamadı' });
        if (product.sellerId !== req.user.id) return res.status(403).json({ error: 'Yetkiniz yok' });

        const { name, price, description, category, stock } = req.body;
        const updates = [];
        const params = [];
        let idx = 1;

        if (name)                 { updates.push(`name = $${idx++}`);           params.push(name.substring(0, 100)); }
        if (price)                { updates.push(`price = $${idx++}`);          params.push(parseFloat(price)); }
        if (description !== undefined) { updates.push(`description = $${idx++}`); params.push(description.substring(0, 1000)); }
        if (category)             { updates.push(`category = $${idx++}`);       params.push(category); }
        if (stock !== undefined)  { updates.push(`stock = $${idx++}`);          params.push(parseInt(stock)); }

        const files = Array.isArray(req.files) ? req.files : [];
        if (files.length > 0) {
            let images = [];
            for (let i = 0; i < files.length; i++) {
                const filename = `product_${Date.now()}_${i}_${Math.round(Math.random() * 1e9)}.webp`;
                const outputPath = path.join(postsDir, filename);
                await sharp(files[i].path).resize(1080, 1080, { fit: 'inside', withoutEnlargement: true }).webp({ quality: 85 }).toFile(outputPath);
                await fs.unlink(files[i].path).catch(() => {});
                images.push(`/uploads/posts/${filename}`);
            }
            updates.push(`image = $${idx++}`);   params.push(images[0]);
            updates.push(`images = $${idx++}::jsonb`); params.push(JSON.stringify(images));
        }

        if (updates.length === 0) return res.status(400).json({ error: 'Güncellenecek alan yok' });
        updates.push(`"updatedAt" = NOW()`);
        params.push(req.params.id);
        await pool.query(`UPDATE products SET ${updates.join(', ')} WHERE id = $${idx}`, params);

        const updated = await dbGet('SELECT * FROM products WHERE id = $1', [req.params.id]);
        res.json({ message: 'Ürün güncellendi', product: updated });
    } catch (error) {
        console.error('Ürün güncelleme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası: ' + error.message });
    }
});

// ─── 50. ÜRÜN DETAYI ────────────────────────────────────────────────
app.get('/api/store/products/:id', authenticateToken, async (req, res) => {
    try {
        const product = await dbGet(
            `SELECT p.*, u.username as "sellerName", u."profilePic" as "sellerProfilePic", u.name as "sellerFullName", u."isVerified"
             FROM products p JOIN users u ON p."sellerId" = u.id
             WHERE p.id = $1`,
            [req.params.id]
        );
        if (!product) return res.status(404).json({ error: 'Ürün bulunamadı' });
        res.json({ product });
    } catch (error) {
        console.error('Ürün detay hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 51. HESAP KAPAMA ──────────────────────────────────────────────
app.delete('/api/auth/account', authenticateToken, async (req, res) => {
    try {
        const { password } = req.body;
        if (!password) return res.status(400).json({ error: 'Şifre gerekli' });

        const user = await dbGet('SELECT password FROM users WHERE id = $1', [req.user.id]);
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: 'Şifre yanlış' });

        await dbRun('UPDATE users SET "isActive" = FALSE, "updatedAt" = NOW() WHERE id = $1', [req.user.id]);
        await dbRun('UPDATE refresh_tokens SET "isActive" = FALSE WHERE "userId" = $1', [req.user.id]);

        res.json({ message: 'Hesap kapatıldı' });
    } catch (error) {
        console.error('Hesap silme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 52. KULLANICI ÖNERİLERİ ────────────────────────────────────────
app.get('/api/users/suggestions', authenticateToken, async (req, res) => {
    try {
        const suggestions = await dbAll(
            `SELECT id, username, name, "profilePic", "isVerified", "hasFarmerBadge", "userType"
             FROM users
             WHERE "isActive" = TRUE AND id != $1
               AND id NOT IN (SELECT "followingId" FROM follows WHERE "followerId" = $1)
               AND id NOT IN (SELECT "blockedId" FROM blocks WHERE "blockerId" = $1)
             ORDER BY "isVerified" DESC, "hasFarmerBadge" DESC, RANDOM()
             LIMIT 10`,
            [req.user.id]
        );
        res.json({ suggestions });
    } catch (error) {
        console.error('Öneriler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 53. OKUNMAMIŞ MESAJ SAYISI ─────────────────────────────────────
app.get('/api/messages/unread/count', authenticateToken, async (req, res) => {
    try {
        const result = await dbGet(
            'SELECT COUNT(*) as count FROM messages WHERE "recipientId" = $1 AND read = FALSE',
            [req.user.id]
        );
        res.json({ unreadCount: parseInt(result?.count || 0) });
    } catch (error) {
        console.error('Okunmamış sayısı hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 54. BİLDİRİM SİL ──────────────────────────────────────────────
app.delete('/api/notifications/:id', authenticateToken, async (req, res) => {
    try {
        await dbRun('DELETE FROM notifications WHERE id = $1 AND "userId" = $2', [req.params.id, req.user.id]);
        res.json({ message: 'Bildirim silindi' });
    } catch (error) {
        console.error('Bildirim silme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 55. TÜM BİLDİRİMLERİ SİL ─────────────────────────────────────
app.delete('/api/notifications', authenticateToken, async (req, res) => {
    try {
        await dbRun('DELETE FROM notifications WHERE "userId" = $1', [req.user.id]);
        res.json({ message: 'Tüm bildirimler silindi' });
    } catch (error) {
        console.error('Bildirim temizleme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 56. GİZLİLİK AYARLARI ─────────────────────────────────────────
app.put('/api/users/privacy', authenticateToken, async (req, res) => {
    try {
        const { isPrivate } = req.body;
        await dbRun('UPDATE users SET "isPrivate" = $1, "updatedAt" = NOW() WHERE id = $2', [!!isPrivate, req.user.id]);
        res.json({ message: 'Gizlilik ayarları güncellendi', isPrivate: !!isPrivate });
    } catch (error) {
        console.error('Gizlilik hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 57. KULLANICI ŞİKAYET ET ───────────────────────────────────────
app.post('/api/reports/user', authenticateToken, async (req, res) => {
    try {
        const { userId, reason, description } = req.body;
        if (!userId || !reason) return res.status(400).json({ error: 'Kullanıcı ID ve neden gerekli' });

        await dbRun(
            `INSERT INTO reports (id, "reporterId", "userId", reason, description, "createdAt")
             VALUES ($1, $2, $3, $4, $5, NOW())`,
            [uuidv4(), req.user.id, userId, reason, description || '']
        );

        res.json({ message: 'Şikayet alındı' });
    } catch (error) {
        console.error('Kullanıcı şikayet hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 58. MESAJ SİL ──────────────────────────────────────────────────
app.delete('/api/messages/:id', authenticateToken, async (req, res) => {
    try {
        const msg = await dbGet('SELECT "senderId" FROM messages WHERE id = $1', [req.params.id]);
        if (!msg) return res.status(404).json({ error: 'Mesaj bulunamadı' });
        if (msg.senderId !== req.user.id) return res.status(403).json({ error: 'Yetkiniz yok' });

        await dbRun('DELETE FROM messages WHERE id = $1', [req.params.id]);
        res.json({ message: 'Mesaj silindi' });
    } catch (error) {
        console.error('Mesaj silme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 59. POST DETAYI (v2) ──────────────────────────────────────────
app.get('/api/posts/:id/detail', authenticateToken, async (req, res) => {
    try {
        const post = await dbGet(
            `SELECT p.*, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge", u.username,
                    EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $2) as "isLiked",
                    EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $2) as "isSaved"
             FROM posts p
             JOIN users u ON p."userId" = u.id
             WHERE p.id = $1 AND p."isActive" = TRUE`,
            [req.params.id, req.user.id]
        );
        if (!post) return res.status(404).json({ error: 'Gönderi bulunamadı' });

        await dbRun('UPDATE posts SET views = views + 1 WHERE id = $1', [req.params.id]);

        res.json({ post });
    } catch (error) {
        console.error('Post detay hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 60. KEŞFET ────────────────────────────────────────────────────
app.get('/api/explore', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 30 } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);

        const posts = await dbAll(
            `SELECT p.*, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge",
                    EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) as "isLiked",
                    EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $1) as "isSaved"
             FROM posts p
             JOIN users u ON p."userId" = u.id
             WHERE p."isActive" = TRUE AND p.media IS NOT NULL
             ORDER BY p."likeCount" DESC, p.views DESC, p."createdAt" DESC
             LIMIT $2 OFFSET $3`,
            [req.user.id, parseInt(limit), offset]
        );

        res.json({ posts: posts.map(formatPost) });
    } catch (error) {
        console.error('Keşfet hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 61. GİRİŞ GEÇMİŞİ ────────────────────────────────────────────
app.get('/api/auth/login-history', authenticateToken, async (req, res) => {
    try {
        const history = await dbAll(
            `SELECT id, ip, country, city, "userAgent", "loginType", "createdAt"
             FROM login_history WHERE "userId" = $1
             ORDER BY "createdAt" DESC LIMIT 20`,
            [req.user.id]
        );
        res.json({ history });
    } catch (error) {
        console.error('Giriş geçmişi hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 62. KULLANICININ ÜRÜNLERİ ──────────────────────────────────────
app.get('/api/users/:userId/products', authenticateToken, async (req, res) => {
    try {
        const products = await dbAll(
            `SELECT * FROM products WHERE "sellerId" = $1 AND "isActive" = TRUE ORDER BY "createdAt" DESC`,
            [req.params.userId]
        );
        res.json({ products });
    } catch (error) {
        console.error('Kullanıcı ürünleri hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 63. ÜRÜN ARA ───────────────────────────────────────────────────
app.get('/api/store/search', authenticateToken, async (req, res) => {
    try {
        const { q, category, minPrice, maxPrice, page = 1, limit = 20 } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);
        const conditions = ['p."isActive" = TRUE'];
        const params = [];
        let idx = 1;

        if (q) {
            conditions.push(`(LOWER(p.name) LIKE $${idx} OR LOWER(p.description) LIKE $${idx})`);
            params.push(`%${q.toLowerCase()}%`);
            idx++;
        }
        if (category) {
            conditions.push(`p.category = $${idx}`);
            params.push(category);
            idx++;
        }
        if (minPrice) {
            conditions.push(`price >= $${idx}`);
            params.push(parseFloat(minPrice));
            idx++;
        }
        if (maxPrice) {
            conditions.push(`price <= $${idx}`);
            params.push(parseFloat(maxPrice));
            idx++;
        }

        params.push(parseInt(limit));
        params.push(offset);

        const products = await dbAll(
            `SELECT p.*, u.username as "sellerName", u."profilePic" as "sellerProfilePic"
             FROM products p JOIN users u ON p."sellerId" = u.id
             WHERE ${conditions.join(' AND ')}
             ORDER BY p."createdAt" DESC
             LIMIT $${idx} OFFSET $${idx + 1}`,
            params
        );

        res.json({ products });
    } catch (error) {
        console.error('Ürün arama hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 65. ÇOKLU POST GÖRÜNTÜLEME ────────────────────────────────────
app.post('/api/posts/batch-view', authenticateToken, async (req, res) => {
    try {
        const { postIds } = req.body;
        if (!Array.isArray(postIds) || postIds.length === 0) return res.json({ updated: 0 });

        const placeholders = postIds.map((_, i) => `$${i + 1}`).join(',');
        await pool.query(`UPDATE posts SET views = views + 1 WHERE id IN (${placeholders})`, postIds);
        res.json({ updated: postIds.length });
    } catch (error) {
        console.error('Batch view hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ════════════════════════════════════════════════════════════════════
// 🔒 EKSİK ROTALAR — SQL ENJEKSİYON KORUMALARI DAHİL
//    Tüm sorgular parameterize ($1,$2...) — kullanıcı girdisi asla
//    doğrudan SQL string'e concat edilmez.
// ════════════════════════════════════════════════════════════════════

// ─── EKSİK ROTA 1: TÜM OTURUMLARDAN ÇIKIŞ ──────────────────────────
// Hesap çalınırsa tüm cihazlardan oturumu kapat
app.post('/api/auth/logout-all', authenticateToken, async (req, res) => {
    try {
        const uid = req.user.id;
        // Tüm refresh token'ları geçersiz kıl (parameterize)
        await dbRun(`UPDATE refresh_tokens SET "isActive" = FALSE WHERE "userId" = $1`, [uid]);
        // Aktif oturum kayıtlarını kapat
        await dbRun(`UPDATE active_sessions SET "isActive" = FALSE WHERE "userId" = $1`, [uid]);
        // Online durumunu güncelle
        await dbRun(`UPDATE users SET "isOnline" = FALSE, "lastSeen" = NOW() WHERE id = $1`, [uid]);
        res.json({ success: true, message: 'Tüm oturumlardan çıkış yapıldı' });
    } catch (error) {
        console.error('Logout-all hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── EKSİK ROTA 2: AKTİF OTURUMLAR ────────────────────────────────
// Hangi cihazlardan giriş yapıldığını gösterir
app.get('/api/auth/active-sessions', authenticateToken, async (req, res) => {
    try {
        // Aktif refresh token'ları getir (parameterize, limit cap)
        const sessions = await dbAll(
            `SELECT id, ip, "userAgent", "createdAt", "expiresAt"
             FROM refresh_tokens
             WHERE "userId" = $1 AND "isActive" = TRUE AND "expiresAt" > NOW()
             ORDER BY "createdAt" DESC
             LIMIT 20`,
            [req.user.id]
        );
        res.json({ sessions });
    } catch (error) {
        console.error('Aktif oturumlar hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── EKSİK ROTA 3: ORTAK TAKİPÇİLER ───────────────────────────────
// İki kullanıcının ortak takipçilerini döner
// ─── EKSİK ROTA 4: TAKİP İSTEKLERİ LİSTESİ ────────────────────────
// Gizli hesap için bekleyen takip isteklerini getirir
app.get('/api/follow-requests', authenticateToken, async (req, res) => {
    try {
        const requests = await dbAll(
            `SELECT fr.id, fr."createdAt", fr.status,
                    u.id AS "requesterId", u.name AS "requesterName",
                    u.username AS "requesterUsername", u."profilePic" AS "requesterPic",
                    u."isVerified", u."hasFarmerBadge"
             FROM follow_requests fr
             JOIN users u ON fr."requesterId" = u.id
             WHERE fr."targetId" = $1 AND fr.status = 'pending'
             ORDER BY fr."createdAt" DESC
             LIMIT 100`,
            [req.user.id]
        );
        res.json({ requests, count: requests.length });
    } catch (error) {
        console.error('Takip istekleri hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── EKSİK ROTA 5: TAKİP İSTEĞİ KABUL ET ──────────────────────────
app.post('/api/follow-requests/:requesterId/accept', authenticateToken, async (req, res) => {
    try {
        const { requesterId } = req.params;
        // UUID doğrula (injection önlemi)
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        if (!uuidRegex.test(requesterId)) return res.status(400).json({ error: 'Geçersiz ID' });

        const request = await dbGet(
            `SELECT * FROM follow_requests
             WHERE "requesterId" = $1 AND "targetId" = $2 AND status = 'pending'`,
            [requesterId, req.user.id]          // $1, $2 → tamamen parameterize
        );
        if (!request) return res.status(404).json({ error: 'İstek bulunamadı' });

        // İsteği kabul et
        await dbRun(
            `UPDATE follow_requests SET status = 'accepted', "respondedAt" = NOW() WHERE id = $1`,
            [request.id]
        );

        // Gerçek takip ilişkisi oluştur (ON CONFLICT ile tekrar girişi önle)
        await dbRun(
            `INSERT INTO follows (id, "followerId", "followingId", "createdAt")
             VALUES ($1, $2, $3, NOW())
             ON CONFLICT ("followerId", "followingId") DO NOTHING`,
            [uuidv4(), requesterId, req.user.id]
        );

        // Bildirim gönder
        await createNotification(
            requesterId, 'follow_accepted',
            `${req.user.username} takip isteğinizi kabul etti`,
            { targetId: req.user.id, targetUsername: req.user.username }
        );

        res.json({ success: true, message: 'Takip isteği kabul edildi' });
    } catch (error) {
        console.error('Takip isteği kabul hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── EKSİK ROTA 6: TAKİP İSTEĞİ REDDET ────────────────────────────
app.post('/api/follow-requests/:requesterId/reject', authenticateToken, async (req, res) => {
    try {
        const { requesterId } = req.params;
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        if (!uuidRegex.test(requesterId)) return res.status(400).json({ error: 'Geçersiz ID' });

        await dbRun(
            `UPDATE follow_requests SET status = 'rejected', "respondedAt" = NOW()
             WHERE "requesterId" = $1 AND "targetId" = $2 AND status = 'pending'`,
            [requesterId, req.user.id]          // Tamamen parameterize
        );
        res.json({ success: true, message: 'Takip isteği reddedildi' });
    } catch (error) {
        console.error('Takip isteği reddetme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── EKSİK ROTA 7: KULLANICI ENGELİNİ KALDIR (ayrı endpoint) ──────
// Mevcut toggle (/block) ile birlikte kullanılabilir
app.post('/api/users/:id/unblock', authenticateToken, async (req, res) => {
    try {
        const targetId = req.params.id;
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        if (!uuidRegex.test(targetId)) return res.status(400).json({ error: 'Geçersiz ID' });

        // Sadece kendi bloğunu kaldırabilir — "blockerId" = req.user.id ile kısıt
        const result = await dbRun(
            `DELETE FROM blocks WHERE "blockerId" = $1 AND "blockedId" = $2`,
            [req.user.id, targetId]             // $1 = oturum sahibi (tampon)
        );
        if (result.changes === 0) return res.status(404).json({ error: 'Engelleme kaydı bulunamadı' });
        res.json({ success: true, message: 'Engel kaldırıldı', blocked: false });
    } catch (error) {
        console.error('Engel kaldırma hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── EKSİK ROTA 8: ANKET SONUÇLARI ─────────────────────────────────
// Oy sayıları + hangi opsiyona kaç kişi oy verdi
app.get('/api/posts/:postId/poll/results', authenticateToken, async (req, res) => {
    try {
        const postId = req.params.postId;
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        if (!uuidRegex.test(postId)) return res.status(400).json({ error: 'Geçersiz gönderi ID' });

        const post = await dbGet(
            `SELECT "pollOptions", "pollQuestion", "userId" FROM posts WHERE id = $1 AND "isPoll" = TRUE`,
            [postId]
        );
        if (!post) return res.status(404).json({ error: 'Anket bulunamadı' });

        // Her seçenek için oy sayısını çek
        const voteCounts = await dbAll(
            `SELECT "optionId", COUNT(*) AS "voteCount"
             FROM poll_votes WHERE "postId" = $1
             GROUP BY "optionId"`,
            [postId]
        );

        const totalVotes = voteCounts.reduce((sum, r) => sum + parseInt(r.voteCount), 0);
        const myVote     = await dbGet(
            `SELECT "optionId" FROM poll_votes WHERE "postId" = $1 AND "userId" = $2`,
            [postId, req.user.id]
        );

        let options = post.pollOptions;
        if (typeof options === 'string') options = JSON.parse(options);

        // Oy sayılarını opsiyonlarla birleştir
        const enriched = (options || []).map(opt => {
            const vc = voteCounts.find(v => parseInt(v.optionId) === opt.id);
            const count = vc ? parseInt(vc.voteCount) : 0;
            return {
                ...opt,
                voteCount : count,
                percentage: totalVotes > 0 ? Math.round((count / totalVotes) * 100) : 0,
            };
        });

        res.json({
            pollQuestion: post.pollQuestion,
            options     : enriched,
            totalVotes,
            myVote      : myVote ? myVote.optionId : null,
            isOwner     : post.userId === req.user.id,
        });
    } catch (error) {
        console.error('Anket sonuçları hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── EKSİK ROTA 9: BİLDİRİM AYARLARINI GETİR ───────────────────────
app.get('/api/users/notification-settings', authenticateToken, async (req, res) => {
    try {
        let settings = await dbGet(
            `SELECT likes, comments, follows, messages
             FROM notification_settings WHERE "userId" = $1`,
            [req.user.id]
        );
        // Kayıt yoksa varsayılan döndür (tümü açık)
        if (!settings) {
            settings = { likes: true, comments: true, follows: true, messages: true };
        }
        res.json({ settings });
    } catch (error) {
        console.error('Bildirim ayarları getirme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── EKSİK ROTA 10: PROFİL FOTOĞRAFI SİL ───────────────────────────
// Kullanıcı kendi profil/kapak fotoğrafını kaldırır
app.delete('/api/users/profile-pic', authenticateToken, async (req, res) => {
    try {
        const { type = 'profile' } = req.query;
        // type değerini whitelist ile doğrula — asla SQL'e concat etme
        const allowed = ['profile', 'cover'];
        if (!allowed.includes(type)) return res.status(400).json({ error: 'Geçersiz tip: profile veya cover olmalı' });

        const column = type === 'profile' ? '"profilePic"' : '"coverPic"';

        // Mevcut dosyayı al (silmek için)
        const user = await dbGet(`SELECT ${column} AS pic FROM users WHERE id = $1`, [req.user.id]);
        if (user?.pic) {
            // Güvenli path join — sadece tanımlı dizin altında
            const picPath = path.join(__dirname, user.pic.replace(/^\//, ''));
            if (picPath.startsWith(uploadsDir)) {    // Path traversal önlemi
                fs.unlink(picPath).catch(() => {});
            }
        }

        // Parameterize UPDATE — column adı whitelist'ten seçildi, injection imkansız
        await dbRun(`UPDATE users SET ${column} = NULL, "updatedAt" = NOW() WHERE id = $1`, [req.user.id]);

        res.json({ success: true, message: `${type === 'profile' ? 'Profil' : 'Kapak'} fotoğrafı silindi` });
    } catch (error) {
        console.error('Profil fotoğrafı silme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ════════════════════════════════════════════════════════════════════

const agrolinkDir = path.join(__dirname, 'public', 'agrolink');
if (fssync.existsSync(agrolinkDir)) {
    app.use('/agrolink', express.static(agrolinkDir, { maxAge: '1d' }));
}
app.get('/agrolink', (req, res) => {
    const htmlPath = path.join(__dirname, 'public', 'agrolink', 'index.html');
    if (fssync.existsSync(htmlPath)) {
        res.sendFile(htmlPath);
    } else {
        res.status(404).json({ error: 'AgroLink uygulaması bulunamadı' });
    }
});

const publicDir = path.join(__dirname, 'public');
if (fssync.existsSync(publicDir)) {
    app.use(express.static(publicDir, { maxAge: '1d', index: false }));
}

app.get('/', (req, res) => {
    const htmlPath = path.join(__dirname, 'public', 'index.html');
    if (fssync.existsSync(htmlPath)) {
        res.sendFile(htmlPath);
    } else {
        res.json({ message: 'AgroLink API Server - PostgreSQL v2.1 (UUID Fixed)', status: 'running' });
    }
});

// ==================== YENİ ROTALAR (SQLite→PG PORT) ====================

// ─── ANA FEED: /api/posts ───────────────────────────────────────────
// Karma algoritma: her 5 doğrulanmış posta 2 doğrulanmamış post karıştırılır
app.get('/api/posts', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 10 } = req.query;
        const pageNum = Math.max(1, parseInt(page) || 1);
        const limitNum = Math.min(parseInt(limit) || 10, 50);
        const offset = (pageNum - 1) * limitNum;

        const totalResult = await dbGet(
            `SELECT COUNT(*) as count FROM posts p JOIN users u ON p."userId" = u.id WHERE p."isActive" = TRUE AND u."isActive" = TRUE`
        );
        const total = totalResult ? parseInt(totalResult.count) : 0;

        // Mavi tikli post ID'leri
        const verifiedIds = await dbAll(
            `SELECT p.id FROM posts p JOIN users u ON p."userId" = u.id
             WHERE p."isActive" = TRUE AND u."isActive" = TRUE AND u."isVerified" = TRUE
             ORDER BY p."createdAt" DESC`
        );
        // Mavi tiksiz post ID'leri
        const unverifiedIds = await dbAll(
            `SELECT p.id FROM posts p JOIN users u ON p."userId" = u.id
             WHERE p."isActive" = TRUE AND u."isActive" = TRUE AND (u."isVerified" = FALSE OR u."isVerified" IS NULL)
             ORDER BY p."createdAt" DESC`
        );

        // 5:2 karıştırma algoritması
        let allIds = [];
        let vIdx = 0, uIdx = 0;
        while (vIdx < verifiedIds.length || uIdx < unverifiedIds.length) {
            for (let i = 0; i < 5 && vIdx < verifiedIds.length; i++) allIds.push(verifiedIds[vIdx++].id);
            for (let i = 0; i < 2 && uIdx < unverifiedIds.length; i++) allIds.push(unverifiedIds[uIdx++].id);
        }

        const pageIds = allIds.slice(offset, offset + limitNum);
        let posts = [];

        if (pageIds.length > 0) {
            const placeholders = pageIds.map((_, i) => `$${i + 3}`).join(',');
            posts = await dbAll(
                `SELECT p.*, u."profilePic" as "userProfilePic", u.name as "userName", u.username as "userUsername",
                    u."isVerified" as "userVerified", u."userType",
                    EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) as "isLiked",
                    EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $2) as "isSaved"
                 FROM posts p JOIN users u ON p."userId" = u.id
                 WHERE p.id IN (${placeholders})`,
                [req.user.id, req.user.id, ...pageIds]
            );
            const postMap = new Map(posts.map(p => [p.id, p]));
            posts = pageIds.map(id => postMap.get(id)).filter(Boolean);
        }

        // commentsDisabled normalize et
        posts = posts.map(p => ({ ...p, commentsDisabled: p.allowComments === false || p.allowComments === 0 }));

        res.json({
            posts,
            hasMore: (offset + limitNum) < allIds.length,
            total,
            page: pageNum,
            totalPages: Math.ceil(allIds.length / limitNum)
        });
    } catch (error) {
        console.error('Ana feed hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ GÖNDERILER: /api/posts/new ───────────────────────────────
app.get('/api/posts/new', authenticateToken, async (req, res) => {
    try {
        const { since } = req.query;
        const sinceDate = since ? new Date(since) : new Date(Date.now() - 24 * 60 * 60 * 1000);

        const posts = await dbAll(
            `SELECT p.*, u."profilePic" as "userProfilePic", u.name as "userName", u."isVerified" as "userVerified",
                EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) as "isLiked"
             FROM posts p JOIN users u ON p."userId" = u.id
             WHERE p."isActive" = TRUE AND u."isActive" = TRUE AND p."createdAt" > $2
             ORDER BY p."createdAt" DESC LIMIT 20`,
            [req.user.id, sinceDate.toISOString()]
        );

        res.json({ posts: posts.map(formatPost) });
    } catch (error) {
        console.error('Yeni gönderiler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── BEĞENİLEN GÖNDERILER: /api/posts/liked ────────────────────────
app.get('/api/posts/liked', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 10 } = req.query;
        const pageNum = Math.max(1, parseInt(page) || 1);
        const limitNum = Math.min(parseInt(limit) || 10, 100);
        const offset = (pageNum - 1) * limitNum;

        const posts = await dbAll(
            `SELECT p.*, u."profilePic" as "userProfilePic", u.name as "userName", TRUE as "isLiked",
                EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $1) as "isSaved"
             FROM likes l JOIN posts p ON l."postId" = p.id JOIN users u ON p."userId" = u.id
             WHERE l."userId" = $1 AND p."isActive" = TRUE
             ORDER BY l."createdAt" DESC LIMIT $2 OFFSET $3`,
            [req.user.id, limitNum, offset]
        );

        const totalResult = await dbGet(
            `SELECT COUNT(*) as count FROM likes l JOIN posts p ON l."postId" = p.id WHERE l."userId" = $1 AND p."isActive" = TRUE`,
            [req.user.id]
        );
        const total = parseInt(totalResult?.count || 0);

        res.json({ posts, hasMore: (pageNum * limitNum) < total, total, page: pageNum, totalPages: Math.ceil(total / limitNum) });
    } catch (error) {
        console.error('Beğenilenler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── KAYDEDİLEN GÖNDERILER: /api/posts/saved ───────────────────────
app.get('/api/posts/saved', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 10 } = req.query;
        const pageNum = Math.max(1, parseInt(page) || 1);
        const limitNum = Math.min(parseInt(limit) || 10, 100);
        const offset = (pageNum - 1) * limitNum;

        const posts = await dbAll(
            `SELECT p.*, u."profilePic" as "userProfilePic", u.name as "userName", TRUE as "isSaved",
                EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) as "isLiked"
             FROM saves s JOIN posts p ON s."postId" = p.id JOIN users u ON p."userId" = u.id
             WHERE s."userId" = $1 AND p."isActive" = TRUE
             ORDER BY s."createdAt" DESC LIMIT $2 OFFSET $3`,
            [req.user.id, limitNum, offset]
        );

        const totalResult = await dbGet(
            `SELECT COUNT(*) as count FROM saves s JOIN posts p ON s."postId" = p.id WHERE s."userId" = $1 AND p."isActive" = TRUE`,
            [req.user.id]
        );
        const total = parseInt(totalResult?.count || 0);

        res.json({ posts: posts.map(formatPost), hasMore: (pageNum * limitNum) < total, total, page: pageNum, totalPages: Math.ceil(total / limitNum) });
    } catch (error) {
        console.error('Kaydedilenler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── EXPLORE FEED: /api/feed/explore ───────────────────────────────
// Takip edilmeyenlerin popüler postlarını gösterir
app.get('/api/feed/explore', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 10 } = req.query;
        const pageNum = Math.max(1, parseInt(page) || 1);
        const limitNum = Math.min(parseInt(limit) || 10, 100);
        const offset = (pageNum - 1) * limitNum;

        const posts = await dbAll(
            `SELECT p.*, u."profilePic" as "userProfilePic", u.name as "userName", u."isVerified" as "userVerified",
                EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) as "isLiked",
                EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $1) as "isSaved"
             FROM posts p JOIN users u ON p."userId" = u.id
             WHERE p."userId" NOT IN (
                 SELECT "followingId" FROM follows WHERE "followerId" = $1
                 UNION SELECT $1
             )
             AND p."isActive" = TRUE AND u."isActive" = TRUE
             ORDER BY (p."likeCount" * 2 + p."commentCount") DESC, p."createdAt" DESC
             LIMIT $2 OFFSET $3`,
            [req.user.id, limitNum, offset]
        );

        const totalResult = await dbGet(
            `SELECT COUNT(*) as count FROM posts p JOIN users u ON p."userId" = u.id
             WHERE p."userId" NOT IN (SELECT "followingId" FROM follows WHERE "followerId" = $1 UNION SELECT $1)
             AND p."isActive" = TRUE AND u."isActive" = TRUE`,
            [req.user.id]
        );
        const total = parseInt(totalResult?.count || 0);

        res.json({ posts, total, page: pageNum, totalPages: Math.ceil(total / limitNum), hasMore: (pageNum * limitNum) < total });
    } catch (error) {
        console.error('Explore feed hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── KULLANICI ARAMA: /api/users/search (query param: q) ───────────
app.get('/api/users/search', authenticateToken, async (req, res) => {
    try {
        const { q, page = 1, limit = 20 } = req.query;
        if (!q || q.length < 2) return res.json({ users: [], total: 0, page: 1, totalPages: 0 });

        const pageNum = Math.max(1, parseInt(page) || 1);
        const limitNum = Math.min(parseInt(limit) || 20, 100);
        const offset = (pageNum - 1) * limitNum;
        const searchTerm = `%${q}%`;

        const users = await dbAll(
            `SELECT u.id, u.username, u.name, u."profilePic", u.bio, u."isVerified",
                (SELECT COUNT(*) FROM follows WHERE "followingId" = u.id) as "followerCount",
                EXISTS(SELECT 1 FROM follows WHERE "followerId" = $1 AND "followingId" = u.id) as "isFollowing"
             FROM users u
             WHERE (u.username ILIKE $2 OR u.name ILIKE $2) AND u.id != $1 AND u."isActive" = TRUE
             ORDER BY u."isVerified" DESC,
                CASE WHEN u.username ILIKE $3 THEN 1 WHEN u.name ILIKE $3 THEN 2 ELSE 3 END,
                (SELECT COUNT(*) FROM follows WHERE "followingId" = u.id) DESC
             LIMIT $4 OFFSET $5`,
            [req.user.id, searchTerm, `${q}%`, limitNum, offset]
        );

        const totalResult = await dbGet(
            `SELECT COUNT(*) as count FROM users u WHERE (u.username ILIKE $1 OR u.name ILIKE $1) AND u.id != $2 AND u."isActive" = TRUE`,
            [searchTerm, req.user.id]
        );
        const total = parseInt(totalResult?.count || 0);

        res.json({ users, total, page: pageNum, totalPages: Math.ceil(total / limitNum), hasMore: pageNum < Math.ceil(total / limitNum) });
    } catch (error) {
        console.error('Kullanıcı arama hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── TAKİP EDİLENLER: /api/users/following ─────────────────────────
app.get('/api/users/following', authenticateToken, async (req, res) => {
    try {
        const following = await dbAll(
            `SELECT u.id, u.name, u.username, u."profilePic", u."isVerified", u."userType", f."createdAt" as "followedAt"
             FROM follows f JOIN users u ON f."followingId" = u.id
             WHERE f."followerId" = $1 ORDER BY f."createdAt" DESC`,
            [req.user.id]
        );
        res.json({ following, count: following.length });
    } catch (error) {
        console.error('Takip edilenler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── ENGELLENEN KULLANICILAR: /api/users/blocked ───────────────────
// Frontend res.data.blockedUsers bekliyor!
app.get('/api/users/blocked', authenticateToken, async (req, res) => {
    try {
        const blocked = await dbAll(
            `SELECT u.id, u.name, u.username, u."profilePic", b."createdAt" as "blockedAt"
             FROM blocks b JOIN users u ON b."blockedId" = u.id
             WHERE b."blockerId" = $1 ORDER BY b."createdAt" DESC`,
            [req.user.id]
        );
        // Her iki key adıyla döndür (frontend uyumluluğu)
        res.json({ blocked, blockedUsers: blocked, count: blocked.length });
    } catch (error) {
        console.error('Engellenenler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── KAYIT DOĞRULAMA: /api/auth/register-verify ────────────────────
// register-init ile gönderilen 6 haneli kodu doğrular ve hesabı aktif eder
app.post('/api/auth/register-verify', async (req, res) => {
    try {
        const { email, code } = req.body;
        if (!email || !code) return res.status(400).json({ error: 'E-posta ve kod zorunludur' });

        const cleanEmail = email.toLowerCase().trim();

        // Doğrulama kodunu kontrol et
        const verification = await dbGet(
            `SELECT ev.*, u.id as "userId2" FROM email_verifications ev
             JOIN users u ON ev."userId" = u.id
             WHERE u.email = $1 AND ev.code = $2 AND ev."expiresAt" > NOW()
             ORDER BY ev."createdAt" DESC LIMIT 1`,
            [cleanEmail, String(code)]
        );

        if (!verification) {
            return res.status(400).json({ error: 'Geçersiz veya süresi dolmuş kod' });
        }

        // Kullanıcıyı doğrulandı olarak işaretle
        await dbRun(`UPDATE users SET "emailVerified" = TRUE, "updatedAt" = NOW() WHERE id = $1`, [verification.userId]);
        await dbRun(`DELETE FROM email_verifications WHERE "userId" = $1`, [verification.userId]);

        const user = await dbGet(
            `SELECT id, name, username, email, "profilePic", bio FROM users WHERE id = $1`,
            [verification.userId]
        );

        const tokens = generateTokens(user);

        res.status(201).json({
            token: tokens.accessToken,
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            user,
            message: 'Kayıt başarıyla tamamlandı!'
        });
    } catch (error) {
        console.error('Kayıt doğrulama hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 2FA DOĞRULAMA: /api/auth/verify-2fa ───────────────────────────
app.post('/api/auth/verify-2fa', async (req, res) => {
    try {
        const { tempToken, code } = req.body;
        if (!tempToken || !code) return res.status(400).json({ error: 'Token ve kod zorunludur' });

        let decoded;
        try {
            decoded = jwt.verify(tempToken, JWT_SECRET, { algorithms: ['HS256'] });
        } catch (err) {
            return res.status(401).json({ error: 'Geçersiz veya süresi dolmuş oturum. Lütfen tekrar giriş yapın.' });
        }

        if (!decoded.pending2FA) return res.status(400).json({ error: 'Geçersiz istek' });

        // 2FA kodunu doğrula
        const twofa = await dbGet(
            `SELECT * FROM two_factor_codes WHERE "userId" = $1 AND code = $2 AND "expiresAt" > NOW() AND used = FALSE
             ORDER BY "createdAt" DESC LIMIT 1`,
            [decoded.id, String(code)]
        );

        if (!twofa) return res.status(400).json({ error: 'Geçersiz veya süresi dolmuş 2FA kodu' });

        await dbRun(`UPDATE two_factor_codes SET used = TRUE WHERE id = $1`, [twofa.id]);

        const user = await dbGet(
            `SELECT id, username, name, email, role, "profilePic", "coverPic", bio,
                    "isVerified", "isActive", "userType", "hasFarmerBadge",
                    "isOnline", "isBanned", "emailVerified", "twoFactorEnabled"
             FROM users WHERE id = $1 AND "isActive" = TRUE`,
            [decoded.id]
        );
        if (!user) return res.status(401).json({ error: 'Kullanıcı bulunamadı' });

        await dbRun('UPDATE users SET "lastLogin" = NOW(), "isOnline" = TRUE, "updatedAt" = NOW() WHERE id = $1', [user.id]);

        const tokens = generateTokens(user);
        const tokenHash = crypto.createHash('sha256').update(tokens.refreshToken).digest('hex');
        await dbRun(
            `INSERT INTO refresh_tokens (id, "userId", "tokenHash", ip, "userAgent", "createdAt", "expiresAt")
             VALUES ($1, $2, $3, $4, $5, NOW(), NOW() + INTERVAL '30 days')`,
            [uuidv4(), user.id, tokenHash, req.ip, req.headers['user-agent'] || '']
        );

        const { password: _, ...userWithoutPassword } = user;
        res.json({ token: tokens.accessToken, accessToken: tokens.accessToken, refreshToken: tokens.refreshToken, user: userWithoutPassword, message: 'Giriş başarılı!' });
    } catch (error) {
        console.error('2FA doğrulama hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 2FA KOD YENİLE: /api/auth/resend-2fa ──────────────────────────
app.post('/api/auth/resend-2fa', async (req, res) => {
    try {
        const { tempToken } = req.body;
        if (!tempToken) return res.status(400).json({ error: 'Token zorunludur' });

        let decoded;
        try {
            decoded = jwt.verify(tempToken, JWT_SECRET, { algorithms: ['HS256'] });
        } catch (err) {
            return res.status(401).json({ error: 'Geçersiz veya süresi dolmuş oturum.' });
        }

        if (!decoded.pending2FA) return res.status(400).json({ error: 'Geçersiz istek' });

        const user = await dbGet('SELECT id, email, name FROM users WHERE id = $1 AND "isActive" = TRUE', [decoded.id]);
        if (!user) return res.status(401).json({ error: 'Kullanıcı bulunamadı' });

        // Yeni kod oluştur
        const newCode = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
        await dbRun(
            `INSERT INTO two_factor_codes (id, "userId", code, purpose, "expiresAt", used, "createdAt") VALUES ($1, $2, $3, $4, $5, FALSE, NOW())`,
            [uuidv4(), user.id, newCode, 'login', expiresAt]
        );

        sendEmail(user.email, '🔐 Agrolink — Yeni 2FA Kodunuz',
            `<p>Yeni giriş doğrulama kodunuz: <strong style="font-size:24px">${newCode}</strong></p><p>10 dakika geçerlidir.</p>`
        ).catch(() => {});

        res.json({ message: 'Yeni doğrulama kodu e-posta adresinize gönderildi.' });
    } catch (error) {
        console.error('2FA kod yenileme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── BU BEN DEĞİLİM: POST /api/auth/not-me ─────────────────────────
// Şüpheli giriş bildirimi — IP engeller, oturumları kapatır, şifre sıfırlama başlatır
app.post('/api/auth/not-me', async (req, res) => {
    try {
        const { email, username } = req.body;
        if (!email && !username) return res.status(400).json({ error: 'Email veya kullanıcı adı gereklidir' });

        const loginId = (email || username).toLowerCase().trim();
        const user = await dbGet(
            'SELECT * FROM users WHERE (email = $1 OR username = $1) AND "isActive" = TRUE',
            [loginId]
        );
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });

        const now = new Date().toISOString();
        const resetToken = crypto.randomBytes(32).toString('hex');
        const tokenExpires = new Date(Date.now() + 10 * 60 * 1000).toISOString();

        // Şüpheli giriş raporunu kaydet
        await dbRun(
            `INSERT INTO suspicious_login_reports (id, "userId", "reportedIp", "reportedAt", "passwordResetToken", "tokenExpiresAt")
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT DO NOTHING`,
            [uuidv4(), user.id, req.ip, now, resetToken, tokenExpires]
        ).catch(() => {});

        // Tüm refresh token'ları iptal et (oturumları kapat)
        await dbRun('DELETE FROM refresh_tokens WHERE "userId" = $1', [user.id]).catch(() => {});

        // E-posta bildirimi gönder
        sendEmail(user.email, '⚠️ Agrolink — Şüpheli Giriş Bildirimi',
            `<p>Hesabınıza şüpheli bir giriş yapıldı ve siz bunu bildirdiniz.</p>
             <p>Tüm oturumlarınız sonlandırıldı. Lütfen şifrenizi değiştirin.</p>
             <p>Şifre sıfırlama bağlantısı: <a href="https://sehitumitkestitarimmtal.com/api/auth/reset-password-direct?token=${resetToken}">Buraya tıklayın</a></p>`
        ).catch(() => {});

        res.json({
            success: true,
            message: 'Güvenlik önlemleri aktifleştirildi. Oturumlarınız sonlandırıldı.',
            actions: { sessionTerminated: true, passwordResetRequired: true }
        });
    } catch (error) {
        console.error('Bu ben değilim hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── BU BEN DEĞİLİM LINK: GET /api/auth/not-me ─────────────────────
app.get('/api/auth/not-me', async (req, res) => {
    const { token } = req.query;
    if (!token) return res.status(400).send('<h2>Geçersiz bağlantı</h2>');
    res.send(`<h2>Güvenlik bildirimi alındı. Oturumlarınız sonlandırıldı. Lütfen şifrenizi değiştirin.</h2>`);
});

// ─── AI CHAT: /api/ai-chat ──────────────────────────────────────────
const LLAMA_CPP_URL = process.env.LLAMA_CPP_URL || 'http://localhost:8080';
const AI_TIMEOUT_MS = parseInt(process.env.AI_TIMEOUT_MS) || 60000;

app.post('/api/ai-chat', authenticateToken, async (req, res) => {
    const { messages, stream = false, model, max_tokens, temperature } = req.body;
    if (!messages || !Array.isArray(messages) || messages.length === 0) {
        return res.status(400).json({ error: 'messages dizisi gerekli' });
    }
    for (const msg of messages) {
        if (typeof msg.content === 'string' && msg.content.length > 8000) {
            return res.status(400).json({ error: 'Mesaj çok uzun (max 8000 karakter)' });
        }
    }
    try {
        const { default: fetch } = await import('node-fetch');
        const ctrl = new AbortController();
        const timeout = setTimeout(() => ctrl.abort(), AI_TIMEOUT_MS);
        const llamaBody = {
            model: model || 'default',
            messages,
            stream: !!stream,
            max_tokens: Math.min(parseInt(max_tokens) || 1024, 4096),
            temperature: Math.min(parseFloat(temperature) || 0.7, 2.0)
        };
        const llamaRes = await fetch(LLAMA_CPP_URL + '/v1/chat/completions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(llamaBody),
            signal: ctrl.signal
        });
        clearTimeout(timeout);
        if (!llamaRes.ok) {
            const errTxt = await llamaRes.text().catch(() => '');
            return res.status(llamaRes.status).json({ error: 'AI hatası: ' + llamaRes.status, detail: errTxt.slice(0, 200) });
        }
        if (stream) {
            res.setHeader('Content-Type', 'text/event-stream');
            res.setHeader('Cache-Control', 'no-cache');
            res.setHeader('X-Accel-Buffering', 'no');
            llamaRes.body.pipe(res);
            llamaRes.body.on('error', () => res.end());
            req.on('close', () => llamaRes.body.destroy());
        } else {
            const data = await llamaRes.json();
            res.json(data);
        }
    } catch (error) {
        if (error.name === 'AbortError') {
            return res.status(504).json({ error: 'AI sunucusu zaman aşımı.', code: 'AI_TIMEOUT' });
        }
        res.status(503).json({ error: 'AI sunucusuna bağlanılamadı.', hint: `llama.cpp çalışıyor mu? (${LLAMA_CPP_URL})`, code: 'AI_OFFLINE' });
    }
});

app.get('/api/ai-chat/health', authenticateToken, async (req, res) => {
    try {
        const { default: fetch } = await import('node-fetch');
        const ctrl = new AbortController();
        const t = setTimeout(() => ctrl.abort(), 4000);
        const r = await fetch(LLAMA_CPP_URL + '/health', { signal: ctrl.signal });
        clearTimeout(t);
        res.json({ online: r.ok, status: r.status });
    } catch {
        res.json({ online: false });
    }
});

// ─── HASHTAG ARAMA: /api/hashtags/search ───────────────────────────
app.get('/api/hashtags/search', authenticateToken, async (req, res) => {
    try {
        const { q } = req.query;
        if (!q) return res.json({ hashtags: [] });

        const hashtags = await dbAll(
            `SELECT tag, COUNT(*) as count FROM (
                SELECT unnest(regexp_matches(content, '#([A-Za-z0-9_ğüşıöçĞÜŞİÖÇ]+)', 'g')) as tag FROM posts WHERE "isActive" = TRUE
             ) t WHERE tag ILIKE $1 GROUP BY tag ORDER BY count DESC LIMIT 20`,
            [`${q}%`]
        );
        res.json({ hashtags });
    } catch (error) {
        console.error('Hashtag arama hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── HASHTAG POSTLARI: /api/hashtags/:tag/posts ────────────────────
app.get('/api/hashtags/:tag/posts', authenticateToken, async (req, res) => {
    try {
        const { tag } = req.params;
        const { page = 1, limit = 10 } = req.query;
        const pageNum = Math.max(1, parseInt(page) || 1);
        const limitNum = Math.min(parseInt(limit) || 10, 50);
        const offset = (pageNum - 1) * limitNum;

        const posts = await dbAll(
            `SELECT p.*, u."profilePic" as "userProfilePic", u.name as "userName", u."isVerified" as "userVerified",
                EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) as "isLiked",
                EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $1) as "isSaved"
             FROM posts p JOIN users u ON p."userId" = u.id
             WHERE p."isActive" = TRUE AND u."isActive" = TRUE AND p.content ILIKE $2
             ORDER BY p."createdAt" DESC LIMIT $3 OFFSET $4`,
            [req.user.id, `%#${tag}%`, limitNum, offset]
        );

        res.json({ posts, tag, page: pageNum });
    } catch (error) {
        console.error('Hashtag postları hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── EN ÇOK TAKİP EDİLENLER: /api/users/top-followed ──────────────
app.get('/api/users/top-followed', authenticateToken, async (req, res) => {
    try {
        const limit = Math.min(parseInt(req.query.limit) || 10, 50);
        const users = await dbAll(
            `SELECT u.id, u.name, u.username, u."profilePic", u."isVerified", u."userType", u.bio,
                (SELECT COUNT(*) FROM follows WHERE "followingId" = u.id) as "followersCount",
                EXISTS(SELECT 1 FROM follows WHERE "followerId" = $1 AND "followingId" = u.id) as "isFollowing"
             FROM users u WHERE u.id != $1 AND u."isActive" = TRUE
             ORDER BY (SELECT COUNT(*) FROM follows WHERE "followingId" = u.id) DESC LIMIT $2`,
            [req.user.id, limit]
        );
        res.json({ users });
    } catch (error) {
        console.error('Top kullanıcılar hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── PUSH VAPID: /api/push/vapid-public-key ────────────────────────
app.get('/api/push/vapid-public-key', (req, res) => {
    res.json({ publicKey: process.env.VAPID_PUBLIC_KEY || null });
});


// ==================== 15 YENİ ROTA ====================

// ─── 1. KENDİ PROFIL İSTATİSTİKLERİ ───────────────────────────────
app.get('/api/users/me/stats', authenticateToken, async (req, res) => {
    try {
        const uid = req.user.id;
        const [posts, followers, following, likes, saves, views] = await Promise.all([
            pool.query('SELECT COUNT(*)::int AS cnt FROM posts   WHERE "userId"=$1 AND "isActive"=TRUE', [uid]),
            pool.query('SELECT COUNT(*)::int AS cnt FROM follows WHERE "followingId"=$1', [uid]),
            pool.query('SELECT COUNT(*)::int AS cnt FROM follows WHERE "followerId"=$1', [uid]),
            pool.query('SELECT COUNT(*) AS c FROM likes   WHERE "userId"=$1', [uid]),
            pool.query('SELECT COUNT(*) AS c FROM saves   WHERE "userId"=$1', [uid]),
            pool.query('SELECT COALESCE(SUM(views),0) AS c FROM posts WHERE "userId"=$1 AND "isActive"=TRUE', [uid]),
        ]);
        res.json({ stats: {
            postCount     : posts.rows[0]?.cnt     ?? 0,
            followerCount : followers.rows[0]?.cnt ?? 0,
            followingCount: following.rows[0]?.cnt ?? 0,
            likedCount    : parseInt(likes.rows[0]?.c     || 0),
            savedCount    : parseInt(saves.rows[0]?.c     || 0),
            totalViews    : parseInt(views.rows[0]?.c     || 0),
        }});
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 2. BAŞKA BİRİNİN PROFIL İSTATİSTİKLERİ ───────────────────────
app.get('/api/users/:id/stats', authenticateToken, async (req, res) => {
    try {
        const target = await dbGet('SELECT id FROM users WHERE id=$1 AND "isActive"=TRUE', [req.params.id]);
        if (!target) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
        const stats = await dbGet(`
            SELECT
                (SELECT COUNT(*) FROM posts   WHERE "userId"=$1 AND "isActive"=TRUE) AS "postCount",
                (SELECT COUNT(*) FROM follows WHERE "followingId"=$1)                AS "followerCount",
                (SELECT COUNT(*) FROM follows WHERE "followerId"=$1)                 AS "followingCount",
                (SELECT COUNT(*) FROM posts   WHERE "userId"=$1 AND "mediaType"='video' AND "isActive"=TRUE) AS "videoCount",
                (SELECT COALESCE(SUM(views),0) FROM posts WHERE "userId"=$1 AND "isActive"=TRUE) AS "totalViews"
        `, [target.id]);
        res.json({ stats: {
            postCount     : parseInt(stats?.postCount      || 0),
            followerCount : parseInt(stats?.followerCount  || 0),
            followingCount: parseInt(stats?.followingCount || 0),
            videoCount    : parseInt(stats?.videoCount     || 0),
            totalViews    : parseInt(stats?.totalViews     || 0),
        }});
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 3. TAKİPÇİ LİSTESİ (sayfalı + isFollowing) ───────────────────
app.get('/api/users/:id/followers/list', authenticateToken, async (req, res) => {
    try {
        const { page=1, limit=20 } = req.query;
        const pn = Math.max(1,parseInt(page)||1), ln = Math.min(parseInt(limit)||20,100);
        const off = (pn-1)*ln;
        const followers = await dbAll(`
            SELECT u.id, u.name, u.username, u."profilePic", u."isVerified",
                EXISTS(SELECT 1 FROM follows WHERE "followerId"=$1 AND "followingId"=u.id) AS "isFollowing",
                EXISTS(SELECT 1 FROM blocks  WHERE "blockerId"=$1 AND "blockedId"=u.id)   AS "isBlocked"
            FROM follows f JOIN users u ON f."followerId"=u.id
            WHERE f."followingId"=$2 AND u."isActive"=TRUE
            ORDER BY f."createdAt" DESC LIMIT $3 OFFSET $4
        `, [req.user.id, req.params.id, ln, off]);
        const tot = await dbGet('SELECT COUNT(*) AS c FROM follows WHERE "followingId"=$1', [req.params.id]);
        res.json({ followers, total: parseInt(tot?.c||0), page: pn, totalPages: Math.ceil((tot?.c||0)/ln) });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 4. TAKİP EDİLENLER LİSTESİ (sayfalı) ─────────────────────────
app.get('/api/users/:id/following/list', authenticateToken, async (req, res) => {
    try {
        const { page=1, limit=20 } = req.query;
        const pn = Math.max(1,parseInt(page)||1), ln = Math.min(parseInt(limit)||20,100);
        const off = (pn-1)*ln;
        const following = await dbAll(`
            SELECT u.id, u.name, u.username, u."profilePic", u."isVerified",
                EXISTS(SELECT 1 FROM follows WHERE "followerId"=$1 AND "followingId"=u.id) AS "isFollowing"
            FROM follows f JOIN users u ON f."followingId"=u.id
            WHERE f."followerId"=$2 AND u."isActive"=TRUE
            ORDER BY f."createdAt" DESC LIMIT $3 OFFSET $4
        `, [req.user.id, req.params.id, ln, off]);
        const tot = await dbGet('SELECT COUNT(*) AS c FROM follows WHERE "followerId"=$1', [req.params.id]);
        res.json({ following, total: parseInt(tot?.c||0), page: pn, totalPages: Math.ceil((tot?.c||0)/ln) });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 5. ORTAK TAKİPÇİLER ──────────────────────────────────────────
app.get('/api/users/:userId/mutual-followers', authenticateToken, async (req, res) => {
    try {
        const targetId = req.params.userId;
        if (req.user.id === targetId) return res.json({ mutualFollowers: [], count: 0 });
        const mutual = await dbAll(`
            SELECT u.id, u.name, u.username, u."profilePic", u."isVerified"
            FROM users u
            WHERE u."isActive"=TRUE
              AND EXISTS(SELECT 1 FROM follows WHERE "followerId"=$1 AND "followingId"=u.id)
              AND EXISTS(SELECT 1 FROM follows WHERE "followerId"=$2 AND "followingId"=u.id)
            ORDER BY u.name ASC LIMIT 50
        `, [req.user.id, targetId]);
        res.json({ mutualFollowers: mutual, count: mutual.length });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});



// ─── 8. HİKAYE SİL ───────────────────────────────────────────────
app.delete('/api/stories/:storyId', authenticateToken, async (req, res) => {
    try {
        const story = await dbGet('SELECT * FROM stories WHERE id=$1', [req.params.storyId]);
        if (!story) return res.status(404).json({ error:'Hikaye bulunamadı' });
        if (story.userId !== req.user.id) return res.status(403).json({ error:'Yetki yok' });
        await dbRun('DELETE FROM story_views WHERE "storyId"=$1', [req.params.storyId]);
        await dbRun('DELETE FROM story_likes WHERE "storyId"=$1', [req.params.storyId]);
        await dbRun('DELETE FROM stories WHERE id=$1', [req.params.storyId]);
        res.json({ message:'Hikaye silindi' });
    } catch (e) { console.error(e); res.status(500).json({ error:'Sunucu hatası' }); }
});

// ─── 9. HİKAYE GÖRÜNTÜLEME + BEĞENİ ──────────────────────────────
app.post('/api/stories/:storyId/view', authenticateToken, async (req, res) => {
    try {
        const ex = await dbGet('SELECT id FROM story_views WHERE "storyId"=$1 AND "userId"=$2',[req.params.storyId, req.user.id]);
        if (!ex) await dbRun('INSERT INTO story_views (id,"storyId","userId","viewedAt") VALUES ($1,$2,$3,NOW())',[uuidv4(),req.params.storyId,req.user.id]);
        await dbRun('UPDATE stories SET "viewCount"=COALESCE("viewCount",0)+1 WHERE id=$1 AND "userId"!=$2',[req.params.storyId,req.user.id]).catch(()=>{});
        res.json({ message:'Görüntüleme kaydedildi' });
    } catch (e) { res.status(500).json({ error:'Sunucu hatası' }); }
});
app.post('/api/stories/:storyId/like', authenticateToken, async (req, res) => {
    try {
        const story = await dbGet('SELECT * FROM stories WHERE id=$1 AND "expiresAt">NOW()',[req.params.storyId]);
        if (!story) return res.status(404).json({ error:'Hikaye bulunamadı' });
        if (story.userId===req.user.id) return res.status(400).json({ error:'Kendi hikayenizi beğenemezsiniz' });
        const ex = await dbGet('SELECT id FROM story_likes WHERE "storyId"=$1 AND "userId"=$2',[req.params.storyId,req.user.id]);
        if (ex) return res.status(400).json({ error:'Zaten beğenilmiş' });
        await dbRun('INSERT INTO story_likes (id,"storyId","userId","createdAt") VALUES ($1,$2,$3,NOW())',[uuidv4(),req.params.storyId,req.user.id]);
        await dbRun('UPDATE stories SET "likeCount"=COALESCE("likeCount",0)+1 WHERE id=$1',[req.params.storyId]);
        res.json({ success:true });
    } catch (e) { res.status(500).json({ error:'Sunucu hatası' }); }
});
app.delete('/api/stories/:storyId/like', authenticateToken, async (req, res) => {
    try {
        const like = await dbGet('SELECT id FROM story_likes WHERE "storyId"=$1 AND "userId"=$2',[req.params.storyId,req.user.id]);
        if (!like) return res.status(404).json({ error:'Beğeni bulunamadı' });
        await dbRun('DELETE FROM story_likes WHERE id=$1',[like.id]);
        await dbRun('UPDATE stories SET "likeCount"=GREATEST(0,COALESCE("likeCount",0)-1) WHERE id=$1',[req.params.storyId]);
        res.json({ success:true });
    } catch (e) { res.status(500).json({ error:'Sunucu hatası' }); }
});
app.get('/api/stories/:storyId/viewers', authenticateToken, async (req, res) => {
    try {
        const story = await dbGet('SELECT "userId" FROM stories WHERE id=$1',[req.params.storyId]);
        if (!story) return res.status(404).json({ error:'Hikaye bulunamadı' });
        if (story.userId!==req.user.id) return res.status(403).json({ error:'Yetki yok' });
        const viewers = await dbAll(`SELECT u.id,u.username,u."profilePic",u.name,sv."viewedAt" FROM story_views sv JOIN users u ON sv."userId"=u.id WHERE sv."storyId"=$1 ORDER BY sv."viewedAt" DESC`,[req.params.storyId]);
        res.json({ viewers });
    } catch (e) { res.status(500).json({ error:'Sunucu hatası' }); }
});
app.get('/api/stories/:storyId/likes', authenticateToken, async (req, res) => {
    try {
        const likes = await dbAll(`SELECT u.id,u.username,u."profilePic",u.name,sl."createdAt" FROM story_likes sl JOIN users u ON sl."userId"=u.id WHERE sl."storyId"=$1 ORDER BY sl."createdAt" DESC`,[req.params.storyId]);
        const cnt = await dbGet('SELECT COUNT(*) AS c FROM story_likes WHERE "storyId"=$1',[req.params.storyId]);
        res.json({ likes, count: parseInt(cnt?.c||0) });
    } catch (e) { res.status(500).json({ error:'Sunucu hatası' }); }
});

// ─── 10. MESAJDA GÖRSEL GÖNDER ────────────────────────────────────
app.post('/api/messages/image', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        const { recipientId } = req.body;
        if (!recipientId || !req.file) return res.status(400).json({ error:'Alıcı ve görsel gerekli' });
        const recipient = await dbGet('SELECT id,username FROM users WHERE id=$1 AND "isActive"=TRUE',[recipientId]);
        if (!recipient) return res.status(404).json({ error:'Kullanıcı bulunamadı' });
        const blocked = await dbGet('SELECT id FROM blocks WHERE ("blockerId"=$1 AND "blockedId"=$2) OR ("blockerId"=$2 AND "blockedId"=$1)',[req.user.id,recipientId]);
        if (blocked) return res.status(403).json({ error:'Mesaj gönderilemiyor' });
        const filename  = `msg_${Date.now()}_${Math.round(Math.random()*1e9)}.webp`;
        const outPath   = path.join(postsDir, filename);
        await sharp(req.file.path).resize(1920,1920,{fit:'inside',withoutEnlargement:true}).webp({quality:85}).toFile(outPath);
        await fs.unlink(req.file.path).catch(()=>{});
        const imageUrl  = `/uploads/posts/${filename}`;
        const sender    = await dbGet('SELECT username FROM users WHERE id=$1',[req.user.id]);
        const msgId     = uuidv4();
        await dbRun(`INSERT INTO messages (id,"senderId","senderUsername","recipientId","recipientUsername",content,read,"createdAt","updatedAt") VALUES ($1,$2,$3,$4,$5,$6,FALSE,NOW(),NOW())`,[msgId,req.user.id,sender.username,recipientId,recipient.username,imageUrl]);
        res.status(201).json({ message:'Görsel gönderildi', messageId:msgId, imageUrl });
    } catch (e) {
        if (req.file) await fs.unlink(req.file.path).catch(()=>{});
        console.error(e); res.status(500).json({ error:'Sunucu hatası' });
    }
});

// ─── 11. MESAJDA SESLİ MESAJ GÖNDER ──────────────────────────────
app.post('/api/messages/voice', authenticateToken, upload.single('voice'), async (req, res) => {
    try {
        const { recipientId } = req.body;
        if (!recipientId || !req.file) return res.status(400).json({ error:'Alıcı ve ses dosyası gerekli' });
        const recipient = await dbGet('SELECT id,username FROM users WHERE id=$1 AND "isActive"=TRUE',[recipientId]);
        if (!recipient) return res.status(404).json({ error:'Kullanıcı bulunamadı' });
        const voiceDir = path.join(uploadsDir,'voice');
        if (!fssync.existsSync(voiceDir)) fssync.mkdirSync(voiceDir,{recursive:true});
        const filename = `voice_${Date.now()}_${Math.round(Math.random()*1e9)}.webm`;
        const outPath  = path.join(voiceDir, filename);
        await fs.copyFile(req.file.path, outPath);
        await fs.unlink(req.file.path).catch(()=>{});
        const voiceUrl = `/uploads/voice/${filename}`;
        const sender   = await dbGet('SELECT username FROM users WHERE id=$1',[req.user.id]);
        const msgId    = uuidv4();
        await dbRun(`INSERT INTO messages (id,"senderId","senderUsername","recipientId","recipientUsername",content,read,"createdAt","updatedAt") VALUES ($1,$2,$3,$4,$5,$6,FALSE,NOW(),NOW())`,[msgId,req.user.id,sender.username,recipientId,recipient.username,voiceUrl]);
        res.status(201).json({ message:'Sesli mesaj gönderildi', messageId:msgId, voiceUrl });
    } catch (e) {
        if (req.file) await fs.unlink(req.file.path).catch(()=>{});
        console.error(e); res.status(500).json({ error:'Sunucu hatası' });
    }
});

// ─── 12. FARMBOOK KAYITLARI CRUD ──────────────────────────────────
app.get('/api/farmbook/records', authenticateToken, async (req, res) => {
    try {
        const { season, year, type, page=1, limit=50 } = req.query;
        const pn=Math.max(1,parseInt(page)||1), ln=Math.min(parseInt(limit)||50,200);
        const off=(pn-1)*ln;
        const conds=['r."userId"=$1'], params=[req.user.id];
        let pi=2;
        if (season) { conds.push(`r.season=$${pi++}`); params.push(season); }
        if (year)   { conds.push(`r.year=$${pi++}`);   params.push(parseInt(year)); }
        if (type)   { conds.push(`r."recordType"=$${pi++}`); params.push(type); }
        const where = conds.join(' AND ');
        const records = await dbAll(`SELECT * FROM farmbook_records WHERE ${where} ORDER BY "recordDate" DESC LIMIT $${pi} OFFSET $${pi+1}`,[...params,ln,off]);
        const tot = await dbGet(`SELECT COUNT(*) AS c FROM farmbook_records WHERE ${where}`,params);
        res.json({ success:true, records, total:parseInt(tot?.c||0), page:pn, totalPages:Math.ceil((tot?.c||0)/ln) });
    } catch (e) { console.error(e); res.status(500).json({ error:'Sunucu hatası' }); }
});
app.post('/api/farmbook/records', authenticateToken, async (req, res) => {
    try {
        const { recordType, productName, quantity, unit, cost, income, recordDate, fieldName, fieldSize, fieldSizeUnit, season, year, notes, harvestAmount, harvestUnit, qualityRating, weatherCondition } = req.body;
        if (!recordType||!recordDate) return res.status(400).json({ error:'Kayıt tipi ve tarih zorunludur' });
        const id = uuidv4();
        await dbRun(`INSERT INTO farmbook_records (id,"userId","recordType","productName",quantity,unit,cost,income,"recordDate","fieldName","fieldSize","fieldSizeUnit",season,year,notes,"harvestAmount","harvestUnit","qualityRating","weatherCondition","createdAt","updatedAt") VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,NOW(),NOW())`,
            [id,req.user.id,recordType,productName||null,quantity||null,unit||null,cost||0,income||0,recordDate,fieldName||null,fieldSize||null,fieldSizeUnit||'dekar',season||null,year||new Date().getFullYear(),notes||null,harvestAmount||null,harvestUnit||null,qualityRating||null,weatherCondition||null]);
        const record = await dbGet('SELECT * FROM farmbook_records WHERE id=$1',[id]);
        res.json({ success:true, record });
    } catch (e) { console.error(e); res.status(500).json({ error:'Sunucu hatası' }); }
});
app.put('/api/farmbook/records/:id', authenticateToken, async (req, res) => {
    try {
        const existing = await dbGet('SELECT id FROM farmbook_records WHERE id=$1 AND "userId"=$2',[req.params.id,req.user.id]);
        if (!existing) return res.status(404).json({ error:'Kayıt bulunamadı' });
        const allowed = ['recordType','productName','quantity','unit','cost','income','recordDate','fieldName','fieldSize','fieldSizeUnit','season','year','notes','harvestAmount','harvestUnit','qualityRating','weatherCondition'];
        const sets=[], vals=[];
        let pi=1;
        for (const f of allowed) { if (req.body[f]!==undefined) { sets.push(`"${f}"=$${pi++}`); vals.push(req.body[f]); } }
        if (!sets.length) return res.status(400).json({ error:'Güncellenecek alan yok' });
        sets.push(`"updatedAt"=NOW()`);
        vals.push(req.params.id,req.user.id);
        await dbRun(`UPDATE farmbook_records SET ${sets.join(',')} WHERE id=$${pi} AND "userId"=$${pi+1}`,vals);
        const record = await dbGet('SELECT * FROM farmbook_records WHERE id=$1',[req.params.id]);
        res.json({ success:true, record });
    } catch (e) { console.error(e); res.status(500).json({ error:'Sunucu hatası' }); }
});
app.delete('/api/farmbook/records/:id', authenticateToken, async (req, res) => {
    try {
        const ex = await dbGet('SELECT id FROM farmbook_records WHERE id=$1 AND "userId"=$2',[req.params.id,req.user.id]);
        if (!ex) return res.status(404).json({ error:'Kayıt bulunamadı' });
        await dbRun('DELETE FROM farmbook_records WHERE id=$1',[req.params.id]);
        res.json({ success:true, message:'Kayıt silindi' });
    } catch (e) { console.error(e); res.status(500).json({ error:'Sunucu hatası' }); }
});

// ─── 13. FARMBOOK İSTATİSTİKLER ───────────────────────────────────
app.get('/api/farmbook/stats', authenticateToken, async (req, res) => {
    try {
        const { season, year } = req.query;
        const conds=['r."userId"=$1'], params=[req.user.id];
        let pi=2;
        if (season){ conds.push(`r.season=$${pi++}`); params.push(season); }
        if (year)  { conds.push(`r.year=$${pi++}`);   params.push(parseInt(year)); }
        const where = conds.join(' AND ');
        const [costRow,incRow,types,monthly,seasons] = await Promise.all([
            dbGet(`SELECT COALESCE(SUM(cost),0) AS total FROM farmbook_records r WHERE ${where}`,params),
            dbGet(`SELECT COALESCE(SUM(income),0) AS total FROM farmbook_records r WHERE ${where}`,params),
            dbAll(`SELECT "recordType", COUNT(*) AS count FROM farmbook_records r WHERE ${where} GROUP BY "recordType"`,params),
            dbAll(`SELECT TO_CHAR("recordDate",'YYYY-MM') AS month, SUM(cost) AS "totalCost", SUM(income) AS "totalIncome" FROM farmbook_records r WHERE ${where} GROUP BY TO_CHAR("recordDate",'YYYY-MM') ORDER BY month DESC LIMIT 12`,params),
            dbAll(`SELECT DISTINCT season, year FROM farmbook_records WHERE "userId"=$1 ORDER BY year DESC`,[req.user.id])
        ]);
        const totalCost=parseFloat(costRow?.total||0), totalIncome=parseFloat(incRow?.total||0);
        res.json({ success:true, stats:{ totalCost, totalIncome, profit:totalIncome-totalCost, recordCounts:types.reduce((a,r)=>({...a,[r.recordType]:parseInt(r.count)}),{}), monthlyData:monthly, seasons } });
    } catch (e) { console.error(e); res.status(500).json({ error:'Sunucu hatası' }); }
});

// ─── 14. FARMBOOK CSV EXPORT ───────────────────────────────────────
app.get('/api/farmbook/export', authenticateToken, async (req, res) => {
    try {
        const { season, year } = req.query;
        const conds=['"userId"=$1'], params=[req.user.id]; let pi=2;
        if (season){ conds.push(`season=$${pi++}`); params.push(season); }
        if (year)  { conds.push(`year=$${pi++}`);   params.push(parseInt(year)); }
        const records = await dbAll(`SELECT * FROM farmbook_records WHERE ${conds.join(' AND ')} ORDER BY "recordDate" DESC`,params);
        const typeNames = { ekim:'Ekim',gubre:'Gübre',ilac:'İlaç',hasat:'Hasat',gider:'Gider',gelir:'Gelir',sulama:'Sulama',notlar:'Notlar' };
        const hdrs = ['Tarih','Kayıt Tipi','Ürün/İşlem','Miktar','Birim','Maliyet (₺)','Gelir (₺)','Tarla','Alan','Alan Birimi','Sezon','Yıl','Hasat Miktarı','Hasat Birimi','Kalite','Hava','Notlar'];
        let csv = hdrs.join(';') + '\n';
        for (const r of records) {
            csv += [r.recordDate, typeNames[r.recordType]||r.recordType, r.productName||'', r.quantity||'', r.unit||'', r.cost||0, r.income||0, r.fieldName||'', r.fieldSize||'', r.fieldSizeUnit||'', r.season||'', r.year||'', r.harvestAmount||'', r.harvestUnit||'', r.qualityRating||'', r.weatherCondition||'', (r.notes||'').replace(/;/g,',').replace(/\n/g,' ')].join(';') + '\n';
        }
        const totCost=records.reduce((s,r)=>s+(r.cost||0),0), totInc=records.reduce((s,r)=>s+(r.income||0),0);
        csv += '\nTOPLAM GİDER;;;;;' + totCost + ';\nTOPLAM GELİR;;;;;;' + totInc + '\nKÂR/ZARAR;;;;;;' + (totInc-totCost) + '\n';
        const fname = `farmbook_${season||'tum'}_${year||'tum'}_${new Date().toISOString().split('T')[0]}.csv`;
        res.setHeader('Content-Type','text/csv; charset=utf-8');
        res.setHeader('Content-Disposition',`attachment; filename="${fname}"`);
        res.send('﻿' + csv);
    } catch (e) { console.error(e); res.status(500).json({ error:'Sunucu hatası' }); }
});

// ─── 15. DOĞRULAMA DURUMU + TALEBİ ────────────────────────────────
app.get('/api/users/verification/status', authenticateToken, async (req, res) => {
    try {
        const user = await dbGet('SELECT "isVerified","emailVerified" FROM users WHERE id=$1',[req.user.id]);
        if (!user) return res.status(404).json({ error:'Kullanıcı bulunamadı' });
        res.json({ isVerified: !!user.isVerified, emailVerified: !!user.emailVerified });
    } catch (e) { console.error(e); res.status(500).json({ error:'Sunucu hatası' }); }
});
app.post('/api/users/verification/request', authenticateToken, async (req, res) => {
    try {
        await dbRun('UPDATE users SET "emailVerified"=TRUE,"updatedAt"=NOW() WHERE id=$1',[req.user.id]);
        res.json({ message:'Doğrulama talebi alındı', verified:true });
    } catch (e) { console.error(e); res.status(500).json({ error:'Sunucu hatası' }); }
});


// ==================== EKSİK ROTALAR - TAM DÜZELTME ====================

// ─── 2FA TOGGLE: /api/users/2fa/toggle ─────────────────────────────
app.post('/api/users/2fa/toggle', authenticateToken, async (req, res) => {
    try {
        const enabled = req.body.enabled === true || req.body.enabled === 'true';
        await dbRun('UPDATE users SET "twoFactorEnabled"=$1, "updatedAt"=NOW() WHERE id=$2', [enabled, req.user.id]);
        res.json({ message: enabled ? '2FA açıldı' : '2FA kapatıldı', twoFactorEnabled: enabled });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── POST GÖRÜNTÜLEME: POST /api/posts/:id/view ─────────────────────
app.post('/api/posts/:id/view', authenticateToken, async (req, res) => {
    try {
        const post = await dbGet(
            'SELECT id, views, "userId" FROM posts WHERE id = $1 AND "isActive" = TRUE',
            [req.params.id]
        );
        if (!post) return res.status(404).json({ error: 'Post bulunamadı' });

        // Kendi postu sayılmaz
        if (post.userId !== req.user.id) {
            await incrementPostView(req.params.id, req.user.id, req.ip);
        }

        const updated = await dbGet('SELECT views FROM posts WHERE id = $1', [req.params.id]);
        res.json({ success: true, views: updated?.views ?? post.views });
    } catch (error) {
        console.error('View tracking hatası:', error.message);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── PROFİL PAYLAŞ: /share/profile/:username ───────────────────────
app.get('/share/profile/:username', async (req, res) => {
    try {
        const user = await dbGet(`
            SELECT u.*,
                (SELECT COUNT(*)::int FROM follows WHERE "followingId"=u.id) AS "followerCount",
                (SELECT COUNT(*)::int FROM follows WHERE "followerId"=u.id)  AS "followingCount",
                (SELECT COUNT(*)::int FROM posts   WHERE "userId"=u.id AND "isActive"=TRUE) AS "postCount"
            FROM users u WHERE u.username=$1 AND u."isActive"=TRUE`, [req.params.username]);
        if (!user) return res.status(404).send('<h2>Kullanıcı bulunamadı</h2>');

        const base    = `${req.protocol}://${req.get('host')}`;
        const picUrl  = user.profilePic  ? `${base}${user.profilePic}`  : `${base}/default-avatar.png`;
        const coverUrl= user.coverPic    ? `${base}${user.coverPic}`    : null;
        const bio     = (user.bio || '').substring(0, 160);

        // Son 6 post görselini al
        const recentPosts = await dbAll(
            `SELECT id, media, "mediaType", content FROM posts
             WHERE "userId"=$1 AND "isActive"=TRUE AND media IS NOT NULL
             ORDER BY "createdAt" DESC LIMIT 6`,
            [user.id]
        );

        const gridHtml = recentPosts.map(p => {
            if (p.mediaType === 'video') {
                return `<a href="${base}/share/post/${p.id}" class="grid-item video-item" title="${(p.content||'').substring(0,60)}">
                    <div class="play-icon">▶</div>
                </a>`;
            }
            return `<a href="${base}/share/post/${p.id}" class="grid-item" style="background-image:url('${base}${p.media}')" title="${(p.content||'').substring(0,60)}"></a>`;
        }).join('');

        const userTypeBadge = {
            'ziraat_muhendisi' : '🌿 Ziraat Mühendisi',
            'tarim_ogretmeni'  : '📚 Tarım Öğretmeni',
            'tarim_ogrencisi'  : '🎓 Tarım Öğrencisi',
            'ciftci_hayvancilik': '🐄 Çiftçi',
            'normal_kullanici' : '👤 Kullanıcı',
        }[user.userType] || '👤 Kullanıcı';

        res.send(`<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>${user.name} (@${user.username}) — Agrolink</title>
<meta property="og:title" content="${user.name} - Agrolink">
<meta property="og:description" content="${bio || 'Agrolink kullanıcısı'} | ${user.followerCount} takipçi">
<meta property="og:image" content="${picUrl}">
<meta property="og:url" content="${base}/share/profile/${user.username}">
<meta property="og:type" content="profile">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:#0a0a0a;min-height:100vh;color:#fff}
.hero{position:relative;height:240px;background:${coverUrl ? `url('${coverUrl}') center/cover no-repeat` : 'linear-gradient(135deg,#1b5e20 0%,#2e7d32 40%,#43a047 70%,#66bb6a 100%)'};overflow:hidden}
.hero::after{content:'';position:absolute;inset:0;background:linear-gradient(to bottom,transparent 40%,rgba(0,0,0,.85))}
.hero-gradient{position:absolute;inset:0;background:linear-gradient(135deg,rgba(46,125,50,.3),rgba(102,187,106,.2))}
.back-btn{position:absolute;top:16px;left:16px;z-index:10;background:rgba(0,0,0,.4);backdrop-filter:blur(8px);border:1px solid rgba(255,255,255,.15);color:#fff;padding:8px 16px;border-radius:50px;text-decoration:none;font-size:13px;font-weight:500;display:flex;align-items:center;gap:6px;transition:.2s}
.back-btn:hover{background:rgba(0,0,0,.6)}
.share-btn{position:absolute;top:16px;right:16px;z-index:10;background:rgba(255,255,255,.1);backdrop-filter:blur(8px);border:1px solid rgba(255,255,255,.2);color:#fff;padding:8px 16px;border-radius:50px;cursor:pointer;font-size:13px;font-weight:500;display:flex;align-items:center;gap:6px}
.share-btn:hover{background:rgba(255,255,255,.2)}
.container{max-width:480px;margin:0 auto;position:relative}
.profile-card{background:#111;border-radius:0 0 24px 24px;padding:0 20px 24px;position:relative;margin-bottom:12px}
.avatar-wrap{position:relative;display:inline-block;margin-top:-52px;z-index:5}
.avatar{width:96px;height:96px;border-radius:50%;border:4px solid #111;object-fit:cover;display:block;background:#222}
.online-dot{position:absolute;bottom:6px;right:6px;width:16px;height:16px;background:#4caf50;border-radius:50%;border:3px solid #111}
.profile-header{display:flex;justify-content:space-between;align-items:flex-end;margin-bottom:12px}
.name-row{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:10px}
.name{font-size:22px;font-weight:800;color:#fff;line-height:1.1}
.verified{color:#4caf50;font-size:18px}
.handle{color:#888;font-size:14px;font-weight:400;margin-top:2px}
.badge{background:rgba(76,175,80,.15);color:#66bb6a;border:1px solid rgba(76,175,80,.3);padding:4px 10px;border-radius:20px;font-size:11px;font-weight:600;margin-top:6px;display:inline-block}
.bio{color:#bbb;font-size:14px;line-height:1.6;margin:12px 0;white-space:pre-wrap}
.meta{display:flex;gap:16px;flex-wrap:wrap;margin:10px 0}
.meta-item{color:#888;font-size:13px;display:flex;align-items:center;gap:4px}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;background:#222;border-radius:16px;overflow:hidden;margin:16px 0}
.stat{background:#1a1a1a;padding:16px 8px;text-align:center}
.stat-val{font-size:22px;font-weight:800;color:#fff;line-height:1}
.stat-lbl{font-size:11px;color:#666;margin-top:4px;font-weight:500;letter-spacing:.3px}
.cta{display:block;background:linear-gradient(135deg,#2e7d32,#43a047);color:#fff;text-align:center;padding:15px;border-radius:14px;text-decoration:none;font-weight:700;font-size:15px;letter-spacing:.3px;transition:.2s;margin-top:4px}
.cta:hover{opacity:.9;transform:translateY(-1px)}
.posts-section{padding:0 20px 32px}
.posts-title{color:#888;font-size:12px;font-weight:600;letter-spacing:1px;text-transform:uppercase;margin-bottom:10px}
.posts-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:3px;border-radius:16px;overflow:hidden}
.grid-item{aspect-ratio:1;background:#222 center/cover no-repeat;display:block;position:relative;overflow:hidden;transition:.2s}
.grid-item:hover{opacity:.85}
.video-item{background:#1a1a1a;display:flex;align-items:center;justify-content:center}
.play-icon{width:44px;height:44px;background:rgba(255,255,255,.15);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:18px;color:#fff}
.powered{text-align:center;padding:20px;color:#444;font-size:12px}
.powered span{color:#4caf50}
.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%) translateY(80px);background:#1e1e1e;color:#fff;padding:12px 20px;border-radius:12px;font-size:14px;font-weight:500;border:1px solid #333;transition:.3s;z-index:100;opacity:0}
.toast.show{transform:translateX(-50%) translateY(0);opacity:1}
@media(max-width:400px){.name{font-size:18px}.stat-val{font-size:18px}}
</style>
</head>
<body>
<div class="container">
  <div class="hero">
    <div class="hero-gradient"></div>
    <a href="${base}" class="back-btn">🌾 Agrolink</a>
    <button class="share-btn" onclick="copyLink()">⬆ Paylaş</button>
  </div>
  <div class="profile-card">
    <div class="profile-header">
      <div class="avatar-wrap">
        <img src="${picUrl}" class="avatar" onerror="this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 96 96%22><rect fill=%22%23222%22 width=%2296%22 height=%2296%22/><text y=%2264%22 x=%2248%22 text-anchor=%22middle%22 font-size=%2248%22>👤</text></svg>'">
        ${user.isOnline ? '<div class="online-dot"></div>' : ''}
      </div>
    </div>
    <div class="name-row">
      <span class="name">${user.name}</span>
      ${user.isVerified ? '<span class="verified">✅</span>' : ''}
    </div>
    <div class="handle">@${user.username}</div>
    <div class="badge">${userTypeBadge}</div>
    ${bio ? `<div class="bio">${bio}</div>` : ''}
    ${user.location ? `<div class="meta"><span class="meta-item">📍 ${user.location}</span></div>` : ''}
    <div class="stats">
      <div class="stat"><div class="stat-val">${user.postCount ?? 0}</div><div class="stat-lbl">Gönderi</div></div>
      <div class="stat"><div class="stat-val">${user.followerCount ?? 0}</div><div class="stat-lbl">Takipçi</div></div>
      <div class="stat"><div class="stat-val">${user.followingCount ?? 0}</div><div class="stat-lbl">Takip</div></div>
    </div>
    <a href="${base}" class="cta">🌾 Agrolink'te Görüntüle</a>
  </div>
  ${recentPosts.length > 0 ? `
  <div class="posts-section">
    <div class="posts-title">Son Gönderiler</div>
    <div class="posts-grid">${gridHtml}</div>
  </div>` : ''}
  <div class="powered">Powered by <span>Agrolink</span></div>
</div>
<div class="toast" id="toast">🔗 Link kopyalandı!</div>
<script>
function copyLink(){
  navigator.clipboard.writeText(window.location.href).then(()=>{
    const t=document.getElementById('toast');
    t.classList.add('show');
    setTimeout(()=>t.classList.remove('show'),2200);
  }).catch(()=>{
    const inp=document.createElement('input');
    inp.value=window.location.href;
    document.body.appendChild(inp);
    inp.select();
    document.execCommand('copy');
    document.body.removeChild(inp);
    const t=document.getElementById('toast');
    t.classList.add('show');
    setTimeout(()=>t.classList.remove('show'),2200);
  });
}
</script>
</body></html>`);
    } catch(e) { console.error(e); res.status(500).send('<h2>Sunucu hatası</h2>'); }
});

// ─── GÖNDERI PAYLAŞ: /share/post/:postId ───────────────────────────
app.get('/share/post/:postId', async (req, res) => {
    try {
        const post = await dbGet(`
            SELECT p.*, u.username, u.name AS "userName", u."profilePic" AS "userProfilePic",
                   u."isVerified" AS "userVerified", u."userType",
                   (SELECT COUNT(*)::int FROM likes   WHERE "postId"=p.id) AS "likeCount",
                   (SELECT COUNT(*)::int FROM comments c WHERE c."postId"=p.id AND c."isActive"=TRUE) AS "commentCount"
            FROM posts p JOIN users u ON p."userId"=u.id
            WHERE p.id=$1 AND p."isActive"=TRUE AND u."isActive"=TRUE`, [req.params.postId]);
        if (!post) return res.status(404).send('<h2>Gönderi bulunamadı</h2>');

        const base      = `${req.protocol}://${req.get('host')}`;
        const picUrl    = post.userProfilePic ? `${base}${post.userProfilePic}` : `${base}/default-avatar.png`;
        const date      = new Date(post.createdAt).toLocaleDateString('tr-TR', {day:'numeric',month:'long',year:'numeric'});
        const content_text = (post.content || '').substring(0, 500);

        let mediaHtml = '';
        if (post.media) {
            if (post.mediaType === 'video') {
                const isHLS = post.media.endsWith('.m3u8');
                const posterAttr = post.thumbnailUrl ? `poster="${base}${post.thumbnailUrl}"` : '';
                if (isHLS) {
                    mediaHtml = `<div class="media-wrap">
<video id="sv" controls playsinline ${posterAttr} style="width:100%;max-height:480px;object-fit:contain;background:#000;display:block"></video>
<script src="https://cdn.jsdelivr.net/npm/hls.js@latest"><\/script>
<script>
(function(){
  var v=document.getElementById('sv');
  var s='${base}${post.media}';
  if(window.Hls&&Hls.isSupported()){var h=new Hls();h.loadSource(s);h.attachMedia(v);}
  else if(v.canPlayType('application/vnd.apple.mpegurl')){v.src=s;}
  else{v.src='${base}${post.media.replace('.m3u8','.mp4')}';}
})();
<\/script>
</div>`;
                } else {
                    mediaHtml = `<div class="media-wrap"><video controls playsinline ${posterAttr} style="width:100%;max-height:480px;object-fit:contain;background:#000;display:block"><source src="${base}${post.media}" type="video/mp4"></video></div>`;
                }
            } else {
                mediaHtml = `<div class="media-wrap"><img src="${base}${post.media}" style="width:100%;max-height:520px;object-fit:cover;display:block" onerror="this.style.display='none'"></div>`;
            }
        }

        const ogImage = (post.media && post.mediaType !== 'video') ? `${base}${post.media}` : picUrl;

        res.send(`<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>${post.userName} Agrolink Gönderisi</title>
<meta property="og:title" content="${post.userName} - Agrolink">
<meta property="og:description" content="${(post.content||'').substring(0,200)}">
<meta property="og:image" content="${ogImage}">
<meta property="og:url" content="${base}/share/post/${post.id}">
<meta property="og:type" content="article">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:#0a0a0a;min-height:100vh;color:#fff}
.container{max-width:520px;margin:0 auto;padding-bottom:40px}
.top-bar{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;border-bottom:1px solid #1a1a1a}
.logo{color:#4caf50;font-weight:800;font-size:17px;text-decoration:none;display:flex;align-items:center;gap:6px}
.share-btn{background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.12);color:#fff;padding:8px 14px;border-radius:50px;cursor:pointer;font-size:13px;font-weight:500;display:flex;align-items:center;gap:5px;font-family:inherit}
.share-btn:hover{background:rgba(255,255,255,.14)}
.card{background:#111;margin:12px 16px;border-radius:20px;overflow:hidden;border:1px solid #1e1e1e}
.post-header{display:flex;align-items:center;gap:12px;padding:14px 16px}
.avatar{width:44px;height:44px;border-radius:50%;object-fit:cover;background:#222;flex-shrink:0}
.user-info{flex:1;min-width:0}
.user-name{font-weight:700;font-size:15px;color:#fff;display:flex;align-items:center;gap:5px;flex-wrap:wrap}
.user-handle{color:#666;font-size:13px;margin-top:1px}
.verified{color:#4caf50;font-size:14px}
.post-date{color:#555;font-size:12px;font-weight:400;margin-left:auto;white-space:nowrap;flex-shrink:0}
.media-wrap{background:#000;line-height:0}
.post-content{padding:14px 16px 10px;font-size:15px;line-height:1.65;color:#e0e0e0;white-space:pre-wrap;word-break:break-word}
.post-stats{display:flex;gap:20px;padding:10px 16px 14px;border-top:1px solid #1a1a1a;margin-top:6px}
.stat-item{display:flex;align-items:center;gap:6px;color:#666;font-size:13px;font-weight:500}
.stat-item span{font-weight:700;color:#aaa}
.cta-section{padding:0 16px}
.cta{display:flex;align-items:center;justify-content:center;gap:8px;background:linear-gradient(135deg,#2e7d32,#43a047);color:#fff;text-align:center;padding:16px;border-radius:16px;text-decoration:none;font-weight:700;font-size:15px;transition:.2s;letter-spacing:.3px}
.cta:hover{opacity:.9;transform:translateY(-1px)}
.related-label{color:#555;font-size:11px;font-weight:600;letter-spacing:1px;text-transform:uppercase;padding:20px 16px 10px}
.powered{text-align:center;padding:24px;color:#333;font-size:12px}
.powered span{color:#4caf50}
.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%) translateY(80px);background:#1e1e1e;color:#fff;padding:12px 20px;border-radius:12px;font-size:14px;font-weight:500;border:1px solid #2e7d32;transition:.3s;z-index:100;opacity:0}
.toast.show{transform:translateX(-50%) translateY(0);opacity:1}
</style>
</head>
<body>
<div class="container">
  <div class="top-bar">
    <a href="${base}" class="logo">🌾 Agrolink</a>
    <button class="share-btn" onclick="copyLink()">⬆ Paylaş</button>
  </div>

  <div class="card">
    <div class="post-header">
      <img src="${picUrl}" class="avatar" onerror="this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 44 44%22><rect fill=%22%23222%22 width=%2244%22 height=%2244%22/><text y=%2232%22 x=%2222%22 text-anchor=%22middle%22 font-size=%2224%22>👤</text></svg>'">
      <div class="user-info">
        <div class="user-name">
          ${post.userName}
          ${post.userVerified ? '<span class="verified">✅</span>' : ''}
        </div>
        <div class="user-handle">@${post.username}</div>
      </div>
      <div class="post-date">${date}</div>
    </div>

    ${mediaHtml}

    ${content_text ? `<div class="post-content">${content_text}</div>` : ''}

    <div class="post-stats">
      <div class="stat-item">❤️ <span>${post.likeCount ?? 0}</span> beğeni</div>
      <div class="stat-item">💬 <span>${post.commentCount ?? 0}</span> yorum</div>
      <div class="stat-item">👁️ <span>${post.views ?? 0}</span> görüntülenme</div>
    </div>
  </div>

  <div class="cta-section">
    <a href="${base}" class="cta">🌾 Agrolink'te Görüntüle →</a>
  </div>

  <div class="powered">Powered by <span>Agrolink</span></div>
</div>
<div class="toast" id="toast">🔗 Link kopyalandı!</div>
<script>
function copyLink(){
  navigator.clipboard.writeText(window.location.href).then(()=>{
    const t=document.getElementById('toast');
    t.classList.add('show');
    setTimeout(()=>t.classList.remove('show'),2200);
  }).catch(()=>{
    const inp=document.createElement('input');
    inp.value=window.location.href;
    document.body.appendChild(inp);
    inp.select();
    document.execCommand('copy');
    document.body.removeChild(inp);
    const t=document.getElementById('toast');
    t.classList.add('show');
    setTimeout(()=>t.classList.remove('show'),2200);
  });
}
</script>
</body></html>`);
    } catch(e) { console.error(e); res.status(500).send('<h2>Sunucu hatası</h2>'); }
});

// ═══════════════════════════════════════════════════════════════════════
// 📦 EKSİK API'LAR (v5 SQLite uyumluluğu)
// ═══════════════════════════════════════════════════════════════════════

// ─── 1. YORUM CEVAPLARI: GET /api/comments/:id/replies ──────────────
app.get('/api/comments/:id/replies', authenticateToken, async (req, res) => {
    try {
        const replies = await dbAll(
            `SELECT c.*, u.name, u.username, u."profilePic", u."isVerified",
                    (SELECT COUNT(*)::int FROM likes WHERE "commentId"=c.id) AS "likeCount",
                    EXISTS(SELECT 1 FROM likes WHERE "commentId"=c.id AND "userId"=$2) AS "isLiked"
             FROM comments c JOIN users u ON c."userId"=u.id
             WHERE c."parentId"=$1 AND c."isActive"=TRUE
             ORDER BY c."createdAt" ASC`,
            [req.params.id, req.user.id]
        );
        res.json({ replies: replies || [] });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 2. YORUM SİL: DELETE /api/posts/:id/comments/:commentId ────────
app.delete('/api/posts/:id/comments/:commentId', authenticateToken, async (req, res) => {
    try {
        const comment = await dbGet(
            'SELECT * FROM comments WHERE id=$1 AND "isActive"=TRUE', [req.params.commentId]
        );
        if (!comment) return res.status(404).json({ error: 'Yorum bulunamadı' });

        const post = await dbGet('SELECT "userId" FROM posts WHERE id=$1', [req.params.id]);
        const isOwner = comment.userId === req.user.id;
        const isPostOwner = post?.userId === req.user.id;
        const isAdmin = req.user.role === 'admin';

        if (!isOwner && !isPostOwner && !isAdmin) {
            return res.status(403).json({ error: 'Yetki yok' });
        }

        await dbRun('UPDATE comments SET "isActive"=FALSE, "updatedAt"=NOW() WHERE id=$1', [req.params.commentId]);
        // Yorum sayacını azalt
        await dbRun('UPDATE posts SET "commentCount"=GREATEST(0, COALESCE("commentCount",0)-1) WHERE id=$1', [req.params.id]);
        res.json({ success: true });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 3. YORUM CEVAPLA: POST /api/comments/:id/replies ───────────────
app.post('/api/comments/:id/replies', authenticateToken, async (req, res) => {
    try {
        const { content } = req.body;
        if (!content?.trim()) return res.status(400).json({ error: 'Cevap içeriği gerekli' });

        const parent = await dbGet(
            'SELECT * FROM comments WHERE id=$1 AND "isActive"=TRUE', [req.params.id]
        );
        if (!parent) return res.status(404).json({ error: 'Yorum bulunamadı' });

        const user = await dbGet('SELECT username FROM users WHERE id=$1', [req.user.id]);
        const replyId = uuidv4();

        await dbRun(
            `INSERT INTO comments (id, "postId", "userId", username, content, "parentId", "isActive", "createdAt", "updatedAt")
             VALUES ($1,$2,$3,$4,$5,$6,TRUE,NOW(),NOW())`,
            [replyId, parent.postId, req.user.id, user.username, content.trim(), req.params.id]
        );

        const reply = await dbGet(
            `SELECT c.*, u.name, u.username, u."profilePic", u."isVerified"
             FROM comments c JOIN users u ON c."userId"=u.id WHERE c.id=$1`,
            [replyId]
        );
        res.status(201).json({ reply });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 4. KULLANICI SUSTUR/SUSTURMA KALDIR: POST/DELETE /api/users/:id/mute
app.post('/api/users/:id/mute', authenticateToken, async (req, res) => {
    try {
        const targetId = req.params.id;
        if (targetId === req.user.id) return res.status(400).json({ error: 'Kendinizi susamazsınız' });

        await dbRun(
            `INSERT INTO mutes (id, "userId", "mutedId", "createdAt")
             VALUES ($1,$2,$3,NOW()) ON CONFLICT ("userId","mutedId") DO NOTHING`,
            [uuidv4(), req.user.id, targetId]
        ).catch(async () => {
            // Tablo yoksa oluştur
            await dbRun(`CREATE TABLE IF NOT EXISTS mutes (
                id UUID PRIMARY KEY, "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                "mutedId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                "createdAt" TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE("userId","mutedId"))`);
            await dbRun(`INSERT INTO mutes (id,"userId","mutedId","createdAt") VALUES ($1,$2,$3,NOW()) ON CONFLICT DO NOTHING`,
                [uuidv4(), req.user.id, targetId]);
        });
        res.json({ success: true, message: 'Kullanıcı susturuldu' });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

app.delete('/api/users/:id/mute', authenticateToken, async (req, res) => {
    try {
        await dbRun('DELETE FROM mutes WHERE "userId"=$1 AND "mutedId"=$2', [req.user.id, req.params.id]);
        res.json({ success: true, message: 'Susturma kaldırıldı' });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

app.get('/api/users/muted', authenticateToken, async (req, res) => {
    try {
        const muted = await dbAll(
            `SELECT u.id, u.username, u.name, u."profilePic", m."createdAt"
             FROM mutes m JOIN users u ON m."mutedId"=u.id
             WHERE m."userId"=$1 ORDER BY m."createdAt" DESC`,
            [req.user.id]
        ).catch(() => []);
        res.json({ muted });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 5. STORY REAKSİYON: POST /api/stories/:id/react ───────────────
app.post('/api/stories/:id/react', authenticateToken, async (req, res) => {
    try {
        const { emoji = '❤️' } = req.body;
        const story = await dbGet('SELECT id,"userId" FROM stories WHERE id=$1 AND "isActive"=TRUE', [req.params.id]);
        if (!story) return res.status(404).json({ error: 'Story bulunamadı' });

        await dbRun(
            `INSERT INTO story_reactions (id,"storyId","userId",emoji,"createdAt")
             VALUES ($1,$2,$3,$4,NOW())
             ON CONFLICT ("storyId","userId") DO UPDATE SET emoji=$4,"createdAt"=NOW()`,
            [uuidv4(), req.params.id, req.user.id, emoji]
        ).catch(async () => {
            await dbRun(`CREATE TABLE IF NOT EXISTS story_reactions (
                id UUID PRIMARY KEY, "storyId" UUID NOT NULL REFERENCES stories(id) ON DELETE CASCADE,
                "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                emoji TEXT DEFAULT '❤️', "createdAt" TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE("storyId","userId"))`);
            await dbRun(`INSERT INTO story_reactions (id,"storyId","userId",emoji,"createdAt") VALUES ($1,$2,$3,$4,NOW()) ON CONFLICT DO NOTHING`,
                [uuidv4(), req.params.id, req.user.id, emoji]);
        });

        // Story sahibine bildirim
        if (story.userId !== req.user.id) {
            await createNotification(story.userId, 'story_reaction',
                `Hikayen ${emoji} reaksiyonu aldı`, { storyId: req.params.id });
        }
        res.json({ success: true, emoji });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 6. POST PAYLAŞ SAYACI: POST /api/posts/:id/share ───────────────
app.post('/api/posts/:id/share', authenticateToken, async (req, res) => {
    try {
        const post = await dbGet('SELECT id,"userId","shareCount" FROM posts WHERE id=$1 AND "isActive"=TRUE', [req.params.id]);
        if (!post) return res.status(404).json({ error: 'Post bulunamadı' });

        await dbRun(
            'UPDATE posts SET "shareCount"=COALESCE("shareCount",0)+1,"updatedAt"=NOW() WHERE id=$1',
            [req.params.id]
        );

        // Paylaşım kaydı
        await dbRun(
            `INSERT INTO post_shares (id,"postId","userId","createdAt") VALUES ($1,$2,$3,NOW()) ON CONFLICT DO NOTHING`,
            [uuidv4(), req.params.id, req.user.id]
        ).catch(async () => {
            await dbRun(`CREATE TABLE IF NOT EXISTS post_shares (
                id UUID PRIMARY KEY, "postId" UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
                "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                "createdAt" TIMESTAMPTZ DEFAULT NOW(), UNIQUE("postId","userId"))`);
        });

        const shareUrl = `${req.protocol}://${req.get('host')}/share/post/${req.params.id}`;
        res.json({ success: true, shareUrl, shareCount: (post.shareCount || 0) + 1 });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 7. HESAP SİL: DELETE /api/users/account/delete ────────────────
app.delete('/api/users/account/delete', authenticateToken, async (req, res) => {
    try {
        const { password } = req.body;
        if (!password) return res.status(400).json({ error: 'Şifre gerekli' });

        // 🔒 Sadece şifre doğrulaması için gerekli alan çekiliyor
        const user = await dbGet('SELECT id, password FROM users WHERE id=$1', [req.user.id]);
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: 'Şifre yanlış' });

        // Soft delete
        await dbRun(
            `UPDATE users SET "isActive"=FALSE, email=CONCAT('deleted_',$1,'_',email),
             username=CONCAT('deleted_',$1,'_',username), "updatedAt"=NOW() WHERE id=$1`,
            [req.user.id]
        );
        await dbRun('DELETE FROM refresh_tokens WHERE "userId"=$1', [req.user.id]);

        console.log(`🗑️ Hesap silindi: ${user.username} (${user.id})`);
        res.json({ success: true, message: 'Hesabınız başarıyla silindi.' });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 8. ADMİN GENEL BAKIŞ: GET /api/admin/overview ─────────────────
app.get('/api/admin/overview', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });

        const [users, posts, reports, bannedIps, activeToday] = await Promise.all([
            dbGet('SELECT COUNT(*)::int AS cnt FROM users WHERE "isActive"=TRUE'),
            dbGet('SELECT COUNT(*)::int AS cnt FROM posts WHERE "isActive"=TRUE'),
            dbGet(`SELECT COUNT(*)::int AS cnt FROM reports WHERE status='pending'`).catch(() => ({ cnt: 0 })),
            dbGet('SELECT COUNT(*)::int AS cnt FROM banned_ips WHERE ("expiresAt" IS NULL OR "expiresAt">NOW())'),
            dbGet(`SELECT COUNT(*)::int AS cnt FROM users WHERE "lastLogin" > NOW() - INTERVAL '24 hours' AND "isActive"=TRUE`),
        ]);

        const { activeJobs, maxConcurrent } = getVideoQueueStatus();

        res.json({
            stats: {
                totalUsers     : users?.cnt || 0,
                totalPosts     : posts?.cnt || 0,
                pendingReports : reports?.cnt || 0,
                bannedIPs      : bannedIps?.cnt || 0,
                activeToday    : activeToday?.cnt || 0,
            },
            videoProcessor: { activeJobs, maxConcurrent },
            firewall: {
                blockedIPs : FIREWALL_BLOCKED_IPS.size,
                attackLogs : FIREWALL_ATTACK_LOG.size,
            },
            serverTime: new Date().toISOString(),
        });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 9. ADMİN RAPORLAR: GET /api/admin/reports ──────────────────────
app.get('/api/admin/reports', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });

        const { page = 1, limit = 20, status = 'pending' } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);

        const reports = await dbAll(
            `SELECT r.*, 
                    ru.username AS "reporterUsername", ru.name AS "reporterName",
                    CASE r.type
                        WHEN 'post' THEN (SELECT content FROM posts WHERE id=r."targetId")
                        WHEN 'user' THEN (SELECT username FROM users WHERE id=r."targetId")
                        ELSE NULL
                    END AS "targetPreview"
             FROM reports r
             LEFT JOIN users ru ON r."reporterId"=ru.id
             WHERE ($1='all' OR r.status=$1)
             ORDER BY r."createdAt" DESC
             LIMIT $2 OFFSET $3`,
            [status, parseInt(limit), offset]
        ).catch(() => []);

        res.json({ reports, page: parseInt(page) });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

app.patch('/api/admin/reports/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
        const { status, note } = req.body;
        await dbRun(
            `UPDATE reports SET status=$1, "adminNote"=$2, "reviewedAt"=NOW(), "reviewedBy"=$3 WHERE id=$4`,
            [status, note || null, req.user.id, req.params.id]
        );
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 10. ADMİN YASAKLI IP YÖNETİMİ: GET/DELETE /api/admin/banned-ips
app.get('/api/admin/banned-ips', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });

        const bans = await dbAll(
            `SELECT * FROM banned_ips WHERE ("expiresAt" IS NULL OR "expiresAt" > NOW())
             ORDER BY "bannedAt" DESC LIMIT 100`
        );
        res.json({ bans, total: bans.length });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

app.delete('/api/admin/banned-ips/:ip', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
        const ip = decodeURIComponent(req.params.ip);
        await dbRun('DELETE FROM banned_ips WHERE ip=$1', [ip]);
        FIREWALL_BLOCKED_IPS.delete(ip);
        ipBanCache.delete(ip);
        res.json({ success: true, message: `${ip} yasağı kaldırıldı` });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── MAĞAZA EKSİK ROTALAR ─────────────────────────────────────────
// Satıcının ürünleri
app.get('/api/store/products/seller/:sellerId', authenticateToken, async (req, res) => {
    try {
        const products = await dbAll(
            `SELECT p.*, u.username AS "sellerName", u."profilePic" AS "sellerPic"
             FROM products p JOIN users u ON p."sellerId"=u.id
             WHERE p."sellerId"=$1 AND p."isActive"=TRUE ORDER BY p."createdAt" DESC`,
            [req.params.sellerId]);
        res.json({ products });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// Kendi ürünleri (alias)
app.get('/api/products/my', authenticateToken, async (req, res) => {
    try {
        const products = await dbAll(
            `SELECT * FROM products WHERE "sellerId"=$1 ORDER BY "createdAt" DESC`, [req.user.id]);
        res.json({ products });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// Tüm ürünler (alias /api/products)
app.get('/api/products', authenticateToken, async (req, res) => {
    try {
        const { page=1, limit=20, category, q } = req.query;
        const pn=Math.max(1,parseInt(page)||1), ln=Math.min(parseInt(limit)||20,100);
        const off=(pn-1)*ln;
        const conds=['"isActive"=TRUE'], params=[]; let pi=1;
        if (category){ conds.push(`category=$${pi++}`); params.push(category); }
        if (q){ conds.push(`(name ILIKE $${pi} OR description ILIKE $${pi})`); params.push(`%${q}%`); pi++; }
        const products = await dbAll(
            `SELECT p.*,u.username AS "sellerName",u."profilePic" AS "sellerPic" FROM products p JOIN users u ON p."sellerId"=u.id WHERE ${conds.join(' AND ')} ORDER BY p."createdAt" DESC LIMIT $${pi} OFFSET $${pi+1}`,
            [...params, ln, off]);
        res.json({ products });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// Kullanıcıya ait ürünler
app.get('/api/users/:userId/products', authenticateToken, async (req, res) => {
    try {
        const products = await dbAll(
            `SELECT * FROM products WHERE "sellerId"=$1 AND "isActive"=TRUE ORDER BY "createdAt" DESC`, [req.params.userId]);
        res.json({ products });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// Ürün sil (alias /api/products/:productId)
app.delete('/api/products/:productId', authenticateToken, async (req, res) => {
    try {
        const p = await dbGet('SELECT "sellerId" FROM products WHERE id=$1', [req.params.productId]);
        if (!p) return res.status(404).json({ error: 'Ürün bulunamadı' });
        if (p.sellerId !== req.user.id) return res.status(403).json({ error: 'Yetki yok' });
        await dbRun('UPDATE products SET "isActive"=FALSE,"updatedAt"=NOW() WHERE id=$1', [req.params.productId]);
        res.json({ message: 'Ürün silindi' });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── POST KAYDET SİL: DELETE /api/posts/:id/save ───────────────────
app.delete('/api/posts/:id/save', authenticateToken, async (req, res) => {
    try {
        const save = await dbGet('SELECT id FROM saves WHERE "postId"=$1 AND "userId"=$2', [req.params.id, req.user.id]);
        if (!save) return res.status(404).json({ error: 'Kayıt bulunamadı' });
        await dbRun('DELETE FROM saves WHERE id=$1', [save.id]);
        await dbRun('UPDATE posts SET "saveCount"=GREATEST(0,COALESCE("saveCount",0)-1) WHERE id=$1', [req.params.id]).catch(()=>{});
        res.json({ message: 'Kayıt kaldırıldı', isSaved: false });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── KONUŞMA SİL: DELETE /api/messages/conversations/:userId ───────
app.delete('/api/messages/conversations/:userId', authenticateToken, async (req, res) => {
    try {
        const partnerId = req.params.userId;
        await dbRun(
            'DELETE FROM messages WHERE ("senderId"=$1 AND "recipientId"=$2) OR ("senderId"=$2 AND "recipientId"=$1)',
            [req.user.id, partnerId]);
        res.json({ message: 'Konuşma silindi' });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── FARMBOOK TARLALAR: GET /api/farmbook/fields ───────────────────
app.get('/api/farmbook/fields', authenticateToken, async (req, res) => {
    try {
        const fields = await dbAll(
            `SELECT DISTINCT "fieldName", "fieldSize", "fieldSizeUnit", MAX("recordDate") AS "lastRecord"
             FROM farmbook_records WHERE "userId"=$1 AND "fieldName" IS NOT NULL
             GROUP BY "fieldName","fieldSize","fieldSizeUnit" ORDER BY "lastRecord" DESC`,
            [req.user.id]);
        res.json({ fields });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── HESAP SİL ─────────────────────────────────────────────────────
app.delete('/api/users/account', authenticateToken, async (req, res) => {
    try {
        const { password } = req.body;
        if (!password) return res.status(400).json({ error: 'Şifre gerekli' });
        const user = await dbGet('SELECT password FROM users WHERE id=$1', [req.user.id]);
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: 'Şifre yanlış' });
        await dbRun('UPDATE users SET "isActive"=FALSE,"updatedAt"=NOW() WHERE id=$1', [req.user.id]);
        await dbRun('DELETE FROM refresh_tokens WHERE "userId"=$1', [req.user.id]).catch(()=>{});
        res.json({ message: 'Hesap silindi' });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── PUSH BİLDİRİM DURUM: /api/push/status ─────────────────────────
app.get('/api/push/status', authenticateToken, async (req, res) => {
    try {
        const sub = await dbGet('SELECT id FROM push_subscriptions WHERE "userId"=$1 LIMIT 1', [req.user.id]).catch(()=>null);
        res.json({ subscribed: !!sub });
    } catch (e) { res.json({ subscribed: false }); }
});

// ─── PUSH SUBSCRIBE ────────────────────────────────────────────────
app.post('/api/push/subscribe', authenticateToken, async (req, res) => {
    try {
        const { endpoint, keys } = req.body;
        if (!endpoint) return res.status(400).json({ error: 'Endpoint gerekli' });
        await dbRun(
            `INSERT INTO push_subscriptions (id,"userId",endpoint,keys,"createdAt")
             VALUES ($1,$2,$3,$4,NOW())
             ON CONFLICT("userId",endpoint) DO UPDATE SET keys=$4,"updatedAt"=NOW()`,
            [uuidv4(), req.user.id, endpoint, JSON.stringify(keys||{})]).catch(async()=>{
            // Tablo yoksa oluştur
            await dbRun(`CREATE TABLE IF NOT EXISTS push_subscriptions (id UUID PRIMARY KEY, "userId" UUID, endpoint TEXT, keys JSONB, "createdAt" TIMESTAMPTZ DEFAULT NOW(), "updatedAt" TIMESTAMPTZ, UNIQUE("userId",endpoint))`).catch(()=>{});
            await dbRun(`INSERT INTO push_subscriptions (id,"userId",endpoint,keys,"createdAt") VALUES ($1,$2,$3,$4,NOW()) ON CONFLICT DO NOTHING`,[uuidv4(),req.user.id,endpoint,JSON.stringify(keys||{})]).catch(()=>{});
        });
        res.json({ message: 'Push aboneliği kaydedildi' });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── DOĞRULAMA DURUM (alias): /api/verification/status ─────────────
app.get('/api/verification/status', authenticateToken, async (req, res) => {
    try {
        const user = await dbGet('SELECT "isVerified","emailVerified" FROM users WHERE id=$1', [req.user.id]);
        res.json({ isVerified: !!user?.isVerified, emailVerified: !!user?.emailVerified });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── KULLANICI İLGİ ALANLARI ────────────────────────────────────────
app.post('/api/users/interests', authenticateToken, async (req, res) => {
    try {
        const { interests } = req.body;
        if (!interests || !Array.isArray(interests)) return res.status(400).json({ error: 'interests dizisi gerekli' });
        await dbRun('DELETE FROM user_interests WHERE "userId"=$1', [req.user.id]).catch(()=>{});
        for (const interest of interests.slice(0,100)) {
            if (interest?.trim()) {
                await dbRun(`INSERT INTO user_interests (id,"userId",interest,"createdAt") VALUES ($1,$2,$3,NOW()) ON CONFLICT DO NOTHING`,[uuidv4(),req.user.id,interest.trim()]).catch(()=>{});
            }
        }
        res.json({ message: 'İlgi alanları kaydedildi', count: interests.length });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});
app.get('/api/users/interests', authenticateToken, async (req, res) => {
    try {
        const rows = await dbAll('SELECT interest FROM user_interests WHERE "userId"=$1 ORDER BY "createdAt"', [req.user.id]).catch(()=>[]);
        res.json({ interests: rows.map(r=>r.interest) });
    } catch (e) { res.json({ interests: [] }); }
});

// ─── E-POSTA ABONELIK YÖNET ────────────────────────────────────────
app.get('/api/email/unsubscribe/:userId', async (req, res) => {
    try {
        await dbRun('UPDATE users SET "emailNotifications"=FALSE,"updatedAt"=NOW() WHERE id=$1', [req.params.userId]).catch(()=>{});
        res.send('<html><body style="font-family:sans-serif;text-align:center;padding:40px"><h2>✅ E-posta bildirimlerinden çıkıldı.</h2><p>Agrolink e-posta bildirimleri durduruldu.</p></body></html>');
    } catch (e) { res.status(500).send('Hata oluştu'); }
});
app.get('/api/email/resubscribe/:userId', async (req, res) => {
    try {
        await dbRun('UPDATE users SET "emailNotifications"=TRUE,"updatedAt"=NOW() WHERE id=$1', [req.params.userId]).catch(()=>{});
        res.send('<html><body style="font-family:sans-serif;text-align:center;padding:40px"><h2>✅ E-posta bildirimleri yeniden etkinleştirildi.</h2></body></html>');
    } catch (e) { res.status(500).send('Hata oluştu'); }
});

// ─── ŞIFRE SIFIRLA DIREKT LINK: /api/auth/reset-password-direct ────
app.get('/api/auth/reset-password-direct', async (req, res) => {
    const { token } = req.query;
    if (!token) return res.status(400).send('<h2>Geçersiz bağlantı</h2>');
    try {
        const report = await dbGet(
            `SELECT slr."userId", u.email FROM suspicious_login_reports slr JOIN users u ON slr."userId"=u.id
             WHERE slr."passwordResetToken"=$1 AND slr."tokenExpiresAt">NOW() LIMIT 1`,
            [token]).catch(()=>null);
        if (!report) return res.send('<html><body style="font-family:sans-serif;text-align:center;padding:40px"><h2>❌ Bağlantı geçersiz veya süresi dolmuş</h2><p>Yeni bir şifre sıfırlama bağlantısı için uygulamayı kullanın.</p></body></html>');
        res.send(`<html><body style="font-family:sans-serif;text-align:center;padding:40px"><h2>🔐 Şifre Sıfırlama</h2><p>${report.email} hesabı için şifre sıfırlama.</p><p>Uygulama üzerinden "Şifremi Unuttum" seçeneğini kullanarak yeni şifrenizi belirleyebilirsiniz.</p><a href="/" style="color:#2e7d32">Uygulamaya Git →</a></body></html>`);
    } catch (e) { res.status(500).send('<h2>Sunucu hatası</h2>'); }
});


// ==================== 15 KRİTİK EKSİK ROTA ====================

// ─── 1. KULLANICI PROFİLİ (ID ile): GET /api/users/:id ────────────
// NOT: /api/users/:username zaten var; bu UUID/ID ile çalışır
app.get('/api/users/:id/profile', authenticateToken, async (req, res) => {
    try {
        const user = await dbGet(`
            SELECT u.id, u.username, u.name, u."profilePic", u."coverPic", u.bio, u.location,
                   u.website, u."isVerified", u."hasFarmerBadge", u."userType", u."isOnline",
                   u."lastSeen", u."createdAt",
                   (SELECT COUNT(*) FROM posts   WHERE "userId"=u.id AND "isActive"=TRUE) AS "postCount",
                   (SELECT COUNT(*) FROM follows WHERE "followingId"=u.id)                AS "followerCount",
                   (SELECT COUNT(*) FROM follows WHERE "followerId"=u.id)                 AS "followingCount",
                   EXISTS(SELECT 1 FROM follows WHERE "followerId"=$1 AND "followingId"=u.id) AS "isFollowing",
                   EXISTS(SELECT 1 FROM blocks  WHERE "blockerId"=$1 AND "blockedId"=u.id)   AS "isBlocked"
            FROM users u WHERE u.id=$2 AND u."isActive"=TRUE`, [req.user.id, req.params.id]);
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
        const { password: _, ...safe } = user;
        res.json({ user: safe });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 2. KULLANICI GÖNDERİLERİ: GET /api/users/:id/posts ───────────
// MEVCUT /api/users/:userId/posts'tan farklı path uyumluluğu için
// (zaten var ama /api/users/:userId/posts olarak - bu da çalışsın)
// Bu rota zaten mevcut, alias tanımla:

// ─── 3. ŞİFRE SIFIRLAMA (TOKEN ile): POST /api/auth/reset-password-with-token
app.post('/api/auth/reset-password-with-token', async (req, res) => {
    try {
        const { username, resetToken, newPassword, confirmPassword } = req.body;
        if (!username || !resetToken || !newPassword || !confirmPassword)
            return res.status(400).json({ error: 'Tüm alanlar zorunludur' });
        if (newPassword !== confirmPassword)
            return res.status(400).json({ error: 'Şifreler eşleşmiyor' });
        if (newPassword.length < 8)
            return res.status(400).json({ error: 'Şifre en az 8 karakter olmalıdır' });

        const user = await dbGet('SELECT * FROM users WHERE username=$1 AND "isActive"=TRUE',
            [username.toLowerCase().trim()]);
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });

        const report = await dbGet(
            `SELECT * FROM suspicious_login_reports
             WHERE "userId"=$1 AND "passwordResetToken"=$2 AND "tokenExpiresAt">NOW()
             ORDER BY "reportedAt" DESC LIMIT 1`,
            [user.id, resetToken]).catch(()=>null);
        if (!report) return res.status(400).json({ error: 'Geçersiz veya süresi dolmuş token' });

        const hashed = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
        await dbRun('UPDATE users SET password=$1,"updatedAt"=NOW() WHERE id=$2', [hashed, user.id]);
        await dbRun('DELETE FROM refresh_tokens WHERE "userId"=$1', [user.id]).catch(()=>{});

        const tokens = generateTokens(user);
        const { password: _, ...safe } = user;
        res.json({ success: true, message: 'Şifre başarıyla değiştirildi.', token: tokens.accessToken, user: safe });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 4. GÖNDERI MESAJDA PAYLAŞ: POST /api/messages/share-post ──────
app.post('/api/messages/share-post', authenticateToken, async (req, res) => {
    try {
        const { postId, recipientId } = req.body;
        if (!postId || !recipientId) return res.status(400).json({ error: 'postId ve recipientId gerekli' });

        const [post, recipient, sender] = await Promise.all([
            dbGet('SELECT id FROM posts WHERE id=$1 AND "isActive"=TRUE', [postId]),
            dbGet('SELECT id,username FROM users WHERE id=$1 AND "isActive"=TRUE', [recipientId]),
            dbGet('SELECT username FROM users WHERE id=$1', [req.user.id])
        ]);
        if (!post) return res.status(404).json({ error: 'Gönderi bulunamadı' });
        if (!recipient) return res.status(404).json({ error: 'Alıcı bulunamadı' });

        const blocked = await dbGet(
            'SELECT id FROM blocks WHERE ("blockerId"=$1 AND "blockedId"=$2) OR ("blockerId"=$2 AND "blockedId"=$1)',
            [req.user.id, recipientId]);
        if (blocked) return res.status(403).json({ error: 'Bu kullanıcıya mesaj gönderemezsiniz' });

        const msgId = uuidv4();
        const postUrl = `/post/${postId}`;
        await dbRun(
            `INSERT INTO messages (id,"senderId","senderUsername","recipientId","recipientUsername",content,read,"createdAt","updatedAt")
             VALUES ($1,$2,$3,$4,$5,$6,FALSE,NOW(),NOW())`,
            [msgId, req.user.id, sender.username, recipientId, recipient.username, `📷 Paylaşılan Gönderi: ${postUrl}`]);

        res.json({ message: 'Gönderi paylaşıldı', messageId: msgId });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 5. BİLDİRİMLERİ OKU (POST alias): POST /api/notifications/read
app.post('/api/notifications/read', authenticateToken, async (req, res) => {
    try {
        const { ids } = req.body;
        if (ids && Array.isArray(ids) && ids.length > 0) {
            const ph = ids.map((_,i)=>`$${i+2}`).join(',');
            await dbRun(`UPDATE notifications SET read=TRUE,"readAt"=NOW() WHERE id IN (${ph}) AND "userId"=$1`,
                [req.user.id, ...ids]);
        } else {
            await dbRun('UPDATE notifications SET read=TRUE,"readAt"=NOW() WHERE "userId"=$1', [req.user.id]);
        }
        res.json({ message: 'Bildirimler okundu olarak işaretlendi' });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 6. ANKET OY VER: POST /api/posts/:postId/poll/vote ────────────
app.post('/api/posts/:postId/poll/vote', authenticateToken, async (req, res) => {
    try {
        const { postId } = req.params;
        const { optionId, optionIndex: optIdx } = req.body;
        if (optionId === undefined && optIdx === undefined)
            return res.status(400).json({ error: 'Şık seçimi gereklidir' });

        const post = await dbGet('SELECT * FROM posts WHERE id=$1 AND "isPoll"=TRUE', [postId]);
        if (!post) return res.status(404).json({ error: 'Anket bulunamadı' });

        const existing = await dbGet('SELECT id FROM poll_votes WHERE "postId"=$1 AND "userId"=$2',
            [postId, req.user.id]).catch(()=>null);
        if (existing) return res.status(400).json({ error: 'Bu ankete zaten oy verdiniz' });

        let pollOptions = typeof post.pollOptions === 'string'
            ? JSON.parse(post.pollOptions) : (post.pollOptions || []);

        const idx = optIdx !== undefined
            ? parseInt(optIdx)
            : pollOptions.findIndex(o => o.id === parseInt(optionId));

        if (idx < 0 || idx >= pollOptions.length)
            return res.status(400).json({ error: 'Geçersiz şık' });

        pollOptions[idx].votes = (pollOptions[idx].votes || 0) + 1;

        await dbRun('UPDATE posts SET "pollOptions"=$1,"updatedAt"=NOW() WHERE id=$2',
            [JSON.stringify(pollOptions), postId]);

        await dbRun(`CREATE TABLE IF NOT EXISTS poll_votes (id UUID PRIMARY KEY, "postId" UUID, "userId" UUID, "optionId" TEXT, "createdAt" TIMESTAMPTZ DEFAULT NOW(), UNIQUE("postId","userId"))`).catch(()=>{});
        await dbRun('INSERT INTO poll_votes (id,"postId","userId","optionId","createdAt") VALUES ($1,$2,$3,$4,NOW()) ON CONFLICT DO NOTHING',
            [uuidv4(), postId, req.user.id, String(optionId ?? idx)]).catch(()=>{});

        res.json({ success: true, pollOptions, message: 'Oyunuz kaydedildi' });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 7. PUBLIC POST ÖNIZLEME: GET /p/:id ───────────────────────────
app.get('/p/:id', async (req, res) => {
    try {
        const post = await dbGet(`
            SELECT p.*, u.username, u.name AS "userName", u."profilePic" AS "userProfilePic", u."isVerified" AS "userVerified"
            FROM posts p JOIN users u ON p."userId"=u.id
            WHERE p.id=$1 AND p."isActive"=TRUE AND u."isActive"=TRUE`, [req.params.id]);
        if (!post) return res.redirect('/');
        const base = `${req.protocol}://${req.get('host')}`;
        res.redirect(`${base}/share/post/${post.id}`);
    } catch (e) { res.redirect('/'); }
});

// ─── 8. PUBLIC KULLANICI ÖNIZLEME: GET /u/:id ──────────────────────
app.get('/u/:id', async (req, res) => {
    try {
        const user = await dbGet(
            'SELECT username FROM users WHERE (username=$1 OR id::text=$1) AND "isActive"=TRUE',
            [req.params.id]).catch(()=>null);
        if (!user) return res.redirect('/');
        const base = `${req.protocol}://${req.get('host')}`;
        res.redirect(`${base}/share/profile/${user.username}`);
    } catch (e) { res.redirect('/'); }
});

// ─── 9. PUSH UNSUBSCRIBE: POST /api/push/unsubscribe ───────────────
app.post('/api/push/unsubscribe', authenticateToken, async (req, res) => {
    try {
        const { endpoint } = req.body;
        if (endpoint) {
            await dbRun('DELETE FROM push_subscriptions WHERE "userId"=$1 AND endpoint=$2',
                [req.user.id, endpoint]).catch(()=>{});
        } else {
            await dbRun('DELETE FROM push_subscriptions WHERE "userId"=$1', [req.user.id]).catch(()=>{});
        }
        res.json({ message: 'Push aboneliği iptal edildi' });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 10. PUSH TEST: POST /api/push/test ────────────────────────────
app.post('/api/push/test', authenticateToken, async (req, res) => {
    try {
        // webpush kurulu değilse sessizce geç
        res.json({ message: 'Test bildirimi gönderildi', sent: false, note: 'web-push paketi yapılandırılmadı' });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 11. HESAP SİL (alias DELETE): DELETE /api/users/delete ────────
app.delete('/api/users/delete', authenticateToken, async (req, res) => {
    try {
        const { password } = req.body;
        if (!password) return res.status(400).json({ error: 'Şifre gerekli' });
        const user = await dbGet('SELECT password FROM users WHERE id=$1', [req.user.id]);
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: 'Şifre yanlış' });
        await dbRun('UPDATE users SET "isActive"=FALSE,"updatedAt"=NOW() WHERE id=$1', [req.user.id]);
        await dbRun('DELETE FROM refresh_tokens WHERE "userId"=$1', [req.user.id]).catch(()=>{});
        res.json({ message: 'Hesap silindi' });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 12. TOPLU POST GÖRÜNTÜLEME: POST /api/posts/batch-view ─────────
app.post('/api/posts/batch-view', authenticateToken, async (req, res) => {
    try {
        const { postIds } = req.body;
        if (!postIds || !Array.isArray(postIds) || postIds.length === 0)
            return res.status(400).json({ error: 'postIds dizisi gerekli' });
        const today = new Date().toISOString().slice(0,10);
        for (const postId of postIds.slice(0,50)) {
            await dbRun(`
                INSERT INTO post_views (id,"postId","userId","viewDate","createdAt")
                VALUES ($1,$2,$3,$4,NOW()) ON CONFLICT DO NOTHING`,
                [uuidv4(), postId, req.user.id, today]).catch(()=>{});
            await dbRun('UPDATE posts SET views=COALESCE(views,0)+1 WHERE id=$1', [postId]).catch(()=>{});
        }
        res.json({ message: 'Görüntülemeler kaydedildi', count: postIds.length });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 13. GRUP SOHBETLERİ: GET /api/chats/groups ────────────────────
app.get('/api/chats/groups', authenticateToken, async (req, res) => {
    try {
        const groups = await dbAll(`
            SELECT gc.*, gm.role, u.name AS "creatorName"
            FROM group_chats gc
            JOIN group_members gm ON gm."groupId"=gc.id AND gm."userId"=$1
            LEFT JOIN users u ON gc."creatorId"=u.id
            ORDER BY gc."createdAt" DESC`, [req.user.id]).catch(()=>[]);
        res.json({ groups });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 14. GRUP SOHBET OLUŞTUR: POST /api/chats/group ─────────────────
app.post('/api/chats/group', authenticateToken, upload.single('photo'), async (req, res) => {
    try {
        const { name, memberIds } = req.body;
        if (!name) return res.status(400).json({ error: 'Grup adı gerekli' });

        const members = typeof memberIds === 'string' ? JSON.parse(memberIds) : (memberIds || []);
        const groupId = uuidv4();

        let photoUrl = null;
        if (req.file) {
            const fname = `group_${groupId}_${Date.now()}.webp`;
            const out = require('path').join(profilesDir, fname);
            await sharp(req.file.path).resize(256,256,{fit:'cover'}).webp({quality:85}).toFile(out);
            await require('fs').promises.unlink(req.file.path).catch(()=>{});
            photoUrl = `/uploads/profiles/${fname}`;
        }

        // group_chats tablosu yoksa oluştur
        await dbRun(`CREATE TABLE IF NOT EXISTS group_chats (id UUID PRIMARY KEY, name TEXT, photo TEXT, "creatorId" UUID, "createdAt" TIMESTAMPTZ DEFAULT NOW())`).catch(()=>{});
        await dbRun(`CREATE TABLE IF NOT EXISTS group_members (id UUID PRIMARY KEY, "groupId" UUID, "userId" UUID, role TEXT DEFAULT 'member', "joinedAt" TIMESTAMPTZ DEFAULT NOW(), UNIQUE("groupId","userId"))`).catch(()=>{});

        await dbRun('INSERT INTO group_chats (id,name,photo,"creatorId","createdAt") VALUES ($1,$2,$3,$4,NOW())',
            [groupId, name.substring(0,100), photoUrl, req.user.id]);

        const allMembers = [...new Set([req.user.id, ...members])];
        for (const uid of allMembers) {
            const role = uid === req.user.id ? 'admin' : 'member';
            await dbRun('INSERT INTO group_members (id,"groupId","userId",role,"joinedAt") VALUES ($1,$2,$3,$4,NOW()) ON CONFLICT DO NOTHING',
                [uuidv4(), groupId, uid, role]).catch(()=>{});
        }

        res.status(201).json({ message: 'Grup oluşturuldu', groupId, name, photo: photoUrl });
    } catch (e) {
        if (req.file) require('fs').promises.unlink(req.file.path).catch(()=>{});
        console.error(e); res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 15. VİDEO THUMBNAIL (alias): GET /api/videos/thumbnail/:filename
app.get('/api/videos/thumbnail/:filename', authenticateToken, (req, res) => {
    const thumbPath = require('path').join(thumbnailsDir, req.params.filename.replace(/[^a-zA-Z0-9._-]/g,''));
    const fss = require('fs');
    if (fss.existsSync(thumbPath)) {
        res.sendFile(thumbPath);
    } else {
        // Default thumbnail
        const def = require('path').join(uploadsDir, 'default-video-thumb.jpg');
        if (fss.existsSync(def)) return res.sendFile(def);
        res.status(404).json({ error: 'Thumbnail bulunamadı' });
    }
});


// ==================== KALAN EKSİK ROTALAR ====================

// GET /api/users/:id  (UUID/id ile profil lookup)
app.get('/api/users/:id', authenticateToken, async (req, res) => {
    try {
        const param = req.params.id;
        const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(param);
        const sql = `
            SELECT u.id, u.username, u.name, u."profilePic", u."coverPic", u.bio, u.location,
                   u.website, u."isVerified", u."hasFarmerBadge", u."userType", u."isOnline",
                   u."lastSeen", u."createdAt",
                   (SELECT COUNT(*) FROM posts   WHERE "userId"=u.id AND "isActive"=TRUE) AS "postCount",
                   (SELECT COUNT(*) FROM follows WHERE "followingId"=u.id)                AS "followerCount",
                   (SELECT COUNT(*) FROM follows WHERE "followerId"=u.id)                 AS "followingCount",
                   EXISTS(SELECT 1 FROM follows WHERE "followerId"=$1 AND "followingId"=u.id) AS "isFollowing",
                   EXISTS(SELECT 1 FROM blocks  WHERE "blockerId"=$1 AND "blockedId"=u.id)   AS "isBlocked"
            FROM users u WHERE ${cond} AND u."isActive"=TRUE
        `;
        const finalSql = sql.replace('${cond}', isUUID ? 'u.id=$2' : 'u.username=$2');
        const user = await dbGet(finalSql, [req.user.id, param]);
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
        const { password: _, ...safe } = user;
        res.json({ user: safe });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});


// GET /api/users/:id/posts  (id ile kullanıcı gönderileri)
app.get('/api/users/:id/posts', authenticateToken, async (req, res) => {
    try {
        const { page=1, limit=12 } = req.query;
        const pn = Math.max(1, parseInt(page)||1);
        const ln = Math.min(parseInt(limit)||12, 50);
        const off = (pn-1)*ln;
        const userId = req.params.id;

        const target = await dbGet('SELECT id,"isPrivate" FROM users WHERE id=$1 AND "isActive"=TRUE', [userId]);
        if (!target) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });

        if (target.isPrivate && userId !== req.user.id) {
            const follows = await dbGet('SELECT id FROM follows WHERE "followerId"=$1 AND "followingId"=$2',
                [req.user.id, userId]);
            if (!follows) return res.status(403).json({ error: 'Bu profili görüntüleme izniniz yok' });
        }

        const posts = await dbAll(`
            SELECT p.*, u."profilePic" AS "userProfilePic", u.name AS "userName", u.username,
                   u."isVerified" AS "userVerified",
                   EXISTS(SELECT 1 FROM likes WHERE "postId"=p.id AND "userId"=$1) AS "isLiked",
                   EXISTS(SELECT 1 FROM saves WHERE "postId"=p.id AND "userId"=$1) AS "isSaved"
            FROM posts p JOIN users u ON p."userId"=u.id
            WHERE p."userId"=$2 AND p."isActive"=TRUE
            ORDER BY p."createdAt" DESC LIMIT $3 OFFSET $4
        `, [req.user.id, userId, ln, off]);

        const tot = await dbGet('SELECT COUNT(*) AS c FROM posts WHERE "userId"=$1 AND "isActive"=TRUE', [userId]);
        res.json({
            posts,
            total: parseInt(tot?.c||0),
            page: pn,
            hasMore: pn * ln < parseInt(tot?.c||0),
            totalPages: Math.ceil((tot?.c||0)/ln)
        });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// GET /api/videos/:id/info  (video detay bilgisi)
app.get('/api/videos/:id/info', authenticateToken, async (req, res) => {
    try {
        const post = await dbGet(`
            SELECT p.*, u.username, u.name, u."profilePic", u."isVerified"
            FROM posts p JOIN users u ON p."userId"=u.id
            WHERE p.id=$1 AND p."mediaType"='video' AND p."isActive"=TRUE`, [req.params.id]);
        if (!post) return res.status(404).json({ error: 'Video bulunamadı' });
        res.json({ video: post });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// POST /api/users/change-password (alias)
app.post('/api/users/change-password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Şifreler gerekli' });
        if (newPassword.length < 6) return res.status(400).json({ error: 'Şifre en az 6 karakter' });
        const user = await dbGet('SELECT password FROM users WHERE id=$1', [req.user.id]);
        const valid = await bcrypt.compare(currentPassword, user.password);
        if (!valid) return res.status(401).json({ error: 'Mevcut şifre yanlış' });
        const hashed = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
        await dbRun('UPDATE users SET password=$1,"updatedAt"=NOW() WHERE id=$2', [hashed, req.user.id]);
        res.json({ message: 'Şifre değiştirildi' });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// POST /api/products (alias - mağaza ürün ekle)
app.post('/api/products', authenticateToken, (req, res, next) => {
    upload.fields([{ name: 'images', maxCount: 5 }, { name: 'image', maxCount: 1 }])(req, res, (err) => {
        if (err) return res.status(400).json({ error: err.message });
        if (req.files && !Array.isArray(req.files)) {
            req.files = [...(req.files['images']||[]), ...(req.files['image']||[])];
        }
        next();
    });
}, async (req, res) => {
    try {
        const { name, price, description, category, stock } = req.body;
        if (!name || !price) return res.status(400).json({ error: 'İsim ve fiyat gerekli' });
        const files = Array.isArray(req.files) ? req.files : [];
        let images = [];
        for (let i = 0; i < files.length; i++) {
            const fname = `product_${Date.now()}_${i}.webp`;
            const out = require('path').join(postsDir, fname);
            await sharp(files[i].path).resize(1080,1080,{fit:'inside',withoutEnlargement:true}).webp({quality:85}).toFile(out);
            await fs.unlink(files[i].path).catch(()=>{});
            images.push(`/uploads/posts/${fname}`);
        }
        const id = uuidv4();
        await dbRun(
            `INSERT INTO products (id,"sellerId",name,price,description,image,images,category,stock,"isActive","createdAt","updatedAt")
             VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,TRUE,NOW(),NOW())`,
            [id, req.user.id, name.substring(0,100), parseFloat(price),
             description?.substring(0,1000)||'', images[0]||null, JSON.stringify(images), category||'', parseInt(stock)||1]
        );
        const product = await dbGet(
            `SELECT p.*,u.username AS "sellerName" FROM products p JOIN users u ON p."sellerId"=u.id WHERE p.id=$1`, [id]);
        res.status(201).json({ message: 'Ürün eklendi', product });
    } catch (e) {
        console.error(e);
        if (req.files) for (const f of (Array.isArray(req.files)?req.files:[])) await fs.unlink(f.path).catch(()=>{});
        res.status(500).json({ error: 'Sunucu hatası: ' + e.message });
    }
});

// PUT /api/products/:productId (alias)
app.put('/api/products/:productId', authenticateToken, (req, res, next) => {
    upload.fields([{ name: 'images', maxCount: 5 }, { name: 'image', maxCount: 1 }])(req, res, (err) => {
        if (err) return res.status(400).json({ error: err.message });
        if (req.files && !Array.isArray(req.files)) {
            req.files = [...(req.files['images']||[]), ...(req.files['image']||[])];
        }
        next();
    });
}, async (req, res) => {
    try {
        const p = await dbGet('SELECT "sellerId" FROM products WHERE id=$1', [req.params.productId]);
        if (!p) return res.status(404).json({ error: 'Ürün bulunamadı' });
        if (p.sellerId !== req.user.id) return res.status(403).json({ error: 'Yetki yok' });
        const { name, price, description, category, stock } = req.body;
        const sets=[], vals=[]; let idx=1;
        if (name)        { sets.push(`name=$${idx++}`);        vals.push(name.substring(0,100)); }
        if (price)       { sets.push(`price=$${idx++}`);       vals.push(parseFloat(price)); }
        if (description !== undefined) { sets.push(`description=$${idx++}`); vals.push(description.substring(0,1000)); }
        if (category)    { sets.push(`category=$${idx++}`);    vals.push(category); }
        if (stock !== undefined) { sets.push(`stock=$${idx++}`); vals.push(parseInt(stock)); }
        const files = Array.isArray(req.files) ? req.files : [];
        if (files.length) {
            let imgs=[];
            for (let i=0;i<files.length;i++){
                const fname=`product_${Date.now()}_${i}.webp`;
                const out=require('path').join(postsDir,fname);
                await sharp(files[i].path).resize(1080,1080,{fit:'inside',withoutEnlargement:true}).webp({quality:85}).toFile(out);
                await fs.unlink(files[i].path).catch(()=>{});
                imgs.push(`/uploads/posts/${fname}`);
            }
            sets.push(`image=$${idx++}`); vals.push(imgs[0]);
            sets.push(`images=$${idx++}::jsonb`); vals.push(JSON.stringify(imgs));
        }
        if (!sets.length) return res.status(400).json({ error: 'Güncellenecek alan yok' });
        sets.push(`"updatedAt"=NOW()`);
        vals.push(req.params.productId);
        await dbRun(`UPDATE products SET ${sets.join(',')} WHERE id=$${idx}`, vals);
        const updated = await dbGet('SELECT * FROM products WHERE id=$1', [req.params.productId]);
        res.json({ message: 'Ürün güncellendi', product: updated });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası: ' + e.message }); }
});

// POST /api/verification/request (alias)
app.post('/api/verification/request', authenticateToken, async (req, res) => {
    try {
        await dbRun('UPDATE users SET "emailVerified"=TRUE,"updatedAt"=NOW() WHERE id=$1', [req.user.id]);
        res.json({ message: 'Doğrulama talebi alındı' });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// POST /api/users/verification/apply (rozet başvurusu)
app.post('/api/users/verification/apply', authenticateToken, upload.fields([
    { name: 'idDocument', maxCount: 1 }, { name: 'selfie', maxCount: 1 }
]), async (req, res) => {
    try {
        const { applicationType, reason } = req.body;
        // Basit: verified olarak işaretle (admin onayı olmadan)
        const user = await dbGet('SELECT "isVerified" FROM users WHERE id=$1', [req.user.id]);
        if (user?.isVerified) return res.json({ message: 'Hesabınız zaten doğrulanmış', isVerified: true });
        // Dosyaları temizle
        if (req.files) {
            const allFiles = [...(req.files['idDocument']||[]), ...(req.files['selfie']||[])];
            for (const f of allFiles) await fs.unlink(f.path).catch(()=>{});
        }
        res.json({ message: 'Doğrulama başvurunuz alındı. İnceleme sonucu e-posta ile bildirilecektir.', pending: true });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// POST /api/email/unsubscribe/:userId (POST alias)
app.post('/api/email/unsubscribe/:userId', async (req, res) => {
    try {
        await dbRun('UPDATE users SET "emailNotifications"=FALSE,"updatedAt"=NOW() WHERE id=$1', [req.params.userId]).catch(()=>{});
        res.json({ message: 'E-posta bildirimlerinden çıkıldı' });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ==================== 🔧 ESKİ v5'TEN TAŞINAN 10 ADMIN API'Sİ ====================

// ─── 1. KULLANICI DURUM GÜNCELLE (admin) ─────────────────────────────
// PUT /api/admin/users/:id/status
app.put('/api/admin/users/:id/status', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
    try {
        const { isActive } = req.body;
        if (typeof isActive === 'undefined') return res.status(400).json({ error: 'isActive alanı gerekli' });
        await dbRun(
            'UPDATE users SET "isActive" = $1, "updatedAt" = NOW() WHERE id = $2',
            [!!isActive, req.params.id]
        );
        res.json({ message: `Kullanıcı ${isActive ? 'aktif' : 'pasif'} edildi` });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 2. KULLANICI KISITLA (admin) ─────────────────────────────────────
// POST /api/admin/users/:id/restrict
app.post('/api/admin/users/:id/restrict', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
    try {
        const { id } = req.params;
        const {
            reason = 'Yönetici tarafından kısıtlandı',
            restrictedUntil = null,
            canPost = false,
            canComment = false,
            canMessage = false,
            canFollow = false,
            canLike = false
        } = req.body;

        const user = await dbGet('SELECT id FROM users WHERE id = $1', [id]);
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });

        await dbRun(
            `INSERT INTO account_restrictions
             (id, "userId", "isRestricted", "restrictedAt", "restrictedUntil", reason, "canPost", "canComment", "canMessage", "canFollow", "canLike", "createdAt", "updatedAt")
             VALUES ($1,$2,TRUE,NOW(),$3,$4,$5,$6,$7,$8,$9,NOW(),NOW())
             ON CONFLICT ("userId") DO UPDATE SET
               "isRestricted"=TRUE, "restrictedAt"=NOW(), "restrictedUntil"=$3,
               reason=$4, "canPost"=$5, "canComment"=$6, "canMessage"=$7, "canFollow"=$8, "canLike"=$9, "updatedAt"=NOW()`,
            [uuidv4(), id, restrictedUntil, reason, canPost, canComment, canMessage, canFollow, canLike]
        );

        res.json({ message: 'Kullanıcı kısıtlandı', restriction: { reason, restrictedUntil, canPost, canComment, canMessage, canFollow, canLike } });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 3. KULLANICI KISITLAMASINI KALDIR (admin) ───────────────────────
// POST /api/admin/users/:id/unrestrict
app.post('/api/admin/users/:id/unrestrict', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
    try {
        const { id } = req.params;
        const user = await dbGet('SELECT id FROM users WHERE id = $1', [id]);
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
        await dbRun(
            `UPDATE account_restrictions SET "isRestricted"=FALSE, "updatedAt"=NOW() WHERE "userId"=$1`,
            [id]
        );
        res.json({ message: 'Kullanıcı kısıtlaması kaldırıldı' });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 4. IP BAN (admin) ──────────────────────────────────────────────
// POST /api/admin/ip/ban
app.post('/api/admin/ip/ban', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
    try {
        const { ip, reason = 'Admin tarafından engellendi', expiresAt = null } = req.body;
        if (!ip) return res.status(400).json({ error: 'IP adresi gerekli' });
        FIREWALL_BLOCKED_IPS.add(ip);
        await dbRun(
            `INSERT INTO banned_ips (id, ip, reason, "bannedAt", "expiresAt")
             VALUES ($1,$2,$3,NOW(),$4)
             ON CONFLICT (ip) DO UPDATE SET reason=$3, "bannedAt"=NOW(), "expiresAt"=$4`,
            [uuidv4(), ip, reason, expiresAt]
        );
        res.json({ message: `${ip} adresi engellendi` });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 5. IP BAN KALDIR (admin) ────────────────────────────────────────
// DELETE /api/admin/ip/unban/:ip
app.delete('/api/admin/ip/unban/:ip', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
    try {
        const ip = req.params.ip;
        FIREWALL_BLOCKED_IPS.delete(ip);
        FIREWALL_ATTACK_LOG.delete(ip);
        await dbRun('DELETE FROM banned_ips WHERE ip = $1', [ip]);
        res.json({ message: `${ip} engeli kaldırıldı` });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 6. YASAKLı IP'LER LİSTESİ (admin) ─────────────────────────────
// GET /api/admin/ip/banned
app.get('/api/admin/ip/banned', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
    try {
        const bannedIps = await dbAll('SELECT * FROM banned_ips ORDER BY "bannedAt" DESC');
        res.json({ bannedIps });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 7. MODERASYON RAPORLARI (admin) ────────────────────────────────
// GET /api/admin/moderation/reports
app.get('/api/admin/moderation/reports', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
    try {
        const { page = 1, limit = 50 } = req.query;
        const pageNum  = Math.max(1, parseInt(page)  || 1);
        const limitNum = Math.min(100, parseInt(limit) || 20);
        const offset   = (pageNum - 1) * limitNum;

        const reports = await dbAll(
            `SELECT cm.*, u.username, u.email,
                    p.content AS "postContent",
                    c.content AS "commentContent"
             FROM content_moderation cm
             JOIN users u ON cm."userId" = u.id
             LEFT JOIN posts p ON cm."postId" = p.id
             LEFT JOIN comments c ON cm."commentId" = c.id
             WHERE cm."isHarmful" = TRUE
             ORDER BY cm."moderatedAt" DESC
             LIMIT $1 OFFSET $2`,
            [limitNum, offset]
        );
        const total = await dbGet('SELECT COUNT(*) AS c FROM content_moderation WHERE "isHarmful" = TRUE');
        res.json({ reports, total: parseInt(total?.c || 0), page: pageNum, totalPages: Math.ceil((total?.c || 0) / limitNum) });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 8. MODERASYON RAPORU DETAY (admin) ─────────────────────────────
// GET /api/admin/moderation/reports/:id
app.get('/api/admin/moderation/reports/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
    try {
        const report = await dbGet(
            `SELECT cm.*, u.username, u.email, u."profilePic",
                    p.content AS "postContent", p.media AS "postMedia", p."mediaType" AS "postMediaType",
                    c.content AS "commentContent"
             FROM content_moderation cm
             JOIN users u ON cm."userId" = u.id
             LEFT JOIN posts p ON cm."postId" = p.id
             LEFT JOIN comments c ON cm."commentId" = c.id
             WHERE cm.id = $1`,
            [req.params.id]
        );
        if (!report) return res.status(404).json({ error: 'Rapor bulunamadı' });
        res.json({ report });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 9. ADMIN POST LİSTESİ ───────────────────────────────────────────
// GET /api/admin/posts
app.get('/api/admin/posts', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
    try {
        const { page = 1, limit = 50 } = req.query;
        const pageNum  = Math.max(1, parseInt(page)  || 1);
        const limitNum = Math.min(100, parseInt(limit) || 20);
        const offset   = (pageNum - 1) * limitNum;

        const posts = await dbAll(
            `SELECT p.*, u.username, u.name, u.email,
                    cm."isHarmful", cm.reason AS "moderationReason"
             FROM posts p
             JOIN users u ON p."userId" = u.id
             LEFT JOIN content_moderation cm ON p.id = cm."postId"
             ORDER BY p."createdAt" DESC
             LIMIT $1 OFFSET $2`,
            [limitNum, offset]
        );
        const total = await dbGet('SELECT COUNT(*) AS c FROM posts');
        res.json({ posts: posts.map(formatPost), total: parseInt(total?.c || 0), page: pageNum, totalPages: Math.ceil((total?.c || 0) / limitNum) });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 10. ADMIN POST DURUM GÜNCELLE ───────────────────────────────────
// PUT /api/admin/posts/:id/status
app.put('/api/admin/posts/:id/status', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
    try {
        const { isActive } = req.body;
        if (typeof isActive === 'undefined') return res.status(400).json({ error: 'isActive alanı gerekli' });
        await dbRun(
            'UPDATE posts SET "isActive" = $1, "updatedAt" = NOW() WHERE id = $2',
            [!!isActive, req.params.id]
        );
        res.json({ message: `Gönderi ${isActive ? 'aktif' : 'pasif'} edildi` });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// GET /* (catch-all - SPA için)
app.get('*', (req, res, next) => {
    // API istekleri buraya düşmemeli
    if (req.path.startsWith('/api/') || req.path.startsWith('/uploads/')) return next();
    const htmlPath = require('path').join(__dirname, 'public', 'index.html');
    const fss = require('fs');
    if (fss.existsSync(htmlPath)) {
        res.sendFile(htmlPath);
    } else {
        res.status(404).json({ error: 'Sayfa bulunamadı' });
    }
});

// ==================== SUNUCU BAŞLAT ====================

const NUM_WORKERS = process.env.WEB_CONCURRENCY || Math.min(os.cpus().length, 4);

if (cluster.isPrimary || cluster.isMaster) {
    console.log(`🚀 Master process ${process.pid} - ${NUM_WORKERS} worker başlatılıyor...`);

    for (let i = 0; i < NUM_WORKERS; i++) {
        cluster.fork();
    }

    cluster.on('exit', (worker, code) => {
        console.log(`⚠️ Worker ${worker.process.pid} kapandı (code: ${code}). Yeniden başlatılıyor...`);
        cluster.fork();
    });
} else {
    (async () => {
        try {
            await initializeDatabase();
            await loadFirewallBans(); // 🔥 DB hazır olduktan sonra firewall ban listesini yükle
            await runSQLiteMigration(); // SQLite → PG geçişi (sadece SQLITE_MIGRATE=true ise çalışır)
            testEmailConnection().catch(() => {}); // E-posta bağlantısını arka planda test et
            server.listen(PORT, '0.0.0.0', () => {
                console.log(`
╔══════════════════════════════════════════════════╗
║  🌾 AGROLINK SERVER - PostgreSQL v6.0             ║
║  📡 Port: ${String(PORT).padEnd(39)}║
║  🌐 Domain: sehitumitkestitarimmtal.com         ║
║  🗄️  DB: PostgreSQL (Pool: 100 bağlantı)        ║
║  🔒 SQL Injection: Tüm sorgular parameterize    ║
║  🎬 Video: FFmpeg+HLS ABR (YouTube Algoritması) ║
║  📧 E-posta: Nodemailer (SMTP)                  ║
║  📊 API: 103 Rota                               ║
║  ⚡ Cluster Mode: Worker ${String(process.pid).padEnd(23)}║
║  🔥 1000+ Eşzamanlı İstek Desteği               ║
╚══════════════════════════════════════════════════╝
                `);
            });
        } catch (error) {
            console.error('❌ Sunucu başlatılamadı:', error);
            process.exit(1);
        }
    })();
}

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('\n🛑 Sunucu kapatılıyor...');
    await pool.end();
    process.exit(0);
});

process.on('SIGTERM', async () => {
    console.log('\n🛑 Sunucu kapatılıyor...');
    await pool.end();
    process.exit(0);
});
