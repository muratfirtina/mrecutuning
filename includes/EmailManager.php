<?php
/**
 * Mr ECU - Email Manager Class with PHPMailer
 * Email Yönetimi ve Gönderme Sınıfı - PHPMailer ile
 * CLEAN VERSION - Duplicate metodlar temizlendi
 */

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

require_once __DIR__ . '/../vendor/autoload.php';

class EmailManager {
    private $pdo;
    private $smtp_host;
    private $smtp_port;
    private $smtp_username;
    private $smtp_password;
    private $smtp_encryption;
    private $from_email;
    private $from_name;
    private $debug_mode;
    
    public function __construct($database) {
        $this->pdo = $database;
        $this->loadEmailConfig();
    }
    
    /**
     * Email konfigürasyonunu yükle (.env dosyasından)
     */
    private function loadEmailConfig() {
        $this->smtp_host = getenv('SMTP_HOST');
        $this->smtp_port = getenv('SMTP_PORT');
        $this->smtp_username = getenv('SMTP_USERNAME');
        $this->smtp_password = getenv('SMTP_PASSWORD');
        $this->smtp_encryption = getenv('SMTP_ENCRYPTION');
        $this->from_email = getenv('SMTP_FROM_EMAIL');
        $this->from_name = getenv('SMTP_FROM_NAME');
        $this->debug_mode = getenv('DEBUG') === 'true';
        
        error_log('Email config loaded: Host=' . $this->smtp_host . ', Port=' . $this->smtp_port . ', User=' . $this->smtp_username);
    }
    
    /**
     * PHPMailer nesnesi oluştur
     */
    private function createMailer() {
        $mail = new PHPMailer(true);
        
        try {
            // Server ayarları
            $mail->isSMTP();
            $mail->Host       = $this->smtp_host;
            $mail->SMTPAuth   = true;
            $mail->Username   = $this->smtp_username;
            $mail->Password   = $this->smtp_password;
            $mail->SMTPSecure = $this->smtp_encryption;
            $mail->Port       = $this->smtp_port;
            $mail->CharSet    = 'UTF-8';
            
            // Debug modu
            if ($this->debug_mode) {
                $mail->SMTPDebug = SMTP::DEBUG_SERVER;
                $mail->Debugoutput = function($str, $level) {
                    error_log("PHPMailer Debug: $str");
                };
            }
            
            // Gönderen bilgileri
            $mail->setFrom($this->from_email, $this->from_name);
            $mail->addReplyTo($this->from_email, $this->from_name);
            
            return $mail;
            
        } catch (Exception $e) {
            error_log('PHPMailer Mailer oluşturulamadı: ' . $e->getMessage());
            throw $e;
        }
    }
    
    /**
     * Email gönder (PHPMailer ile)
     */
    public function sendEmail($to, $subject, $body, $isHTML = true, $attachments = []) {
        try {
            $mail = $this->createMailer();
            
            // Alıcı
            $mail->addAddress($to);
            
            // İçerik
            $mail->isHTML($isHTML);
            $mail->Subject = $subject;
            $mail->Body    = $body;
            
            if (!$isHTML) {
                $mail->AltBody = strip_tags($body);
            }
            
            // Ekler
            foreach ($attachments as $attachment) {
                if (is_array($attachment)) {
                    $mail->addAttachment($attachment['path'], $attachment['name'] ?? '');
                } else {
                    $mail->addAttachment($attachment);
                }
            }
            
            // Gönder
            $result = $mail->send();
            
            if ($result) {
                error_log("Email başarıyla gönderildi: $to - Subject: $subject");
                $this->logEmailSent($to, $subject, 'sent');
                return true;
            } else {
                error_log("Email gönderilemedi: $to - Subject: $subject");
                $this->logEmailSent($to, $subject, 'failed', 'PHPMailer send() returned false');
                return false;
            }
            
        } catch (Exception $e) {
            error_log("Email gönderme hatası: {$e->getMessage()}");
            $this->logEmailSent($to, $subject, 'failed', $e->getMessage());
            $this->logEmailForTesting($to, $subject, $body, $isHTML, $e->getMessage());
            return false;
        }
    }
    
    /**
     * Test amaçlı email log'lama
     */
    private function logEmailForTesting($to, $subject, $body, $isHTML, $error = null) {
        try {
            $logDir = __DIR__ . '/../logs';
            if (!is_dir($logDir)) {
                mkdir($logDir, 0755, true);
            }
            
            $logFile = $logDir . '/email_test.log';
            $timestamp = date('Y-m-d H:i:s');
            
            $logContent = "\n" . str_repeat('=', 80) . "\n";
            $logContent .= "EMAIL LOG - {$timestamp}\n";
            $logContent .= str_repeat('=', 80) . "\n";
            $logContent .= "To: {$to}\n";
            $logContent .= "Subject: {$subject}\n";
            $logContent .= "Type: " . ($isHTML ? 'HTML' : 'Plain Text') . "\n";
            $logContent .= "From: {$this->from_name} <{$this->from_email}>\n";
            $logContent .= "SMTP Host: {$this->smtp_host}:{$this->smtp_port}\n";
            
            if ($error) {
                $logContent .= "ERROR: {$error}\n";
            }
            
            $logContent .= str_repeat('-', 80) . "\n";
            $logContent .= "Body:\n{$body}\n";
            $logContent .= str_repeat('=', 80) . "\n\n";
            
            file_put_contents($logFile, $logContent, FILE_APPEND | LOCK_EX);
            return true;
            
        } catch (Exception $e) {
            error_log("Email test logging failed: {$e->getMessage()}");
            return false;
        }
    }
    
    /**
     * Email gönderim kaydı
     */
    private function logEmailSent($to, $subject, $status, $error = null) {
        try {
            $stmt = $this->pdo->prepare("
                INSERT INTO email_queue (id, to_email, subject, body, status, error_message, created_at, sent_at) 
                VALUES (?, ?, ?, ?, ?, ?, NOW(), NOW())
            ");
            
            $emailId = generateUUID();
            $stmt->execute([$emailId, $to, $subject, '', $status, $error]);
            
        } catch(PDOException $e) {
            error_log('Email log failed (table may not exist): ' . $e->getMessage());
        }
    }
    
    /**
     * Verification email gönder
     */
    public function sendVerificationEmail($userEmail, $userName, $verificationToken) {
        $subject = 'Mr ECU - Email Adresinizi Doğrulayın';
        $verificationUrl = (getenv('SITE_URL') ?: 'http://localhost') . '/verify.php?token=' . $verificationToken;
        
        $body = "
        <html>
        <head>
            <meta charset='UTF-8'>
            <title>Email Doğrulama</title>
        </head>
        <body style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>
            <h2 style='color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;'>
                📧 Email Adresinizi Doğrulayın
            </h2>
            
            <div style='background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;'>
                <h3 style='color: #2c3e50; margin-top: 0;'>Merhaba {$userName},</h3>
                <p>Hesabınızı aktifleştirmek için email adresinizi doğrulamanız gerekmektedir.</p>
            </div>
            
            <div style='text-align: center; margin: 30px 0;'>
                <a href='{$verificationUrl}' 
                   style='background: #3498db; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block;'>
                    Email Adresimi Doğrula
                </a>
            </div>
            
            <p style='color: #7f8c8d; font-size: 12px; margin-top: 30px;'>
                Bu bağlantı 24 saat geçerlidir.<br>
                Bu email otomatik olarak gönderilmiştir.
            </p>
        </body>
        </html>";
        
        return $this->sendEmail($userEmail, $subject, $body, true);
    }
    
    /**
     * Password reset email gönder
     */
    public function sendPasswordResetEmail($userEmail, $userName, $resetCode) {
        $subject = 'Mr ECU - Şifre Sıfırlama Kodu';
        
        $body = "
        <html>
        <head>
            <meta charset='UTF-8'>
            <title>Şifre Sıfırlama</title>
        </head>
        <body style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>
            <h2 style='color: #e74c3c; border-bottom: 2px solid #e74c3c; padding-bottom: 10px;'>
                🔑 Şifre Sıfırlama Kodu
            </h2>
            
            <div style='background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;'>
                <h3 style='color: #2c3e50; margin-top: 0;'>Merhaba {$userName},</h3>
                <p>Şifre sıfırlama talebiniz için doğrulama kodunuz:</p>
                <h2 style='text-align: center; background: #e74c3c; color: white; padding: 15px; border-radius: 5px; letter-spacing: 3px;'>{$resetCode}</h2>
            </div>
            
            <p style='color: #7f8c8d; font-size: 12px; margin-top: 30px;'>
                Bu kod 15 dakika geçerlidir.<br>
                Eğer bu talebi siz yapmadıysanız bu emaili görmezden gelebilirsiniz.
            </p>
        </body>
        </html>";
        
        return $this->sendEmail($userEmail, $subject, $body, true);
    }
    
    /**
     * Test email gönder
     */
    public function sendTestEmail($to) {
        $subject = 'Mr ECU - Email Test';
        $body = '
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Email Test</title>
        </head>
        <body>
            <h2>Email Test - Mr ECU</h2>
            <p>Bu bir test emailidir.</p>
            <p>Eğer bu emaili alıyorsanız, email sistemi doğru çalışıyor demektir.</p>
            <p><strong>Test Bilgileri:</strong></p>
            <ul>
                <li>SMTP Host: ' . $this->smtp_host . '</li>
                <li>SMTP Port: ' . $this->smtp_port . '</li>
                <li>Gönderim Zamanı: ' . date('d.m.Y H:i:s') . '</li>
            </ul>
            <hr>
            <p><small>Mr ECU - Otomatik Email Sistemi</small></p>
        </body>
        </html>';
        
        return $this->sendEmail($to, $subject, $body, true);
    }
    
    /**
     * Kullanıcı dosya yüklediğinde admin'e bildirim gönder
     */
    public function sendFileUploadNotificationToAdmin($emailData, $adminEmail = null) {
        try {
            if (!$adminEmail) {
                $stmt = $this->pdo->prepare("SELECT email FROM users WHERE role = 'admin' AND email_verified = 1");
                $stmt->execute();
                $adminEmails = $stmt->fetchAll(PDO::FETCH_COLUMN);
                
                $success = true;
                foreach ($adminEmails as $email) {
                    $result = $this->sendFileUploadNotificationToAdmin($emailData, $email);
                    if (!$result) $success = false;
                }
                return $success;
            }
            
            $subject = 'Yeni Dosya Yüklendi - ' . $emailData['file_name'];
            
            $body = "
            <div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>
                <h2 style='color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;'>
                    📎 Yeni Dosya Yüklendi
                </h2>
                
                <div style='background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;'>
                    <h3 style='color: #2c3e50; margin-top: 0;'>Kullanıcı Bilgileri</h3>
                    <p><strong>Ad Soyad:</strong> {$emailData['user_name']}</p>
                    <p><strong>Email:</strong> {$emailData['user_email']}</p>
                    <p><strong>Telefon:</strong> {$emailData['user_phone']}</p>
                </div>
                
                <div style='background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;'>
                    <h3 style='color: #2c3e50; margin-top: 0;'>Dosya Bilgileri</h3>
                    <p><strong>Dosya Adı:</strong> {$emailData['file_name']}</p>
                    <p><strong>Yükleme Tarihi:</strong> {$emailData['upload_time']}</p>
                    <p><strong>Notlar:</strong> {$emailData['upload_notes']}</p>
                </div>
                
                <div style='background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;'>
                    <h3 style='color: #2c3e50; margin-top: 0;'>Araç Bilgileri</h3>
                    <p><strong>Plaka:</strong> {$emailData['plate']}</p>
                    <p><strong>Marka:</strong> {$emailData['vehicle_brand']}</p>
                    <p><strong>Model:</strong> {$emailData['vehicle_model']}</p>
                    <p><strong>Seri:</strong> {$emailData['vehicle_series']}</p>
                    <p><strong>Motor:</strong> {$emailData['vehicle_engine']}</p>
                    <p><strong>Yakıt Tipi:</strong> {$emailData['fuel_type']}</p>
                    <p><strong>Vites Tipi:</strong> {$emailData['gearbox_type']}</p>
                </div>
                
                <div style='text-align: center; margin: 30px 0;'>
                    <a href='{$emailData['admin_url']}' 
                       style='background: #3498db; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block;'>
                        Dosyayı İncele
                    </a>
                </div>
                
                <p style='color: #7f8c8d; font-size: 12px; margin-top: 30px;'>
                    Bu email otomatik olarak gönderilmiştir. Lütfen yanıtlamayınız.
                </p>
            </div>
            ";
            
            return $this->sendEmail($adminEmail, $subject, $body);
            
        } catch (Exception $e) {
            error_log('sendFileUploadNotificationToAdmin error: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Admin yanıt dosyası yüklediğinde kullanıcıya bildirim gönder
     */
    public function sendFileResponseNotificationToUser($emailData, $userEmail = null) {
        try {
            if (!$userEmail && isset($emailData['user_email'])) {
                $userEmail = $emailData['user_email'];
            }
            
            if (!$userEmail) {
                error_log('sendFileResponseNotificationToUser: User email not provided');
                return false;
            }
            
            $subject = 'Dosyanız Hazır! - ' . $emailData['original_file_name'];
            
            $body = "
            <div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>
                <h2 style='color: #27ae60; border-bottom: 2px solid #27ae60; padding-bottom: 10px;'>
                    ✓ Dosyanız Tamamlandı!
                </h2>
                
                <div style='background: #d5f4e6; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #27ae60;'>
                    <h3 style='color: #2c3e50; margin-top: 0;'>Merhaba {$emailData['user_name']},</h3>
                    <p>Yüklemiş olduğunuz <strong>{$emailData['plate']}</strong> plakasına ait <strong>{$emailData['original_file_name']}</strong> dosyası işleme alındı ve tamamlandı.</p>
                </div>
                
                <div style='background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;'>
                    <h3 style='color: #2c3e50; margin-top: 0;'>Yanıt Dosyası</h3>
                    <p><strong>Plaka:</strong> {$emailData['plate']}</p>
                    <p><strong>Dosya Adı:</strong> {$emailData['response_file_name']}</p>
                    <p><strong>Tamamlanma Tarihi:</strong> {$emailData['response_time']}</p>
                    " . (isset($emailData['admin_notes']) && $emailData['admin_notes'] ? "<p><strong>Admin Notları:</strong> {$emailData['admin_notes']}</p>" : "") . "
                </div>
                
                <div style='text-align: center; margin: 30px 0;'>
                    <a href='{$emailData['download_url']}' 
                       style='background: #27ae60; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block;'>
                        Dosyayı İndir
                    </a>
                </div>
                
                <div style='background: #fff3cd; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #ffc107;'>
                    <p style='margin: 0; color: #856404;'>
                        <strong>⚠️ Önemli:</strong> Dosyanızı en kısa sürede indirmeyi unutmayınız.
                    </p>
                </div>
                
                <p style='color: #7f8c8d; font-size: 12px; margin-top: 30px;'>
                    Herhangi bir sorunuz varsa bizimle iletişime geçebilirsiniz.<br>
                    Bu email otomatik olarak gönderilmiştir.
                </p>
            </div>
            ";
            
            return $this->sendEmail($userEmail, $subject, $body);
            
        } catch (Exception $e) {
            error_log('sendFileResponseNotificationToUser error: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Kullanıcı revizyon talep ettiğinde admin'e bildirim gönder
     */
    public function sendRevisionRequestNotificationToAdmin($emailData, $adminEmail = null) {
        try {
            if (!$adminEmail) {
                $stmt = $this->pdo->prepare("SELECT email FROM users WHERE role = 'admin' AND email_verified = 1");
                $stmt->execute();
                $adminEmails = $stmt->fetchAll(PDO::FETCH_COLUMN);
                
                $success = true;
                foreach ($adminEmails as $email) {
                    $result = $this->sendRevisionRequestNotificationToAdmin($emailData, $email);
                    if (!$result) $success = false;
                }
                return $success;
            }
            
            $subject = 'Revizyon Talebi - ' . $emailData['file_name'];
            
            $body = "
            <div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>
                <h2 style='color: #e74c3c; border-bottom: 2px solid #e74c3c; padding-bottom: 10px;'>
                    🔄 Revizyon Talebi
                </h2>
                
                <div style='background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;'>
                    <h3 style='color: #2c3e50; margin-top: 0;'>Kullanıcı Bilgileri</h3>
                    <p><strong>Ad Soyad:</strong> {$emailData['user_name']}</p>
                    <p><strong>Email:</strong> {$emailData['user_email']}</p>
                </div>
                
                <div style='background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;'>
                    <h3 style='color: #2c3e50; margin-top: 0;'>Dosya Bilgileri</h3>
                    <p><strong>Dosya Adı:</strong> {$emailData['file_name']}</p>
                    <p><strong>Talep Tarihi:</strong> {$emailData['request_time']}</p>
                </div>
                
                <div style='background: #fff3cd; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #ffc107;'>
                    <h3 style='color: #856404; margin-top: 0;'>Revizyon Notları</h3>
                    <p style='color: #856404;'>{$emailData['revision_notes']}</p>
                </div>
                
                <div style='text-align: center; margin: 30px 0;'>
                    <a href='{$emailData['admin_url']}' 
                       style='background: #e74c3c; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block;'>
                        Revizyon Talebini İncele
                    </a>
                </div>
                
                <p style='color: #7f8c8d; font-size: 12px; margin-top: 30px;'>
                    Bu email otomatik olarak gönderilmiştir. Lütfen yanıtlamayınız.
                </p>
            </div>
            ";
            
            return $this->sendEmail($adminEmail, $subject, $body);
            
        } catch (Exception $e) {
            error_log('sendRevisionRequestNotificationToAdmin error: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Dosya durumu güncellendiğinde kullanıcıya bildirim gönder
     */
    public function sendFileStatusUpdateNotificationToUser($emailData) {
        try {
            $statusColors = [
                'processing' => '#3498db',
                'completed' => '#27ae60',
                'rejected' => '#e74c3c'
            ];
            
            $statusIcons = [
                'processing' => '⏳',
                'completed' => '✓',
                'rejected' => '❌'
            ];
            
            $color = $statusColors[$emailData['status']] ?? '#3498db';
            $icon = $statusIcons[$emailData['status']] ?? '📄';
            
            $subject = 'Dosya Durumu Güncellendi - ' . $emailData['file_name'];
            
            $body = "
            <div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>
                <h2 style='color: {$color}; border-bottom: 2px solid {$color}; padding-bottom: 10px;'>
                    {$icon} {$emailData['status_message']}
                </h2>
                
                <div style='background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;'>
                    <h3 style='color: #2c3e50; margin-top: 0;'>Merhaba {$emailData['user_name']},</h3>
                    <p>Yüklemiş olduğunuz <strong>{$emailData['plate']}</strong> plakasına ait <strong>{$emailData['file_name']}</strong> dosyasının durumu güncellendi.</p>
                </div>
                
                <div style='background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;'>
                    <h3 style='color: #2c3e50; margin-top: 0;'>Güncelleme Bilgileri</h3>
                    <p><strong>Yeni Durum:</strong> <span style='color: {$color};'>{$emailData['status_message']}</span></p>
                    <p><strong>Güncelleme Tarihi:</strong> {$emailData['update_time']}</p>
                    " . (isset($emailData['admin_notes']) && $emailData['admin_notes'] ? "<p><strong>Admin Notları:</strong> {$emailData['admin_notes']}</p>" : "") . "
                </div>
                
                <div style='text-align: center; margin: 30px 0;'>
                    <a href='{$emailData['user_dashboard_url']}' 
                       style='background: {$color}; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block;'>
                        Dosyalarımı Gör
                    </a>
                </div>
                
                <p style='color: #7f8c8d; font-size: 12px; margin-top: 30px;'>
                    Herhangi bir sorunuz varsa bizimle <a href='{$emailData['contact_url']}' style='color: #3498db;'>iletişime geçebilirsiniz</a>.<br>
                    Bu email otomatik olarak gönderilmiştir.
                </p>
            </div>
            ";
            
            return $this->sendEmail($emailData['user_email'], $subject, $body);
            
        } catch (Exception $e) {
            error_log('sendFileStatusUpdateNotificationToUser error: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Ek dosya bildirimini gönder
     */
    public function sendAdditionalFileNotification($emailData, $isToAdmin = true) {
        try {
            $recipientEmail = $emailData['receiver_email'];
            $recipientName = $isToAdmin ? 'Admin' : $emailData['receiver_name'];
            
            $subject = 'Yeni Ek Dosya - ' . $emailData['file_name'];
            
            $body = "
            <div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>
                <h2 style='color: #8e44ad; border-bottom: 2px solid #8e44ad; padding-bottom: 10px;'>
                    📁 Yeni Ek Dosya
                </h2>
                
                <div style='background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;'>
                    <h3 style='color: #2c3e50; margin-top: 0;'>Merhaba {$recipientName},</h3>
                    <p><strong>{$emailData['sender_name']}</strong> size yeni bir dosya gönderdi.</p>
                </div>
                
                <div style='background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;'>
                    <h3 style='color: #2c3e50; margin-top: 0;'>Dosya Bilgileri</h3>
                    <p><strong>Plaka:</strong> {$emailData['plate']}</p>
                    <p><strong>Dosya Adı:</strong> {$emailData['file_name']}</p>
                    <p><strong>Gönderim Tarihi:</strong> {$emailData['upload_time']}</p>
                    <p><strong>İlgili Dosya:</strong> {$emailData['related_file_name']}</p>
                    " . (isset($emailData['notes']) && $emailData['notes'] ? "<p><strong>Notlar:</strong> {$emailData['notes']}</p>" : "") . "
                </div>
                
                <div style='text-align: center; margin: 30px 0;'>
                    <a href='" . ($isToAdmin ? $emailData['admin_url'] : $emailData['download_url']) . "' 
                       style='background: #8e44ad; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block;'>
                        Dosyayı Gör
                    </a>
                </div>
                
                <p style='color: #7f8c8d; font-size: 12px; margin-top: 30px;'>
                    Bu email otomatik olarak gönderilmiştir.
                </p>
            </div>
            ";
            
            return $this->sendEmail($recipientEmail, $subject, $body);
            
        } catch (Exception $e) {
            error_log('sendAdditionalFileNotification error: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Email gönderim öncesi kontroller
     */
    public function checkEmailSendability($toEmail) {
        try {
            if (!filter_var($toEmail, FILTER_VALIDATE_EMAIL)) {
                return [
                    'sendable' => false,
                    'reason' => 'invalid_format',
                    'message' => 'Geçersiz email formatı'
                ];
            }
            
            return [
                'sendable' => true,
                'reason' => 'valid_email',
                'message' => 'Email gönderilebilir'
            ];
            
        } catch (Exception $e) {
            error_log('checkEmailSendability error: ' . $e->getMessage());
            return [
                'sendable' => false,
                'reason' => 'check_error',
                'message' => 'Email kontrol hatası: ' . $e->getMessage()
            ];
        }
    }
    
    /**
     * Güvenli email gönderim (kontroller ile)
     */
    public function sendEmailSafely($toEmail, $subject, $body, $skipChecks = false) {
        if (!$skipChecks) {
            $checkResult = $this->checkEmailSendability($toEmail);
            if (!$checkResult['sendable']) {
                return [
                    'success' => false,
                    'message' => $checkResult['message'],
                    'reason' => $checkResult['reason']
                ];
            }
        }
        
        $sendResult = $this->sendEmail($toEmail, $subject, $body);
        
        return [
            'success' => $sendResult,
            'message' => $sendResult ? 'Email başarıyla gönderildi' : 'Email gönderilemedi',
            'reason' => $sendResult ? 'sent' : 'send_failed'
        ];
    }
    
    /**
     * Email kuyruğundan email gönder (cron job metodları için)
     * Bu metod email_queue tablosundan gelen array formatındaki emaili gönderir
     */
    public function sendQueuedEmail($emailData) {
        try {
            // Email verilerini hazırla
            $to = $emailData['to_email'] ?? null;
            $subject = $emailData['subject'] ?? 'No Subject';
            $body = $emailData['body'] ?? '';
            $isHTML = ($emailData['is_html'] ?? 1) == 1;
            
            if (!$to) {
                error_log('sendQueuedEmail: Email adresi bulunamadı');
                return false;
            }
            
            // Email'i gönder
            $result = $this->sendEmail($to, $subject, $body, $isHTML);
            
            if ($result) {
                error_log("Kuyruktaki email başarıyla gönderildi: {$to} - {$subject}");
            } else {
                error_log("Kuyruktaki email gönderilemedi: {$to} - {$subject}");
            }
            
            return $result;
            
        } catch (Exception $e) {
            error_log('sendQueuedEmail hatası: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Email kuyruğunu işle (process_email_queue.php için)
     * Belirtilen sayıda pending email'i işler
     */
    public function processEmailQueue($limit = 10) {
        try {
            $processedCount = 0;
            
            // Bekleyen email'leri getir
            $stmt = $this->pdo->prepare("
                SELECT * FROM email_queue 
                WHERE status = 'pending' 
                AND (processing_started_at IS NULL OR processing_started_at < DATE_SUB(NOW(), INTERVAL 10 MINUTE))
                AND (next_attempt_at IS NULL OR next_attempt_at <= NOW())
                ORDER BY 
                    CASE priority 
                        WHEN 'high' THEN 1 
                        WHEN 'normal' THEN 2 
                        WHEN 'low' THEN 3 
                        ELSE 2 
                    END, 
                    created_at ASC
                LIMIT ?
            ");
            $stmt->execute([$limit]);
            $emails = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            if (empty($emails)) {
                return 0;
            }
            
            foreach ($emails as $email) {
                try {
                    // Email'i işleme alma
                    $lockStmt = $this->pdo->prepare("
                        UPDATE email_queue 
                        SET processing_started_at = NOW() 
                        WHERE id = ? AND status = 'pending'
                    ");
                    $lockStmt->execute([$email['id']]);
                    
                    if ($lockStmt->rowCount() == 0) {
                        continue; // Başka bir process zaten işledi
                    }
                    
                    // Email'i gönder
                    $result = $this->sendQueuedEmail($email);
                    
                    if ($result) {
                        // Başarılı - durumu güncelle
                        $updateStmt = $this->pdo->prepare("
                            UPDATE email_queue 
                            SET status = 'sent', 
                                sent_at = NOW(), 
                                processing_started_at = NULL, 
                                error_message = NULL 
                            WHERE id = ?
                        ");
                        $updateStmt->execute([$email['id']]);
                        $processedCount++;
                    } else {
                        // Başarısız - deneme sayısını artır
                        $attempts = ($email['attempts'] ?? 0) + 1;
                        $maxAttempts = $email['max_attempts'] ?? 3;
                        
                        if ($attempts >= $maxAttempts) {
                            // Maksimum deneme aşıldı - failed olarak işaretle
                            $updateStmt = $this->pdo->prepare("
                                UPDATE email_queue 
                                SET status = 'failed', 
                                    attempts = ?, 
                                    error_message = 'Maximum attempts reached', 
                                    processing_started_at = NULL 
                                WHERE id = ?
                            ");
                            $updateStmt->execute([$attempts, $email['id']]);
                        } else {
                            // Sonraki deneme için beklet
                            $nextAttemptDelay = pow(2, $attempts) * 5; // Exponential backoff
                            $updateStmt = $this->pdo->prepare("
                                UPDATE email_queue 
                                SET attempts = ?, 
                                    processing_started_at = NULL, 
                                    next_attempt_at = DATE_ADD(NOW(), INTERVAL ? MINUTE)
                                WHERE id = ?
                            ");
                            $updateStmt->execute([$attempts, $nextAttemptDelay, $email['id']]);
                        }
                    }
                    
                    // Rate limiting
                    usleep(500000); // 0.5 saniye bekleme
                    
                } catch (Exception $e) {
                    error_log("Email queue processing error for ID {$email['id']}: " . $e->getMessage());
                    
                    // Hata durumunu kaydet
                    $attempts = ($email['attempts'] ?? 0) + 1;
                    $updateStmt = $this->pdo->prepare("
                        UPDATE email_queue 
                        SET attempts = ?, 
                            error_message = ?, 
                            processing_started_at = NULL 
                        WHERE id = ?
                    ");
                    $updateStmt->execute([$attempts, $e->getMessage(), $email['id']]);
                }
            }
            
            return $processedCount;
            
        } catch (Exception $e) {
            error_log('processEmailQueue error: ' . $e->getMessage());
            return 0;
        }
    }
    
    /**
     * Eski email'leri temizle (process_email_queue.php için)
     */
    public function cleanOldEmails($days = 30) {
        try {
            // Başarıyla gönderilmiş eski email'leri sil
            $stmt = $this->pdo->prepare("
                DELETE FROM email_queue 
                WHERE status = 'sent' 
                AND sent_at < DATE_SUB(NOW(), INTERVAL ? DAY)
            ");
            $stmt->execute([$days]);
            $deletedSent = $stmt->rowCount();
            
            // Başarısız eski email'leri sil
            $stmt = $this->pdo->prepare("
                DELETE FROM email_queue 
                WHERE status = 'failed' 
                AND created_at < DATE_SUB(NOW(), INTERVAL ? DAY)
            ");
            $stmt->execute([$days]);
            $deletedFailed = $stmt->rowCount();
            
            $totalDeleted = $deletedSent + $deletedFailed;
            
            if ($totalDeleted > 0) {
                error_log("Email temizliği: {$deletedSent} başarılı, {$deletedFailed} başarısız email silindi (>{$days} gün)");
            }
            
            return $totalDeleted;
            
        } catch (Exception $e) {
            error_log('cleanOldEmails error: ' . $e->getMessage());
            return 0;
        }
    }
    
    /**
     * Email istatistiklerini getir (process_email_queue.php için)
     */
    public function getEmailStats() {
        try {
            $stats = [
                'total' => 0,
                'pending' => 0,
                'sent' => 0,
                'failed' => 0,
                'processing' => 0
            ];
            
            // Toplam email sayısı
            $stmt = $this->pdo->query("SELECT COUNT(*) FROM email_queue");
            $stats['total'] = (int) $stmt->fetchColumn();
            
            // Bekleyen email sayısı
            $stmt = $this->pdo->query("SELECT COUNT(*) FROM email_queue WHERE status = 'pending'");
            $stats['pending'] = (int) $stmt->fetchColumn();
            
            // Gönderilen email sayısı
            $stmt = $this->pdo->query("SELECT COUNT(*) FROM email_queue WHERE status = 'sent'");
            $stats['sent'] = (int) $stmt->fetchColumn();
            
            // Başarısız email sayısı
            $stmt = $this->pdo->query("SELECT COUNT(*) FROM email_queue WHERE status = 'failed'");
            $stats['failed'] = (int) $stmt->fetchColumn();
            
            // İşlemde olan email sayısı
            $stmt = $this->pdo->query("
                SELECT COUNT(*) FROM email_queue 
                WHERE status = 'pending' 
                AND processing_started_at IS NOT NULL 
                AND processing_started_at > DATE_SUB(NOW(), INTERVAL 10 MINUTE)
            ");
            $stats['processing'] = (int) $stmt->fetchColumn();
            
            return $stats;
            
        } catch (Exception $e) {
            error_log('getEmailStats error: ' . $e->getMessage());
            return [
                'total' => 0,
                'pending' => 0,
                'sent' => 0,
                'failed' => 0,
                'processing' => 0
            ];
        }
    }
}
?>
