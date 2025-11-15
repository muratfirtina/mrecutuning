<?php

/**
 * Mr ECU - User Class (GUID System) - CLEAN VERSION with Email System
 * GUID tabanlı kullanıcı işlemleri sınıfı - Email sistemi ile
 */

class User
{
    private $pdo;
    private $emailManager;

    public function __construct($database)
    {
        $this->pdo = $database;
        
        // EmailManager'ı include et ve oluştur
        if (file_exists(__DIR__ . '/EmailManager.php')) {
            require_once __DIR__ . '/EmailManager.php';
            $this->emailManager = new EmailManager($database);
        }
    }

    // Kullanıcıyı ID ile getir (GUID ID ile) - TERS KREDİ SİSTEMİ ile
    public function getUserById($userId)
    {
        try {
            if (!isValidUUID($userId)) {
                return null;
            }

            $stmt = $this->pdo->prepare("
                SELECT *, 
                       (credit_quota - credit_used) as available_credits,
                       CASE 
                           WHEN credit_quota = 0 THEN 'Kota Belirlenmemiş'
                           WHEN credit_used >= credit_quota THEN 'Limit Aşıldı'
                           WHEN (credit_quota - credit_used) <= 100 THEN 'Düşük Kredi'
                           ELSE 'Normal'
                       END as credit_status
                FROM users WHERE id = ?
            ");
            $stmt->execute([$userId]);
            return $stmt->fetch(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log('getUserById error: ' . $e->getMessage());
            return null;
        }
    }

    // TERS KREDİ SİSTEMİ: Kullanıcı kredisini al (GUID ID ile)
    public function getUserCredits($userId)
    {
        try {
            if (!isValidUUID($userId)) {
                return 0;
            }

            $stmt = $this->pdo->prepare("SELECT credit_quota, credit_used FROM users WHERE id = ?");
            $stmt->execute([$userId]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($result) {
                // Kullanılabilir kredi hesapla (eski sistemle uyumluluk için)
                return (float)$result['credit_quota'] - (float)$result['credit_used'];
            }

            return 0;
        } catch (PDOException $e) {
            error_log('getUserCredits error: ' . $e->getMessage());
            return 0;
        }
    }

    // Log işlemi (GUID ID ile)
    public function logAction($userId, $action, $description = '', $ipAddress = null)
    {
        try {
            error_log('logAction başlatıldı: ' . $action . ' - ' . $description);

            if (!isValidUUID($userId)) {
                error_log('logAction: Geçersiz UUID - ' . $userId);
                return false;
            }

            if (!$ipAddress) {
                $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
                error_log('logAction: IP adresi: ' . $ipAddress);
            }

            // UUID oluştur
            if (function_exists('generateUUID')) {
                $logId = generateUUID();
                error_log('logAction: UUID oluşturuldu - ' . $logId);
            } else {
                error_log('logAction: generateUUID fonksiyonu bulunamadı!');
                // Alternatif UUID oluşturma
                $logId = sprintf(
                    '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
                    mt_rand(0, 0xffff),
                    mt_rand(0, 0xffff),
                    mt_rand(0, 0xffff),
                    mt_rand(0, 0x0fff) | 0x4000,
                    mt_rand(0, 0x3fff) | 0x8000,
                    mt_rand(0, 0xffff),
                    mt_rand(0, 0xffff),
                    mt_rand(0, 0xffff)
                );
                error_log('logAction: Alternatif UUID - ' . $logId);
            }

            // System_logs tablosunu kontrol et
            $checkTable = $this->pdo->query("SHOW TABLES LIKE 'system_logs'");
            if ($checkTable->rowCount() == 0) {
                error_log('logAction: system_logs tablosu bulunamadı!');
                return false;
            }

            $stmt = $this->pdo->prepare("
                INSERT INTO system_logs (id, user_id, action, description, ip_address, user_agent, created_at) 
                VALUES (?, ?, ?, ?, ?, ?, NOW())
            ");

            $result = $stmt->execute([
                $logId,
                $userId,
                $action,
                $description,
                $ipAddress,
                $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'
            ]);

            if ($result) {
                error_log('logAction: Başarılı!');
            } else {
                error_log('logAction: Execute başarısız!');
            }

            return $result;
        } catch (PDOException $e) {
            error_log('Security log database error: ' . $e->getMessage());
            // Log hatası olsa bile işlemi devam ettir
            return true; // Önemli: Ana işlemi durdurmamak için true dön
        }
    }

    // Kredi ekle/çıkar (basit versiyon) - MAIN METHOD - TERS KREDİ SİSTEMİ
    public function addCreditDirectSimple($userId, $amount, $type = 'deposit', $description = '', $referenceId = null, $referenceType = null, $adminId = null)
    {
        try {
            if (!isValidUUID($userId)) {
                return false;
            }

            if ($adminId && !isValidUUID($adminId)) {
                return false;
            }

            if ($referenceId && !isValidUUID($referenceId)) {
                return false;
            }

            // TERS KREDİ SİSTEMİ: Kullanıcının mevcut kredi durumunu güncelle
            if ($type === 'withdraw' || $type === 'file_charge') {
                // Ters kredi sisteminde kredi düşürme = credit_used artırma
                $currentCredits = $this->getUserCredits($userId);

                if ($currentCredits < $amount) {
                    error_log("Yetersiz kredi: Mevcut=$currentCredits, Gerekli=$amount");
                    return false;
                }

                // Kullanılan krediyi artır (ters kredi sistemi)
                $stmt = $this->pdo->prepare("UPDATE users SET credit_used = credit_used + ? WHERE id = ?");
                $result = $stmt->execute([$amount, $userId]);

                if (!$result) {
                    error_log("Kredi düşürme başarısız: userID=$userId, amount=$amount");
                    return false;
                }

                error_log("Kredi başarıyla düşürüldü: userID=$userId, amount=$amount, type=$type");
            } else if ($type === 'quota_increase') {
                // Kredi kotası artırma
                $stmt = $this->pdo->prepare("UPDATE users SET credit_quota = credit_quota + ? WHERE id = ?");
                $result = $stmt->execute([$amount, $userId]);
            } else if ($type === 'additional_file_charge') {
                // Ek dosya ücreti için kredi düşürme (ters kredi sistemi)
                $stmt = $this->pdo->prepare("UPDATE users SET credit_used = credit_used + ? WHERE id = ?");
                $result = $stmt->execute([$amount, $userId]);
            } else if ($type === 'usage_remove') {
                // Kullanılan krediden düşürme (iade)
                $stmt = $this->pdo->prepare("UPDATE users SET credit_used = GREATEST(0, credit_used - ?) WHERE id = ?");
                $result = $stmt->execute([$amount, $userId]);
            } else {
                // Eski sistem uyumluluğu için kredi kotası artırma
                $stmt = $this->pdo->prepare("UPDATE users SET credit_quota = credit_quota + ? WHERE id = ?");
                $stmt->execute([$amount, $userId]);
            }

            // İşlem kaydı ekle (tablo varsa)
            try {
                $transactionId = generateUUID();
                $stmt = $this->pdo->prepare("
                    INSERT INTO credit_transactions (id, user_id, amount, transaction_type, description, reference_id, reference_type, admin_id, created_at) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())
                ");
                $stmt->execute([$transactionId, $userId, $amount, $type, $description, $referenceId, $referenceType, $adminId]);
            } catch (PDOException $e) {
                // Credit transaction tablosu yoksa devam et
                error_log('Credit transaction log failed: ' . $e->getMessage());
            }

            // Session'daki kredi bilgisini güncelle
            $this->updateUserCreditsInSession($userId);

            return true;
        } catch (PDOException $e) {
            error_log("addCreditDirectSimple error: " . $e->getMessage());
            return false;
        }
    }

    // Kredi çıkarma (GUID ID ile)
    public function deductCredits($userId, $amount, $description = '')
    {
        try {
            if (!isValidUUID($userId)) {
                return ['success' => false, 'message' => 'Geçersiz kullanıcı ID formatı.'];
            }

            $currentCredits = $this->getUserCredits($userId);

            if ($currentCredits < $amount) {
                return ['success' => false, 'message' => 'Yetersiz kredi bakiyesi.'];
            }

            $result = $this->addCreditDirectSimple($userId, $amount, 'withdraw', $description);

            if ($result) {
                return ['success' => true, 'message' => 'Kredi başarıyla düşürüldü.'];
            } else {
                return ['success' => false, 'message' => 'Kredi düşürme işlemi başarısız.'];
            }
        } catch (PDOException $e) {
            error_log('deductCredits error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Veritabanı hatası oluştu.'];
        }
    }

    // Kullanıcı giriş
    public function login($email, $password)
    {
        try {
            $stmt = $this->pdo->prepare("SELECT * FROM users WHERE email = ? AND status = 'active'");
            $stmt->execute([$email]);
            $user = $stmt->fetch();

            if ($user && password_verify($password, $user['password'])) {
                // Email doğrulaması kontrolü
                if (!$user['email_verified']) {
                    return ['success' => false, 'message' => 'Email adresinizi doğrulamanız gerekiyor. Lütfen email kutunuzu kontrol edin.'];
                }

                // Tüm kullanıcı bilgilerini session'a kaydet
                session_regenerate_id(true);
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username']; // Orjinal değer, fallback yok
                $_SESSION['email'] = $user['email'];
                $_SESSION['role'] = $user['role'];
                $_SESSION['user_role'] = $user['role']; // Design panel uyumluluğu için
                $_SESSION['is_admin'] = in_array($user['role'], ['admin', 'design']) ? 1 : 0;
                $_SESSION['credits'] = $user['credits'] ?? 0;
                $_SESSION['first_name'] = $user['first_name'] ?? '';
                $_SESSION['last_name'] = $user['last_name'] ?? '';
                $_SESSION['phone'] = $user['phone'] ?? '';

                // Debug log
                error_log('Login successful for user: ' . $_SESSION['user_id'] . ' - Username: ' . ($_SESSION['username'] ?? 'NULL'));

                // Son giriş zamanını güncelle
                $this->updateLastLogin($user['id']);

                // Log kaydı
                $this->logAction($user['id'], 'login', 'Kullanıcı sisteme giriş yaptı');

                return ['success' => true, 'message' => 'Giriş başarılı.'];
            }

            error_log('Login failed for email: ' . $email);
            return ['success' => false, 'message' => 'Email veya şifre hatalı.'];
        } catch (PDOException $e) {
            error_log('Login error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Veritabanı hatası oluştu.'];
        }
    }

    // Kullanıcı kayıt (Email doğrulaması ile)
    public function register($data, $isAdmin = false)
    {
        try {
            // Email ve kullanıcı adı kontrolü
            if ($this->emailExists($data['email'])) {
                return ['success' => false, 'message' => 'Bu email adresi zaten kullanılıyor.'];
            }

            if ($this->usernameExists($data['username'])) {
                return ['success' => false, 'message' => 'Bu kullanıcı adı zaten kullanılıyor.'];
            }

            $hashedPassword = password_hash($data['password'], PASSWORD_DEFAULT);
            $verificationToken = generateToken();
            $userId = generateUUID();

            $role = $isAdmin && isset($data['role']) ? $data['role'] : 'user';
            $credits = $isAdmin && isset($data['credits']) ? $data['credits'] : DEFAULT_CREDITS;

            // Email doğrulaması gerekli mi?
            $emailVerified = $isAdmin ? 1 : 0; // Admin tarafından oluşturulan hesaplar doğrulanmış sayılır

            $stmt = $this->pdo->prepare("
                INSERT INTO users (id, username, email, password, first_name, last_name, phone, role, credits, verification_token, email_verified, terms_accepted, created_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
            ");
            
            $result = $stmt->execute([
                $userId,
                $data['username'],
                $data['email'],
                $hashedPassword,
                $data['first_name'],
                $data['last_name'],
                $data['phone'] ?? '',
                $role,
                $credits,
                $emailVerified ? null : $verificationToken,
                $emailVerified,
                $isAdmin ? 1 : (isset($data['terms_accepted']) ? 1 : 1) // Admin veya terms kabul edilmişse 1
            ]);

            if ($result) {
                // Log kaydı
                $this->logAction($userId, 'register', 'Yeni kullanıcı kaydı');

                // Email doğrulama maili gönder (admin değilse)
                if (!$isAdmin && $this->emailManager) {
                    $fullName = trim($data['first_name'] . ' ' . $data['last_name']);
                    $this->emailManager->sendVerificationEmail($data['email'], $fullName, $verificationToken);
                }

                $message = $isAdmin ? 'Kullanıcı başarıyla oluşturuldu.' : 'Kayıt başarılı. Email adresinizi doğrulamak için email kutunuzu kontrol edin.';
                return ['success' => true, 'message' => $message, 'user_id' => $userId];
            }

            return ['success' => false, 'message' => 'Kayıt sırasında bir hata oluştu.'];
        } catch (PDOException $e) {
            return ['success' => false, 'message' => 'Veritabanı hatası: ' . $e->getMessage()];
        }
    }

    // Email doğrulama
    public function verifyEmail($token)
    {
        try {
            $stmt = $this->pdo->prepare("
                UPDATE users 
                SET email_verified = 1, verification_token = NULL, updated_at = NOW() 
                WHERE verification_token = ? AND email_verified = 0
            ");
            $result = $stmt->execute([$token]);

            if ($result && $stmt->rowCount() > 0) {
                // Kullanıcı bilgilerini al
                $stmt2 = $this->pdo->prepare("SELECT id, email, CONCAT(first_name, ' ', last_name) as full_name FROM users WHERE email_verified = 1 AND verification_token IS NULL ORDER BY updated_at DESC LIMIT 1");
                $stmt2->execute();
                $user = $stmt2->fetch(PDO::FETCH_ASSOC);

                if ($user) {
                    $this->logAction($user['id'], 'email_verified', 'Email adresi doğrulandı');
                }

                return ['success' => true, 'message' => 'Email adresiniz başarıyla doğrulandı. Artık giriş yapabilirsiniz.'];
            }

            return ['success' => false, 'message' => 'Geçersiz veya süresi dolmuş doğrulama kodu.'];
        } catch (PDOException $e) {
            error_log('verifyEmail error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Doğrulama sırasında bir hata oluştu.'];
        }
    }

    // Şifre sıfırlama isteği (KOD TABANLI SİSTEM)
    public function requestPasswordReset($email)
    {
        try {
            // GÜVENLİK: Her durumda başarılı mesaj döndür
            $stmt = $this->pdo->prepare("SELECT id, CONCAT(first_name, ' ', last_name) as full_name FROM users WHERE email = ? AND status = 'active'");
            $stmt->execute([$email]);
            $user = $stmt->fetch();

            if ($user) {
                // 6 haneli rastgele kod oluştur
                $resetCode = sprintf('%06d', mt_rand(100000, 999999));
                $expiresAt = date('Y-m-d H:i:s', strtotime('+15 minutes'));

                $stmt = $this->pdo->prepare("UPDATE users SET reset_token = ?, reset_token_expires = ?, updated_at = NOW() WHERE id = ?");
                $stmt->execute([$resetCode, $expiresAt, $user['id']]);

                // Reset email gönder
                if ($this->emailManager) {
                    $this->emailManager->sendPasswordResetEmail($email, $user['full_name'], $resetCode);
                }

                // Log kaydı
                $this->logAction($user['id'], 'password_reset_requested', 'Şifre sıfırlama kodu istendi - IP: ' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
            }

            // GÜVENLİK: Email kayıtlı olsun veya olmasın hep aynı mesajı döndür
            return ['success' => true, 'message' => 'Şifre sıfırlama kodu email adresinize gönderildi.'];

        } catch (PDOException $e) {
            error_log('requestPasswordReset error: ' . $e->getMessage());
            return ['success' => true, 'message' => 'Şifre sıfırlama kodu email adresinize gönderildi.'];
        }
    }

    // Şifre sıfırlama kodu doğrulama
    public function verifyResetCode($code)
    {
        try {
            $stmt = $this->pdo->prepare("
                SELECT id, email, CONCAT(first_name, ' ', last_name) as full_name 
                FROM users 
                WHERE reset_token = ? AND reset_token_expires > NOW() AND status = 'active'
            ");
            $stmt->execute([$code]);
            $user = $stmt->fetch();

            if ($user) {
                return ['success' => true, 'message' => 'Kod geçerli.', 'user' => $user];
            }

            return ['success' => false, 'message' => 'Geçersiz veya süresi dolmuş kod.'];
        } catch (PDOException $e) {
            error_log('verifyResetCode error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Kod doğrulama sırasında hata oluştu.'];
        }
    }

    // Şifre sıfırlama (kod ile)
    public function resetPasswordWithCode($code, $newPassword)
    {
        try {
            // Kodu doğrula
            $verifyResult = $this->verifyResetCode($code);
            if (!$verifyResult['success']) {
                return $verifyResult;
            }

            $user = $verifyResult['user'];
            $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);

            $stmt = $this->pdo->prepare("
                UPDATE users 
                SET password = ?, reset_token = NULL, reset_token_expires = NULL, updated_at = NOW() 
                WHERE id = ?
            ");
            $result = $stmt->execute([$hashedPassword, $user['id']]);

            if ($result) {
                // Log kaydı
                $this->logAction($user['id'], 'password_reset_completed', 'Şifre başarıyla sıfırlandı');

                return ['success' => true, 'message' => 'Şifreniz başarıyla güncellendi.'];
            }

            return ['success' => false, 'message' => 'Şifre güncellenirken hata oluştu.'];
        } catch (PDOException $e) {
            error_log('resetPasswordWithCode error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Şifre sıfırlama sırasında hata oluştu.'];
        }
    }

    // Email yeniden gönder
    public function resendVerificationEmail($email)
    {
        try {
            $stmt = $this->pdo->prepare("
                SELECT id, CONCAT(first_name, ' ', last_name) as full_name, verification_token 
                FROM users 
                WHERE email = ? AND email_verified = 0 AND verification_token IS NOT NULL
            ");
            $stmt->execute([$email]);
            $user = $stmt->fetch();

            if ($user && $this->emailManager) {
                $this->emailManager->sendVerificationEmail($email, $user['full_name'], $user['verification_token']);
                return ['success' => true, 'message' => 'Doğrulama emaili yeniden gönderildi.'];
            }

            return ['success' => false, 'message' => 'Email adresi bulunamadı veya zaten doğrulanmış.'];
        } catch (PDOException $e) {
            error_log('resendVerificationEmail error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Email gönderme sırasında hata oluştu.'];
        }
    }

    // Kullanıcı bilgilerini güncelle
    public function updateUser($id, $data)
    {
        try {
            if (!isValidUUID($id)) {
                return false;
            }

            // DÜZELTME: DATETIME tipindeki updated_at için NOW() kullanın
            $stmt = $this->pdo->prepare("
            UPDATE users 
            SET first_name = ?, last_name = ?, phone = ?, updated_at = NOW() 
            WHERE id = ?
        ");

            return $stmt->execute([
                $data['first_name'],
                $data['last_name'],
                $data['phone'],
                $id
            ]);
        } catch (PDOException $e) {
            return false;
        }
    }

    // Kullanıcı çıkış
    public function logout()
    {
        if (isset($_SESSION['user_id'])) {
            $this->logAction($_SESSION['user_id'], 'logout', 'Kullanıcı sistemden çıkış yaptı');
        }

        session_destroy();
        return true;
    }

    // Tüm kullanıcıları listele (Admin)
    public function getAllUsers($page = 1, $limit = 50)
    {
        try {
            $page = max(1, (int)$page);
            $limit = max(1, (int)$limit);
            $offset = ($page - 1) * $limit;

            // LIMIT ve OFFSET için direkt sayısal değerler kullan
            $query = "
                SELECT id, username, email, first_name, last_name, phone, credits, role, status, email_verified, created_at, last_login,
                       (SELECT COUNT(*) FROM file_uploads WHERE user_id = users.id) as total_uploads
                FROM users 
                ORDER BY created_at DESC 
                LIMIT $limit OFFSET $offset
            ";

            $stmt = $this->pdo->query($query);
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log("getAllUsers error: " . $e->getMessage());
            return [];
        }
    }

    // Kullanıcı sayısı
    public function getUserCount()
    {
        try {
            $stmt = $this->pdo->query("SELECT COUNT(*) FROM users");
            return $stmt->fetchColumn();
        } catch (PDOException $e) {
            return 0;
        }
    }

    // TERS KREDİ SİSTEMİ: Kullanıcı kredi durumu detayı
    public function getUserCreditDetails($userId)
    {
        try {
            if (!isValidUUID($userId)) {
                return ['credit_quota' => 0, 'credit_used' => 0, 'available_credits' => 0];
            }

            $stmt = $this->pdo->prepare("SELECT credit_quota, credit_used FROM users WHERE id = ?");
            $stmt->execute([$userId]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($result) {
                return [
                    'credit_quota' => (float)$result['credit_quota'],
                    'credit_used' => (float)$result['credit_used'],
                    'available_credits' => (float)$result['credit_quota'] - (float)$result['credit_used']
                ];
            }

            return ['credit_quota' => 0, 'credit_used' => 0, 'available_credits' => 0];
        } catch (PDOException $e) {
            error_log('getUserCreditDetails error: ' . $e->getMessage());
            return ['credit_quota' => 0, 'credit_used' => 0, 'available_credits' => 0];
        }
    }

    // TERS KREDİ SİSTEMİ: Kredi kontrolü (dosya yüklerken)
    public function canUserUploadFile($userId, $estimatedCredits = 0)
    {
        try {
            $creditDetails = $this->getUserCreditDetails($userId);

            // GÜVENLIK: Kredi kotası 0 olan kullanıcılar dosya yükleyemez
            if ($creditDetails['credit_quota'] == 0) {
            return [
            'can_upload' => false,
            'message' => 'Kredi kotanız belirlenmemiş veya sıfır. Dosya yüklemek için yöneticiden kredi kotası talep edin.',
            'available_credits' => 0
            ];
            }

            // Kullanılabilir kredi kontrol et
            if ($creditDetails['available_credits'] <= 0) {
                return [
                    'can_upload' => false,
                    'message' => 'Kredi limitinizi aştınız. Daha fazla dosya yükleyemezsiniz.',
                    'available_credits' => $creditDetails['available_credits']
                ];
            }

            // Tahmini kredi kontrolü
            if ($estimatedCredits > 0 && $creditDetails['available_credits'] < $estimatedCredits) {
                return [
                    'can_upload' => false,
                    'message' => "Yetersiz kredi. Gerekli: {$estimatedCredits} TL, Mevcut: {$creditDetails['available_credits']} TL",
                    'available_credits' => $creditDetails['available_credits']
                ];
            }

            return [
                'can_upload' => true,
                'message' => 'Dosya yüklenebilir.',
                'available_credits' => $creditDetails['available_credits']
            ];
        } catch (PDOException $e) {
            error_log('canUserUploadFile error: ' . $e->getMessage());
            return [
                'can_upload' => false,
                'message' => 'Kredi durumu kontrol edilemedi.',
                'available_credits' => 0
            ];
        }
    }

    // Session'daki kredi bilgisini güncelle
    public function updateUserCreditsInSession($userId = null)
    {
        if (!$userId && isset($_SESSION['user_id'])) {
            $userId = $_SESSION['user_id'];
        }

        if ($userId && isset($_SESSION['user_id']) && $_SESSION['user_id'] == $userId) {
            $_SESSION['credits'] = $this->getUserCredits($userId);
        }
    }

    // Email var mı kontrol et
    private function emailExists($email)
    {
        $stmt = $this->pdo->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->execute([$email]);
        return $stmt->fetch() !== false;
    }

    // Kullanıcı adı var mı kontrol et
    private function usernameExists($username)
    {
        $stmt = $this->pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute([$username]);
        return $stmt->fetch() !== false;
    }

    // Son giriş zamanını güncelle
    private function updateLastLogin($userId)
    {
        if (!isValidUUID($userId)) {
            return false;
        }

        $stmt = $this->pdo->prepare("UPDATE users SET last_login = NOW(), updated_at = NOW() WHERE id = ?");
        $stmt->execute([$userId]);
    }

    // Remember token işlemleri
    public function setRememberToken($userId, $token)
    {
        try {
            if (!isValidUUID($userId)) {
                return false;
            }

            $stmt = $this->pdo->prepare("UPDATE users SET remember_token = ? WHERE id = ?");
            return $stmt->execute([$token, $userId]);
        } catch (PDOException $e) {
            error_log('setRememberToken error: ' . $e->getMessage());
            return false;
        }
    }

    public function getRememberToken($token)
    {
        try {
            $stmt = $this->pdo->prepare("SELECT * FROM users WHERE remember_token = ? AND status = 'active'");
            $stmt->execute([$token]);
            return $stmt->fetch(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log('getRememberToken error: ' . $e->getMessage());
            return false;
        }
    }

    public function clearRememberToken($userId)
    {
        try {
            if (!isValidUUID($userId)) {
                return false;
            }

            $stmt = $this->pdo->prepare("UPDATE users SET remember_token = NULL WHERE id = ?");
            return $stmt->execute([$userId]);
        } catch (PDOException $e) {
            error_log('clearRememberToken error: ' . $e->getMessage());
            return false;
        }
    }
    
}
