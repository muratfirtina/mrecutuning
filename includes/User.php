<?php
/**
 * User.php
 * Refactored, secure, GUID-based User class
 *
 * Requirements:
 *  - PDO instance passed to constructor
 *  - Optional EmailManager in same directory named EmailManager.php
 *
 * Notes:
 *  - Uses credit_quota / credit_used as primary credit storage.
 *  - Backwards-compatible with a legacy 'credits' column (if present).
 */

class User
{
    private PDO $pdo;
    private $emailManager = null;

    public function __construct(PDO $database)
    {
        $this->pdo = $database;

        // Optional EmailManager
        $emailManagerPath = __DIR__ . '/EmailManager.php';
        if (file_exists($emailManagerPath)) {
            require_once $emailManagerPath;
            if (class_exists('EmailManager')) {
                try {
                    $this->emailManager = new EmailManager($database);
                } catch (Exception $e) {
                    error_log('EmailManager init failed: ' . $e->getMessage());
                }
            }
        }
    }

    //
    // -----------------------
    // Helper functions
    // -----------------------
    //

    public static function is_valid_uuid(string $uuid): bool
    {
        return (bool)preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i', $uuid);
    }

    public static function generate_uuid(): string
    {
        // RFC4122 v4 UUID
        $data = random_bytes(16);
        $data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
        $data[8] = chr((ord($data[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    public static function generate_token(int $length = 64): string
    {
        return bin2hex(random_bytes((int)ceil($length / 2)));
    }

    //
    // -----------------------
    // User getters
    // -----------------------
    //

    public function getUserById(string $userId): ?array
    {
        try {
            if (!self::is_valid_uuid($userId)) {
                return null;
            }

            $stmt = $this->pdo->prepare("
                SELECT *, 
                       COALESCE(credit_quota, credits, 0) AS credit_quota,
                       COALESCE(credit_used, 0) AS credit_used,
                       (COALESCE(credit_quota, credits, 0) - COALESCE(credit_used,0)) AS available_credits
                FROM users
                WHERE id = :id
                LIMIT 1
            ");
            $stmt->execute([':id' => $userId]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);

            return $row ?: null;
        } catch (PDOException $e) {
            error_log('getUserById error: ' . $e->getMessage());
            return null;
        }
    }

    public function getUserCredits(string $userId): float
    {
        try {
            if (!self::is_valid_uuid($userId)) {
                return 0.0;
            }

            $stmt = $this->pdo->prepare("SELECT COALESCE(credit_quota, credits, 0) AS credit_quota, COALESCE(credit_used, 0) AS credit_used FROM users WHERE id = :id LIMIT 1");
            $stmt->execute([':id' => $userId]);
            $r = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$r) return 0.0;
            $available = (float)$r['credit_quota'] - (float)$r['credit_used'];
            return $available >= 0 ? $available : 0.0;
        } catch (PDOException $e) {
            error_log('getUserCredits error: ' . $e->getMessage());
            return 0.0;
        }
    }

    //
    // -----------------------
    // Action logging
    // -----------------------
    //

    public function logAction(string $userId = null, string $action, string $description = '', string $ipAddress = null): bool
    {
        try {
            // Allow null userId for system events
            if ($userId !== null && !self::is_valid_uuid($userId)) {
                error_log('logAction: invalid UUID: ' . $userId);
                return false;
            }

            $ip = $ipAddress ?? ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
            $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';

            // Ensure system_logs exists (best-effort)
            try {
                $check = $this->pdo->query("SHOW TABLES LIKE 'system_logs'");
                if ($check === false || $check->rowCount() === 0) {
                    // Not fatal: don't stop the main flow
                    error_log('logAction: system_logs table missing');
                    return false;
                }
            } catch (PDOException $e) {
                // ignore
            }

            $logId = self::generate_uuid();

            $stmt = $this->pdo->prepare("
                INSERT INTO system_logs (id, user_id, action, description, ip_address, user_agent, created_at)
                VALUES (:id, :user_id, :action, :description, :ip, :ua, NOW())
            ");

            return (bool)$stmt->execute([
                ':id' => $logId,
                ':user_id' => $userId,
                ':action' => $action,
                ':description' => $description,
                ':ip' => $ip,
                ':ua' => $ua
            ]);
        } catch (PDOException $e) {
            error_log('logAction exception: ' . $e->getMessage());
            return false;
        }
    }

    //
    // -----------------------
    // Credit management (atomic)
    // -----------------------
    //

    /**
     * Generic credit update helper (supports deposit, withdraw, quota increase, usage_remove)
     * Returns true on success, false on failure.
     */
    public function updateCredits(string $userId, float $amount, string $operation = 'deposit', array $meta = []): bool
    {
        if (!self::is_valid_uuid($userId)) {
            return false;
        }

        // Normalize amount
        $amount = (float)$amount;
        if ($amount < 0) {
            $amount = abs($amount);
        }

        try {
            $this->pdo->beginTransaction();

            // Lock the user row FOR UPDATE to avoid race conditions
            $stmt = $this->pdo->prepare("SELECT COALESCE(credit_quota, credits, 0) AS credit_quota, COALESCE(credit_used,0) AS credit_used FROM users WHERE id = :id FOR UPDATE");
            $stmt->execute([':id' => $userId]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$user) {
                $this->pdo->rollBack();
                return false;
            }

            $quota = (float)$user['credit_quota'];
            $used = (float)$user['credit_used'];

            switch ($operation) {
                case 'withdraw': // increase credit_used (Ters kredi)
                case 'file_charge':
                case 'additional_file_charge':
                    // Ensure enough available credits
                    $available = $quota - $used;
                    if ($available < $amount) {
                        $this->pdo->rollBack();
                        return false;
                    }
                    $stmtUpd = $this->pdo->prepare("UPDATE users SET credit_used = credit_used + :amt, updated_at = NOW() WHERE id = :id");
                    $ok = $stmtUpd->execute([':amt' => $amount, ':id' => $userId]);
                    break;

                case 'usage_remove': // refund used credits
                    $stmtUpd = $this->pdo->prepare("UPDATE users SET credit_used = GREATEST(0, credit_used - :amt), updated_at = NOW() WHERE id = :id");
                    $ok = $stmtUpd->execute([':amt' => $amount, ':id' => $userId]);
                    break;

                case 'quota_increase':
                case 'deposit':
                default:
                    // Increase quota (compatibility with legacy 'credits' column)
                    $stmtUpd = $this->pdo->prepare("UPDATE users SET credit_quota = COALESCE(credit_quota, credits, 0) + :amt, updated_at = NOW() WHERE id = :id");
                    $ok = $stmtUpd->execute([':amt' => $amount, ':id' => $userId]);
                    break;
            }

            if (!$ok) {
                $this->pdo->rollBack();
                return false;
            }

            // Insert transaction record if table exists
            try {
                $txId = self::generate_uuid();
                $stmtTx = $this->pdo->prepare("
                    INSERT INTO credit_transactions (id, user_id, amount, transaction_type, description, reference_id, reference_type, admin_id, created_at)
                    VALUES (:id, :user_id, :amount, :type, :desc, :ref_id, :ref_type, :admin_id, NOW())
                ");
                $stmtTx->execute([
                    ':id' => $txId,
                    ':user_id' => $userId,
                    ':amount' => $amount,
                    ':type' => $operation,
                    ':desc' => $meta['description'] ?? null,
                    ':ref_id' => $meta['reference_id'] ?? null,
                    ':ref_type' => $meta['reference_type'] ?? null,
                    ':admin_id' => $meta['admin_id'] ?? null
                ]);
            } catch (PDOException $e) {
                // Not fatal: continue even if transaction log fails
                error_log('credit_transactions insert failed: ' . $e->getMessage());
            }

            $this->pdo->commit();

            // Update session credits if current user
            $this->updateUserCreditsInSession($userId);

            return true;
        } catch (PDOException $e) {
            try { $this->pdo->rollBack(); } catch (Exception $_) {}
            error_log('updateCredits error: ' . $e->getMessage());
            return false;
        }
    }

    public function deductCredits(string $userId, float $amount, string $description = ''): array
    {
        $ok = $this->updateCredits($userId, $amount, 'withdraw', ['description' => $description]);
        if ($ok) {
            return ['success' => true, 'message' => 'Kredi başarıyla düşürüldü.'];
        }
        return ['success' => false, 'message' => 'Kredi düşürme işlemi başarısız veya yetersiz bakiye.'];
    }

    //
    // -----------------------
    // Authentication
    // -----------------------
    //

    /**
     * login()
     * - returns ['success' => bool, 'message' => string, 'user_id' => ?string]
     */
    public function login(string $email, string $password): array
    {
        try {
            $stmt = $this->pdo->prepare("SELECT * FROM users WHERE email = :email AND status = 'active' LIMIT 1");
            $stmt->execute([':email' => $email]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$user) {
                error_log('Login failed (no user) for: ' . $email);
                return ['success' => false, 'message' => 'Email veya şifre hatalı.'];
            }

            if (!isset($user['password']) || !password_verify($password, $user['password'])) {
                error_log('Login failed (wrong password) for: ' . $email);
                return ['success' => false, 'message' => 'Email veya şifre hatalı.'];
            }

            // Email verification check
            if (isset($user['email_verified']) && (int)$user['email_verified'] === 0) {
                return ['success' => false, 'message' => 'Email adresinizi doğrulamanız gerekiyor. Lütfen email kutunuzu kontrol edin.'];
            }

            // Session hardening: regenerate and set minimal info
            if (session_status() !== PHP_SESSION_ACTIVE) {
                session_start();
            }
            session_regenerate_id(true);

            $_SESSION['user_id'] = $user['id'];
            // Provide both legacy and canonical fields
            $_SESSION['username'] = $user['username'] ?? ($user['email'] ?? null);
            $_SESSION['email'] = $user['email'];
            $_SESSION['role'] = $user['role'] ?? 'user';
            $_SESSION['user_role'] = $_SESSION['role'];
            $_SESSION['is_admin'] = in_array($_SESSION['role'], ['admin', 'design']) ? 1 : 0;
            // Credits session: use calculated available credits
            $_SESSION['credits'] = $this->getUserCredits($user['id']);
            $_SESSION['first_name'] = $user['first_name'] ?? '';
            $_SESSION['last_name'] = $user['last_name'] ?? '';
            $_SESSION['phone'] = $user['phone'] ?? '';

            // update last login
            $this->updateLastLogin($user['id']);

            // log
            $this->logAction($user['id'], 'login', 'Kullanıcı sisteme giriş yaptı');

            // Return user_id for calling code compatibility
            return ['success' => true, 'message' => 'Giriş başarılı.', 'user_id' => $user['id']];
        } catch (PDOException $e) {
            error_log('Login error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Veritabanı hatası oluştu.'];
        }
    }

    //
    // -----------------------
    // Registration & verification
    // -----------------------
    //

    public function register(array $data, bool $isAdmin = false): array
    {
        try {
            $email = $data['email'] ?? null;
            $username = $data['username'] ?? null;
            $password = $data['password'] ?? null;

            if (!$email || !$username || !$password) {
                return ['success' => false, 'message' => 'Gerekli alanlar eksik.'];
            }

            if ($this->emailExists($email)) {
                return ['success' => false, 'message' => 'Bu email adresi zaten kullanılıyor.'];
            }

            if ($this->usernameExists($username)) {
                return ['success' => false, 'message' => 'Bu kullanıcı adı zaten kullanılıyor.'];
            }

            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
            $verificationToken = self::generate_token(48);
            $userId = self::generate_uuid();

            $role = $isAdmin && isset($data['role']) ? $data['role'] : 'user';
            $credits = $isAdmin && isset($data['credits']) ? (float)$data['credits'] : (defined('DEFAULT_CREDITS') ? DEFAULT_CREDITS : 0);

            $emailVerified = $isAdmin ? 1 : 0;
            $verificationTokenDb = $emailVerified ? null : $verificationToken;

            $stmt = $this->pdo->prepare("
                INSERT INTO users (id, username, email, password, first_name, last_name, phone, role, credit_quota, credit_used, verification_token, email_verified, terms_accepted, status, created_at)
                VALUES (:id, :username, :email, :password, :first_name, :last_name, :phone, :role, :credit_quota, 0, :vtoken, :email_verified, :terms, 'active', NOW())
            ");

            $ok = $stmt->execute([
                ':id' => $userId,
                ':username' => $username,
                ':email' => $email,
                ':password' => $hashedPassword,
                ':first_name' => $data['first_name'] ?? '',
                ':last_name' => $data['last_name'] ?? '',
                ':phone' => $data['phone'] ?? '',
                ':role' => $role,
                ':credit_quota' => $credits,
                ':vtoken' => $verificationTokenDb,
                ':email_verified' => $emailVerified ? 1 : 0,
                ':terms' => $isAdmin ? 1 : (isset($data['terms_accepted']) ? (int)$data['terms_accepted'] : 0)
            ]);

            if (!$ok) {
                return ['success' => false, 'message' => 'Kayıt sırasında bir hata oluştu.'];
            }

            $this->logAction($userId, 'register', 'Yeni kullanıcı kaydı');

            // send verification email if needed
            if (!$isAdmin && $this->emailManager) {
                $fullName = trim(($data['first_name'] ?? '') . ' ' . ($data['last_name'] ?? ''));
                try {
                    $this->emailManager->sendVerificationEmail($email, $fullName, $verificationToken);
                } catch (Exception $e) {
                    error_log('sendVerificationEmail failed: ' . $e->getMessage());
                }
            }

            return ['success' => true, 'message' => $isAdmin ? 'Kullanıcı oluşturuldu.' : 'Kayıt başarılı. Email doğrulaması gönderildi.', 'user_id' => $userId];
        } catch (PDOException $e) {
            error_log('register error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Veritabanı hatası: ' . $e->getMessage()];
        }
    }

    public function verifyEmail(string $token): array
    {
        try {
            if (empty($token)) {
                return ['success' => false, 'message' => 'Geçersiz token.'];
            }

            $stmt = $this->pdo->prepare("UPDATE users SET email_verified = 1, verification_token = NULL, updated_at = NOW() WHERE verification_token = :token AND email_verified = 0");
            $stmt->execute([':token' => $token]);

            if ($stmt->rowCount() > 0) {
                // get user id for logging
                $stmt2 = $this->pdo->prepare("SELECT id FROM users WHERE email_verified = 1 AND verification_token IS NULL ORDER BY updated_at DESC LIMIT 1");
                $stmt2->execute();
                $u = $stmt2->fetch(PDO::FETCH_ASSOC);
                if ($u) $this->logAction($u['id'], 'email_verified', 'Email doğrulandı');
                return ['success' => true, 'message' => 'Email adresiniz başarıyla doğrulandı.'];
            }

            return ['success' => false, 'message' => 'Geçersiz veya süresi dolmuş doğrulama kodu.'];
        } catch (PDOException $e) {
            error_log('verifyEmail error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Doğrulama sırasında hata oluştu.'];
        }
    }

    //
    // -----------------------
    // Password reset (code-based)
    // -----------------------
    //

    public function requestPasswordReset(string $email): array
    {
        try {
            $stmt = $this->pdo->prepare("SELECT id, CONCAT(first_name, ' ', last_name) AS full_name FROM users WHERE email = :email AND status = 'active' LIMIT 1");
            $stmt->execute([':email' => $email]);
            $u = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($u) {
                $resetCode = sprintf('%06d', random_int(100000, 999999));
                $expires = date('Y-m-d H:i:s', strtotime('+15 minutes'));

                $stmt2 = $this->pdo->prepare("UPDATE users SET reset_token = :code, reset_token_expires = :exp, updated_at = NOW() WHERE id = :id");
                $stmt2->execute([':code' => $resetCode, ':exp' => $expires, ':id' => $u['id']]);

                if ($this->emailManager) {
                    try {
                        $this->emailManager->sendPasswordResetEmail($email, $u['full_name'], $resetCode);
                    } catch (Exception $e) {
                        error_log('sendPasswordResetEmail failed: ' . $e->getMessage());
                    }
                }
                $this->logAction($u['id'], 'password_reset_requested', 'Şifre sıfırlama kodu istendi');
            }

            // Always return success message for privacy
            return ['success' => true, 'message' => 'Şifre sıfırlama kodu email adresinize gönderildi.'];
        } catch (PDOException $e) {
            error_log('requestPasswordReset error: ' . $e->getMessage());
            return ['success' => true, 'message' => 'Şifre sıfırlama kodu email adresinize gönderildi.'];
        }
    }

    public function verifyResetCode(string $code): array
    {
        try {
            $stmt = $this->pdo->prepare("SELECT id, email, CONCAT(first_name,' ',last_name) as full_name FROM users WHERE reset_token = :code AND reset_token_expires > NOW() AND status = 'active' LIMIT 1");
            $stmt->execute([':code' => $code]);
            $u = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($u) return ['success' => true, 'message' => 'Kod geçerli.', 'user' => $u];
            return ['success' => false, 'message' => 'Geçersiz veya süresi dolmuş kod.'];
        } catch (PDOException $e) {
            error_log('verifyResetCode error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Kod doğrulama sırasında hata oluştu.'];
        }
    }

    public function resetPasswordWithCode(string $code, string $newPassword): array
    {
        try {
            $verify = $this->verifyResetCode($code);
            if (!$verify['success']) return $verify;

            $user = $verify['user'];
            $hashed = password_hash($newPassword, PASSWORD_DEFAULT);

            $stmt = $this->pdo->prepare("UPDATE users SET password = :pwd, reset_token = NULL, reset_token_expires = NULL, updated_at = NOW() WHERE id = :id");
            $ok = $stmt->execute([':pwd' => $hashed, ':id' => $user['id']]);

            if ($ok) {
                $this->logAction($user['id'], 'password_reset_completed', 'Şifre sıfırlama tamamlandı');
                return ['success' => true, 'message' => 'Şifreniz başarıyla güncellendi.'];
            }
            return ['success' => false, 'message' => 'Şifre güncellenirken hata oluştu.'];
        } catch (PDOException $e) {
            error_log('resetPasswordWithCode error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Şifre sıfırlama sırasında hata oluştu.'];
        }
    }

    //
    // -----------------------
    // Misc helpers
    // -----------------------
    //

    private function emailExists(string $email): bool
    {
        $stmt = $this->pdo->prepare("SELECT id FROM users WHERE email = :email LIMIT 1");
        $stmt->execute([':email' => $email]);
        return (bool)$stmt->fetch(PDO::FETCH_ASSOC);
    }

    private function usernameExists(string $username): bool
    {
        $stmt = $this->pdo->prepare("SELECT id FROM users WHERE username = :username LIMIT 1");
        $stmt->execute([':username' => $username]);
        return (bool)$stmt->fetch(PDO::FETCH_ASSOC);
    }

    private function updateLastLogin(string $userId): void
    {
        if (!self::is_valid_uuid($userId)) return;
        try {
            $stmt = $this->pdo->prepare("UPDATE users SET last_login = NOW(), updated_at = NOW() WHERE id = :id");
            $stmt->execute([':id' => $userId]);
        } catch (PDOException $e) {
            error_log('updateLastLogin error: ' . $e->getMessage());
        }
    }

    public function setRememberToken(string $userId, string $token): bool
    {
        if (!self::is_valid_uuid($userId)) return false;
        try {
            $stmt = $this->pdo->prepare("UPDATE users SET remember_token = :token, updated_at = NOW() WHERE id = :id");
            return (bool)$stmt->execute([':token' => $token, ':id' => $userId]);
        } catch (PDOException $e) {
            error_log('setRememberToken error: ' . $e->getMessage());
            return false;
        }
    }

    public function getRememberToken(string $token)
    {
        try {
            $stmt = $this->pdo->prepare("SELECT * FROM users WHERE remember_token = :token AND status = 'active' LIMIT 1");
            $stmt->execute([':token' => $token]);
            return $stmt->fetch(PDO::FETCH_ASSOC) ?: false;
        } catch (PDOException $e) {
            error_log('getRememberToken error: ' . $e->getMessage());
            return false;
        }
    }

    public function clearRememberToken(string $userId): bool
    {
        if (!self::is_valid_uuid($userId)) return false;
        try {
            $stmt = $this->pdo->prepare("UPDATE users SET remember_token = NULL, updated_at = NOW() WHERE id = :id");
            return (bool)$stmt->execute([':id' => $userId]);
        } catch (PDOException $e) {
            error_log('clearRememberToken error: ' . $e->getMessage());
            return false;
        }
    }

    public function logout(): bool
    {
        if (session_status() !== PHP_SESSION_ACTIVE) session_start();
        if (isset($_SESSION['user_id'])) {
            $this->logAction($_SESSION['user_id'], 'logout', 'Kullanıcı çıkış yaptı');
        }
        session_unset();
        session_destroy();
        return true;
    }

    // Admin listing with pagination (safe numeric interpolation)
    public function getAllUsers(int $page = 1, int $limit = 50): array
    {
        try {
            $page = max(1, $page);
            $limit = max(1, min(500, $limit)); // cap limit
            $offset = ($page - 1) * $limit;

            // limit and offset are integers so safe to inject directly
            $query = "
                SELECT id, username, email, first_name, last_name, phone, COALESCE(credit_quota, credits, 0) AS credits, role, status, email_verified, created_at, last_login,
                       (SELECT COUNT(*) FROM file_uploads WHERE user_id = users.id) AS total_uploads
                FROM users
                ORDER BY created_at DESC
                LIMIT {$limit} OFFSET {$offset}
            ";

            $stmt = $this->pdo->query($query);
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log('getAllUsers error: ' . $e->getMessage());
            return [];
        }
    }

    public function getUserCount(): int
    {
        try {
            $stmt = $this->pdo->query("SELECT COUNT(*) FROM users");
            return (int)$stmt->fetchColumn();
        } catch (PDOException $e) {
            return 0;
        }
    }

    public function getUserCreditDetails(string $userId): array
    {
        try {
            if (!self::is_valid_uuid($userId)) {
                return ['credit_quota' => 0.0, 'credit_used' => 0.0, 'available_credits' => 0.0];
            }

            $stmt = $this->pdo->prepare("SELECT COALESCE(credit_quota, credits, 0) AS credit_quota, COALESCE(credit_used,0) AS credit_used FROM users WHERE id = :id LIMIT 1");
            $stmt->execute([':id' => $userId]);
            $r = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$r) return ['credit_quota' => 0.0, 'credit_used' => 0.0, 'available_credits' => 0.0];

            $quota = (float)$r['credit_quota'];
            $used = (float)$r['credit_used'];
            $avail = $quota - $used;
            return ['credit_quota' => $quota, 'credit_used' => $used, 'available_credits' => max(0.0, $avail)];
        } catch (PDOException $e) {
            error_log('getUserCreditDetails error: ' . $e->getMessage());
            return ['credit_quota' => 0.0, 'credit_used' => 0.0, 'available_credits' => 0.0];
        }
    }

    public function canUserUploadFile(string $userId, float $estimatedCredits = 0.0): array
    {
        try {
            $details = $this->getUserCreditDetails($userId);

            if ($details['credit_quota'] == 0.0) {
                return ['can_upload' => false, 'message' => 'Kredi kotanız belirlenmemiş veya sıfır. Yönetici ile iletişime geçin.', 'available_credits' => 0.0];
            }

            if ($details['available_credits'] <= 0.0) {
                return ['can_upload' => false, 'message' => 'Kredi limitiniz tükendi.', 'available_credits' => $details['available_credits']];
            }

            if ($estimatedCredits > 0.0 && $details['available_credits'] < $estimatedCredits) {
                return ['can_upload' => false, 'message' => "Yetersiz kredi. Gerekli: {$estimatedCredits}, Mevcut: {$details['available_credits']}", 'available_credits' => $details['available_credits']];
            }

            return ['can_upload' => true, 'message' => 'Dosya yüklenebilir.', 'available_credits' => $details['available_credits']];
        } catch (Exception $e) {
            error_log('canUserUploadFile error: ' . $e->getMessage());
            return ['can_upload' => false, 'message' => 'Kredi kontrolü yapılamadı.', 'available_credits' => 0.0];
        }
    }

    public function updateUserCreditsInSession(string $userId = null): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) session_start();
        if (!$userId && isset($_SESSION['user_id'])) $userId = $_SESSION['user_id'];
        if (!$userId) return;
        if (!isset($_SESSION['user_id']) || $_SESSION['user_id'] != $userId) return;
        $_SESSION['credits'] = $this->getUserCredits($userId);
    }

    // Update basic profile fields
    public function updateUser(string $id, array $data): bool
    {
        try {
            if (!self::is_valid_uuid($id)) return false;
            $stmt = $this->pdo->prepare("UPDATE users SET first_name = :fn, last_name = :ln, phone = :ph, updated_at = NOW() WHERE id = :id");
            return (bool)$stmt->execute([':fn' => $data['first_name'] ?? '', ':ln' => $data['last_name'] ?? '', ':ph' => $data['phone'] ?? '', ':id' => $id]);
        } catch (PDOException $e) {
            error_log('updateUser error: ' . $e->getMessage());
            return false;
        }
    }
}