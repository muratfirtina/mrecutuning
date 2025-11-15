<?php
/**
 * Mr ECU - Kullanıcı Giriş Sayfası (Geliştirilmiş Tasarım)
 */
require_once 'config/config.php';
require_once 'config/database.php';

// GÜVENLİK SINIFI BAŞLATILDI
$security = new SecurityManager($pdo);

// Zaten giriş yapmışsa yönlendir
if (isLoggedIn()) {
    redirect(isAdmin() ? 'admin/' : 'user/');
}

$error = '';
$success = '';
$showEmailVerification = false;
$userEmail = '';

// URL parametrelerinden hata mesajlarını al
if (isset($_GET['error'])) {
    switch ($_GET['error']) {
        case 'session_invalid':
            $error = 'Oturumunuz geçersiz hale gelmiş. Lütfen tekrar giriş yapın.';
            break;
        case 'access_denied':
            $error = 'Bu sayfaya erişim yetkiniz yok.';
            break;
        case 'user_not_found':
            $error = 'Kullanıcı hesabı bulunamadı veya silinmiş.';
            break;
        default:
            $error = 'Bir hata oluştu. Lütfen tekrar deneyin.';
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF TOKEN KONTROLÜ
    if (!isset($_POST['csrf_token']) || !$security->validateCsrfToken($_POST['csrf_token'])) {
        $error = 'Geçersiz istek. Lütfen formu yeniden gönderin.';
    } else {
        $email = sanitize($_POST['email']);
        $password = $_POST['password'];
        $remember = isset($_POST['remember']);
        
        if (empty($email) || empty($password)) {
            $error = 'Email ve şifre alanları zorunludur.';
        } else {
            // BRUTE-FORCE KONTROLÜ YAPILDI
            if (!$security->checkBruteForce($email, 5, 900)) {
                $error = 'Çok fazla başarısız deneme. 15 dakika bekleyin.';
            } else {
                $user = new User($pdo);
                $loginResult = $user->login($email, $password);
                
                if ($loginResult['success']) {
                    // OTURUM YENİLEME (SESSION FIXATION KORUMASI)
                    session_regenerate_id(true);
                    $_SESSION['user_id'] = $loginResult['user_id'];
                    
                    if ($remember) {
                        $rememberToken = generateToken();
                        $user->setRememberToken($_SESSION['user_id'], $rememberToken);
                        setcookie('remember_token', $rememberToken, time() + (30 * 24 * 60 * 60), '/', '', false, true);
                    }
                    
                    $redirect = isset($_GET['redirect']) ? $_GET['redirect'] : (isAdmin() ? 'admin/' : 'user/');
                    redirect($redirect);
                } else {
                    // BAŞARISIZ DENEME KAYDI
                    $security->recordBruteForceAttempt($email);
                    
                    $error = $loginResult['message'];
                    // Email doğrulama gerekiyorsa özel mesaj
                    if (strpos($error, 'Email adresinizi doğrula') !== false) {
                        $showEmailVerification = true;
                        $userEmail = $email;
                    }
                }
            }
        }
    }
}

// CSRF TOKEN OLUŞTUR
$csrfToken = $security->generateCsrfToken();

$pageTitle = 'Giriş Yap';
$pageDescription = 'Mr ECU hesabınızla giriş yapın ve profesyonel ECU hizmetlerimizden faydalanın.';
$pageKeywords = 'giriş, login, kullanıcı girişi, ECU hizmetleri';
$bodyClass = 'bg-dark';
include 'includes/header.php';
?>

<section class="py-5" style="min-height: 100vh; display: flex; align-items: center; background: url('https://images.unsplash.com/photo-1558618666-fcd25c85cd64?w=1920&h=1080&fit=crop') center/cover fixed; position: relative;">
    <div style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; background: rgba(44, 62, 80, 0.7); z-index: 1;"></div>
    <div class="container" style="position: relative; z-index: 2;">
        <div class="row justify-content-center">
            <!-- Login Card -->
            <div class="col-lg-4 col-md-6 mb-4">
                <div class="flip-card" style="width: 100%; height: 500px; perspective: 1000px;">
                    <div class="flip-card-inner" style="position: relative; width: 100%; height: 100%; transition: transform 0.8s; transform-style: preserve-3d;">
                        <div class="flip-card-front" style="
                            position: absolute;
                            width: 100%;
                            height: 100%;
                            backface-visibility: hidden;
                            background: linear-gradient(135deg, #dc3545, #c82333);
                            color: white;
                            padding: 2rem;
                            border-radius: 16px;
                            box-shadow: 0 15px 35px rgba(0,0,0,0.3);
                            display: flex;
                            flex-direction: column;
                            justify-content: center;
                            text-align: center;
                            backdrop-filter: blur(10px);
                            border: 1px solid rgba(255,255,255,0.2);
                        ">
                            <i class="bi bi-sign-in-alt" style="font-size: 5rem; margin-bottom: 1rem; opacity: 0.8;"></i>
                            <h3 class="fw-bold mb-3">Hoş Geldiniz</h3>
                            <p style="opacity: 0.9;">Hesabınıza giriş yapın ve ECU hizmetlerinden faydalanmaya başlayın.</p>
                            <button type="button" class="btn btn-light mt-4" onclick="flipCard(true)" style="align-self: center;">
                                <i class="bi bi-person-plus me-2"></i> Kayıt Ol
                            </button>
                        </div>

                        <div class="flip-card-back" style="
                            position: absolute;
                            width: 100%;
                            height: 100%;
                            backface-visibility: hidden;
                            background: linear-gradient(135deg, #002d5b, #003469);
                            color: white;
                            transform: rotateY(180deg);
                            padding: 2rem;
                            border-radius: 16px;
                            box-shadow: 0 15px 35px rgba(0,0,0,0.3);
                            display: flex;
                            flex-direction: column;
                            justify-content: center;
                            text-align: center;
                            backdrop-filter: blur(10px);
                            border: 1px solid rgba(255,255,255,0.1);
                        ">
                            <i class="bi bi-person-plus" style="font-size: 5rem; margin-bottom: 1rem; opacity: 0.8;"></i>
                            <h3 class="fw-bold mb-3">Hesap Oluştur</h3>
                            <p style="opacity: 0.9;">Yeni bir hesapla tüm özelliklerden faydalanın.</p>
                            <a href="register.php" class="btn btn-outline-light mt-4" style="align-self: center;">
                                <i class="bi bi-arrow-right me-2"></i> Kayıt Ol
                            </a>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Login Form -->
            <div class="col-lg-5 col-md-7">
                <div class="card border-0 shadow-lg" style="
                    background: rgba(255, 255, 255, 0.95);
                    backdrop-filter: blur(12px);
                    border-radius: 20px;
                    overflow: hidden;
                    box-shadow: 0 20px 50px rgba(0,0,0,0.2);
                ">
                    <div class="card-header text-center py-4" style="background: linear-gradient(45deg, #e91c1c, #fd6060); color: white;">
                        <h3 class="mb-0"><i class="bi bi-sign-in-alt me-2"></i> Giriş Yap</h3>
                        <p class="mb-0 mt-1" style="opacity: 0.85;">Hesabınıza güvenli giriş</p>
                    </div>
                    <div class="card-body p-5">
                        <?php if ($error): ?>
                            <div class="alert alert-danger border-0 rounded-4 text-center" style="background: #f8d7da; color: #721c24;">
                                <i class="bi bi-exclamation-triangle me-2"></i> <?php echo $error; ?>
                            </div>
                            
                            <?php if ($showEmailVerification): ?>
                            <div class="alert alert-info border-0 rounded-4 mt-3" style="background: #d1ecf1; color: #0c5460;">
                                <div class="text-center">
                                    <i class="bi bi-envelope-check" style="font-size: 2rem; color: #0dcaf0;"></i>
                                    <h6 class="mt-2 mb-3">Email Doğrulama Gerekli</h6>
                                    <p class="mb-3 small">
                                        Hesabınıza giriş yapabilmek için email adresinizi doğrulamanız gerekmektedir.
                                    </p>
                                    <div class="d-grid gap-2">
                                        <a href="verify.php" class="btn btn-info btn-sm">
                                            <i class="bi bi-envelope-check me-1"></i>Email Doğrula
                                        </a>
                                        <form method="POST" action="verify.php" style="display: inline;">
                                            <input type="hidden" name="resend_email" value="1">
                                            <input type="hidden" name="email" value="<?php echo htmlspecialchars($userEmail); ?>">
                                            <button type="submit" class="btn btn-outline-info btn-sm w-100">
                                                <i class="bi bi-send me-1"></i>Doğrulama Emaili Yeniden Gönder
                                            </button>
                                        </form>
                                    </div>
                                </div>
                            </div>
                            <?php endif; ?>
                        <?php endif; ?>

                        <form method="POST" action="" id="loginForm">
                            <!-- CSRF TOKEN EKLENDİ -->
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken); ?>">

                            <div class="mb-4">
                                <label class="form-label fw-semibold">E-posta</label>
                                <input type="email" name="email" class="form-control form-control-lg" 
                                       placeholder="ornek@email.com" required
                                       value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>">
                            </div>

                            <div class="mb-4">
                                <label class="form-label fw-semibold">Şifre</label>
                                <div class="input-group">
                                    <input type="password" name="password" id="password" class="form-control form-control-lg"
                                           placeholder="••••••••" required>
                                    <button type="button" class="btn btn-outline-secondary" onclick="togglePassword()">
                                        <i class="bi bi-eye" id="toggleIcon"></i>
                                    </button>
                                </div>
                            </div>

                            <div class="mb-4 d-flex justify-content-between">
                                <div class="form-check">
                                    <input type="checkbox" class="form-check-input" id="remember" name="remember">
                                    <label class="form-check-label" for="remember">Beni hatırla</label>
                                </div>
                                <a href="forgot-password.php" class="text-decoration-none text-danger fw-medium">Şifremi unuttum?</a>
                            </div>

                            <button type="submit" class="btn btn-danger btn-lg w-100 rounded-4 py-3 fw-bold"
                                    style="background: linear-gradient(135deg, #dc3545, #c82333); border: none;">
                                <i class="bi bi-sign-in-alt me-2"></i> Giriş Yap
                            </button>
                        </form>

                        <div class="text-center mt-4">
                            <p class="text-muted small">Hesabınız yok mu? 
                                <a href="register.php" class="text-danger fw-bold text-decoration-none">Kayıt olun</a>
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</section>

<script>
function togglePassword() {
    const input = document.getElementById('password');
    const icon = document.getElementById('toggleIcon');
    if (input.type === 'password') {
        input.type = 'text';
        icon.className = 'bi bi-eye-slash';
    } else {
        input.type = 'password';
        icon.className = 'bi bi-eye';
    }
}

function flipCard(toBack = false) {
    const inner = document.querySelector('.flip-card-inner');
    inner.style.transform = toBack ? 'rotateY(180deg)' : 'rotateY(0deg)';
}
</script>

<style>
    .flip-card:hover .flip-card-inner {
        transform: rotateY(180deg);
    }
    @media (max-width: 768px) {
        .flip-card { height: 400px !important; }
        .card-body { padding: 2rem 1.5rem; }
    }
</style>

<?php include 'includes/footer.php'; ?>