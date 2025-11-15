<?php
/**
 * Mr ECU - Admin Dosya Yönetimi - DÜZELTILMIŞ VERSION
 */

require_once '../config/config.php';
require_once '../config/database.php';

// Session kontrolü
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// Admin kontrolü
if (!isLoggedIn() || !isAdmin()) {
    redirect('../login.php?error=access_denied');
}

// Gerekli sınıfları ve fonksiyonları include et
if (!function_exists('isValidUUID')) {
    require_once '../includes/functions.php';
}
require_once '../includes/FileManager.php';
require_once '../includes/User.php';

// Admin kontrolü otomatik yapılır
$fileManager = new FileManager($pdo);
$user = new User($pdo);
$error = '';
$success = '';

// Dosya durumu güncelleme
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_status'])) {
    $uploadId = sanitize($_POST['upload_id']);
    $status = sanitize($_POST['status']);
    $adminNotes = sanitize($_POST['admin_notes']);
    
    if (!isValidUUID($uploadId)) {
        $error = 'Geçersiz dosya ID formatı.';
    } else {
        if ($fileManager->updateUploadStatus($uploadId, $status, $adminNotes)) {
            $success = 'Dosya durumu başarıyla güncellendi.';
            $user->logAction($_SESSION['user_id'], 'status_update', "Dosya #{$uploadId} durumu {$status} olarak güncellendi");
        } else {
            $error = 'Durum güncellenirken hata oluştu.';
        }
    }
}

// Admin tarafından direkt dosya iptal etme
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['admin_cancel_file'])) {
    $fileId = sanitize($_POST['file_id']);
    $fileType = sanitize($_POST['file_type']);
    $adminNotes = sanitize($_POST['admin_notes']);
    
    if (!isValidUUID($fileId)) {
        $error = 'Geçersiz dosya ID formatı.';
    } else {
        // FileCancellationManager'ı yükle
        require_once '../includes/FileCancellationManager.php';
        $cancellationManager = new FileCancellationManager($pdo);
        
        $result = $cancellationManager->adminDirectCancellation($fileId, $fileType, $_SESSION['user_id'], $adminNotes);
        
        if ($result['success']) {
            $success = $result['message'];
            $user->logAction($_SESSION['user_id'], 'admin_direct_cancel', "Dosya doğrudan iptal edildi: {$fileId} ({$fileType})");
        } else {
            $error = $result['message'];
        }
    }
}

// Yanıt dosyası yükleme
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['response_file'])) {
    $uploadId = sanitize($_POST['upload_id']);
    $creditsCharged = floatval($_POST['credits_charged']);
    $responseNotes = sanitize($_POST['response_notes']);
    
    if (!isValidUUID($uploadId)) {
        $error = 'Geçersiz dosya ID formatı.';
    } elseif ($creditsCharged < 0) {
        $error = 'Kredi miktarı negatif olamaz.';
    } else {
        $result = $fileManager->uploadResponseFile($uploadId, $_FILES['response_file'], $creditsCharged, $responseNotes);
        
        if ($result['success']) {
            $success = $result['message'];
            $user->logAction($_SESSION['user_id'], 'response_upload', "Yanıt dosyası yüklendi: {$uploadId}");
        } else {
            $error = $result['message'];
        }
    }
}

// Filtreleme ve arama parametreleri
$search = isset($_POST['search']) ? sanitize($_POST['search']) : (isset($_GET['search']) ? sanitize($_GET['search']) : '');
$status = isset($_POST['status']) ? sanitize($_POST['status']) : (isset($_GET['status']) ? sanitize($_GET['status']) : '');
$brand = isset($_POST['brand']) ? sanitize($_POST['brand']) : (isset($_GET['brand']) ? sanitize($_GET['brand']) :  '');
$dateFrom = isset($_POST['date_from']) ? sanitize($_POST['date_from']) : (isset($_GET['date_from']) ? sanitize($_GET['date_from']) : '');
$dateTo = isset($_POST['date_to']) ? sanitize($_POST['date_to']) : (isset($_GET['date_to']) ? sanitize($_GET['date_to']) : '');
$uploadId = isset($_POST['id']) ? sanitize($_POST['id']) : (isset($_GET['id']) ? sanitize($_GET['id']) : '');// Belirli dosya ID'si için filtreleme
$sortBy = isset($_POST['sort']) ? sanitize($_POST['sort']) : 'upload_date';  (isset($_GET['sort']) ? sanitize($_GET['sort']) : 'upload_date');
$sortOrder = isset($_POST['order']) && $_POST['order'] === 'asc' ? 'ASC' : 'DESC'; (isset($_GET['order']) && $_GET['order'] === 'asc' ? 'ASC' : 'DESC');

// Sayfalama
$page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
$per_page = isset($_GET['per_page']) ? intval($_GET['per_page']) : 25;
// Geçerli per_page değerleri
$allowed_per_page = [10, 25, 50, 100];
if (!in_array($per_page, $allowed_per_page)) {
    $per_page = 25;
}
$limit = $per_page;
$offset = ($page - 1) * $limit;

// Dosyaları getir
try {
    $whereClause = "WHERE 1=1";
    $params = [];
    
    if ($search) {
        $whereClause .= " AND (u.original_name LIKE ? OR users.username LIKE ? OR users.email LIKE ? OR u.plate LIKE ? OR users.first_name LIKE ? OR users.last_name LIKE ? OR ecu.name LIKE ? OR d.name LIKE ?)";
        $searchParam = "%$search%";
        $params = array_merge($params, [$searchParam, $searchParam, $searchParam, $searchParam, $searchParam, $searchParam, $searchParam, $searchParam]);
    }
    
    if ($status) {
        $whereClause .= " AND u.status = ?";
        $params[] = $status;
    }
    
    if ($brand) {
        $whereClause .= " AND b.id = ?";
        $params[] = $brand;
    }
    
    if ($dateFrom) {
        $whereClause .= " AND DATE(u.upload_date) >= ?";
        $params[] = $dateFrom;
    }
    
    if ($dateTo) {
        $whereClause .= " AND DATE(u.upload_date) <= ?";
        $params[] = $dateTo;
    }
    
    // Belirli dosya ID'si için filtreleme
    if ($uploadId && isValidUUID($uploadId)) {
        $whereClause .= " AND u.id = ?";
        $params[] = $uploadId;
    }
    
    // Toplam dosya sayısı
    $countQuery = "
        SELECT COUNT(*) 
        FROM file_uploads u
        LEFT JOIN users ON u.user_id = users.id
        LEFT JOIN brands b ON u.brand_id = b.id
        LEFT JOIN ecus ecu ON u.ecu_id = ecu.id
        LEFT JOIN devices d ON u.device_id = d.id
        $whereClause
    ";
    $stmt = $pdo->prepare($countQuery);
    $stmt->execute($params);
    $totalUploads = $stmt->fetchColumn();
    
    // Dosyaları getir
    $query = "
        SELECT u.*, 
               users.username, users.email, users.first_name, users.last_name,
               b.name as brand_name,
               m.name as model_name,
               s.name as series_name,
               e.name as engine_name,
               ecu.name as ecu_name,
               d.name as device_name,
               u.is_cancelled
        FROM file_uploads u
        LEFT JOIN users ON u.user_id = users.id
        LEFT JOIN brands b ON u.brand_id = b.id
        LEFT JOIN models m ON u.model_id = m.id
        LEFT JOIN series s ON u.series_id = s.id
        LEFT JOIN engines e ON u.engine_id = e.id
        LEFT JOIN ecus ecu ON u.ecu_id = ecu.id
        LEFT JOIN devices d ON u.device_id = d.id
        $whereClause 
        ORDER BY u.$sortBy $sortOrder 
        LIMIT $limit OFFSET $offset
    ";
    
    $stmt = $pdo->prepare($query);
    $stmt->execute($params);
    $uploads = $stmt->fetchAll();
    
    $totalPages = ceil($totalUploads / $limit);
} catch(PDOException $e) {
    $uploads = [];
    $totalUploads = 0;
    $totalPages = 0;
}

// İstatistikler
try {
    $stmt = $pdo->query("
        SELECT 
            COALESCE(COUNT(*), 0) as total_uploads,
            COALESCE(SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END), 0) as pending_count,
            COALESCE(SUM(CASE WHEN status = 'processing' THEN 1 ELSE 0 END), 0) as processing_count,
            COALESCE(SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END), 0) as completed_count,
            COALESCE(SUM(CASE WHEN is_cancelled = 1 THEN 1 ELSE 0 END), 0) as rejected_count,
            COALESCE(SUM(CASE WHEN upload_date >= DATE_SUB(NOW(), INTERVAL 24 HOUR) THEN 1 ELSE 0 END), 0) as today_uploads,
            COALESCE(AVG(file_size), 0) as avg_file_size
        FROM file_uploads
    ");
    $stats = $stmt->fetch();
    
    // Null değerleri 0 ile değiştir
    $stats = array_map(function($value) {
        return $value === null ? 0 : $value;
    }, $stats);
    
} catch(PDOException $e) {
    $stats = ['total_uploads' => 0, 'pending_count' => 0, 'processing_count' => 0, 'completed_count' => 0, 'rejected_count' => 0, 'today_uploads' => 0, 'avg_file_size' => 0];
}

// Markalar listesi (filtre için)
try {
    $stmt = $pdo->query("SELECT id, name FROM brands WHERE is_active = 1 ORDER BY name");
    $brands = $stmt->fetchAll();
} catch(PDOException $e) {
    $brands = [];
}

// Sayfa bilgileri
if ($uploadId && isValidUUID($uploadId)) {
    $pageTitle = 'Dosya Detayı - ' . substr($uploadId, 0, 8) . '...';
    $pageDescription = 'Belirli dosya görüntüleniyor: ' . $uploadId;
} else {
    $pageTitle = 'Dosya Yüklemeleri';
    $pageDescription = 'Kullanıcı dosya yüklemelerini yönetin ve işleyin.';
}
$pageIcon = 'bi bi-upload';

// Header ve Sidebar include
include '../includes/admin_header.php';
include '../includes/admin_sidebar.php';
?>

<!-- Hata/Başarı Mesajları -->
<?php if ($error): ?>
    <div class="alert alert-admin alert-danger" role="alert">
        <i class="bi bi-exclamation-triangle me-2"></i>
        <?php echo $error; ?>
    </div>
<?php endif; ?>

<?php if ($success): ?>
    <div class="alert alert-admin alert-success" role="alert">
        <i class="bi bi-check-circle me-2"></i>
        <?php echo $success; ?>
    </div>
<?php endif; ?>

<!-- İstatistik Kartları -->
<div class="row g-4 mb-4">
    <a class="col-lg-3 col-md-6" href="uploads.php" style="text-decoration: none; outline: none;">
        <div class="stat-widget">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <div class="stat-number text-primary"><?php echo safe_number_format($stats['total_uploads']); ?></div>
                    <div class="stat-label">Toplam Dosya</div>
                    <small class="text-success">+<?php echo $stats['today_uploads']; ?> bugün</small>
                </div>
                <div class="bg-primary bg-opacity-10 p-3 rounded">
                    <i class="bi bi-folder2-open text-primary fa-lg"></i>
                </div>
            </div>
        </div>
    </a>
    
    <a class="col-lg-3 col-md-6" href="uploads.php?status=pending" style="text-decoration: none; outline: none;">
        <div class="stat-widget">
            <div class="d-flex justify-content-between align-items-start" >
                <div>
                    <div class="stat-number text-warning"><?php echo safe_number_format($stats['pending_count']); ?></div>
                    <div class="stat-label">Bekleyen</div>
                    <small class="text-muted">İşlem bekliyor</small>
                </div>
                <div class="bg-warning bg-opacity-10 p-3 rounded">
                    <i class="bi bi-clock text-warning fa-lg"></i>
                </div>
            </div>
        </div>
    </a>
    
    <a class="col-lg-3 col-md-6" href="uploads.php?status=processing" style="text-decoration: none; outline: none;">
        <div class="stat-widget">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <div class="stat-number text-info"><?php echo safe_number_format($stats['processing_count']); ?></div>
                    <div class="stat-label">İşleniyor</div>
                    <small class="text-muted">Aktif işlemde</small>
                </div>
                <div class="bg-info bg-opacity-10 p-3 rounded">
                    <i class="bi bi-gear-wide-connected text-info fa-lg"></i>
                </div>
            </div>
        </div>
    </a>
    
    <a class="col-lg-3 col-md-6" href="uploads.php?status=completed" style="text-decoration: none; outline: none;">
        <div class="stat-widget">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <div class="stat-number text-success"><?php echo safe_number_format($stats['completed_count']); ?></div>
                    <div class="stat-label">Tamamlanan</div>
                    <small class="text-danger"><?php echo safe_number_format($stats['rejected_count']); ?> reddedilen</small>
                </div>
                <div class="bg-success bg-opacity-10 p-3 rounded">
                    <i class="bi bi-check-circle text-success fa-lg"></i>
                </div>
            </div>
        </div>
    </a>
</div>

<!-- Filtre ve Arama -->
<div class="card mb-4">
        <div class="card-header bg-light">
            <h6 class="mb-0">
                <i class="bi bi-filter me-2"></i>Filtreler ve Arama
            </h6>
        </div>
    <div class="card-body">
        <?php if ($uploadId && isValidUUID($uploadId)): ?>
            <div class="alert-info mb-3" style=" padding: 1rem; display: flex; align-items: center;">
                <i class="bi bi-info-circle me-2"></i>
                <strong>Belirli dosya görüntüleniyor:</strong> ID: <?php echo htmlspecialchars($uploadId); ?>
                <a href="uploads.php" class="btn btn-sm btn-outline-primary ms-2">
                    <i class="bi bi-trash3 me-1"></i>Filtreyi Kaldır
                </a>
            </div>
        <?php endif; ?>
        
        <form method="POST" action="uploads.php" class="row g-3 align-items-end">
            <?php if ($uploadId && isValidUUID($uploadId)): ?>
                <input type="hidden" name="id" value="<?php echo htmlspecialchars($uploadId); ?>">
            <?php endif; ?>
            
            <div class="col-md-3">
                <label for="search" class="form-label">
                    <i class="bi bi-search me-1"></i>Arama
                </label>
                <input type="text" class="form-control" id="search" name="search" 
                       value="<?php echo htmlspecialchars($search); ?>" 
                       placeholder="Dosya adı, kullanıcı, plaka, ECU, Device...">
            </div>
            
            <div class="col-md-2">
                <label for="status" class="form-label">
                    <i class="bi bi-filter me-1"></i>Durum
                </label>
                <select class="form-select" id="status" name="status">
                    <option value="">Tüm Durumlar</option>
                    <option value="pending" <?php echo $status === 'pending' ? 'selected' : ''; ?>>Bekleyen</option>
                    <option value="processing" <?php echo $status === 'processing' ? 'selected' : ''; ?>>İşleniyor</option>
                    <option value="completed" <?php echo $status === 'completed' ? 'selected' : ''; ?>>Tamamlanan</option>
                    <option value="rejected" <?php echo $status === 'rejected' ? 'selected' : ''; ?>>Reddedilen</option>
                </select>
            </div>
            
            <div class="col-md-2">
                <label for="brand" class="form-label">
                    <i class="bi bi-car me-1"></i>Marka
                </label>
                <select class="form-select" id="brand" name="brand">
                    <option value="">Tüm Markalar</option>
                    <?php foreach ($brands as $brandOption): ?>
                        <option value="<?php echo $brandOption['id']; ?>" 
                                <?php echo $brand === $brandOption['id'] ? 'selected' : ''; ?>>
                            <?php echo htmlspecialchars($brandOption['name']); ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>
            
            <div class="col-md-2">
                <label for="date_from" class="form-label">
                    <i class="bi bi-calendar me-1"></i>Başlangıç
                </label>
                <input type="date" class="form-control" id="date_from" name="date_from" 
                       value="<?php echo htmlspecialchars($dateFrom); ?>">
            </div>
            
            <div class="col-md-2">
                <label for="date_to" class="form-label">
                    <i class="bi bi-calendar me-1"></i>Bitiş
                </label>
                <input type="date" class="form-control" id="date_to" name="date_to" 
                       value="<?php echo htmlspecialchars($dateTo); ?>">
            </div>
            
            <div class="col-md-1">
                <div class="d-flex flex-column gap-2">
                    <button type="submit" class="btn btn-primary btn-sm">
                        <i class="bi bi-search"></i>
                    </button>
                    <a href="uploads.php" class="btn btn-outline-secondary btn-sm">
                        <i class="bi bi-arrow-counterclockwise"></i>
                    </a>
                </div>
            </div>
            
            <!-- Per Page Seçimi -->
            <div class="col-md-12">
                <div class="row align-items-center">
                    <div class="col-auto">
                        <div class="d-flex align-items-center gap-2">
                            <label for="per_page" class="form-label mb-0 fw-bold">
                                <i class="bi bi-list me-1 text-primary"></i>Sayfa başına:
                            </label>
                            <select class="form-select form-select-sm px-3 py-2" id="per_page" name="per_page" style="width: 120px; border: 2px solid #e9ecef;" onchange="this.form.submit()">
                                <option value="10" <?php echo $per_page === 10 ? 'selected' : ''; ?>>10 kayıt</option>
                                <option value="25" <?php echo $per_page === 25 ? 'selected' : ''; ?>>25 kayıt</option>
                                <option value="50" <?php echo $per_page === 50 ? 'selected' : ''; ?>>50 kayıt</option>
                                <option value="100" <?php echo $per_page === 100 ? 'selected' : ''; ?>>100 kayıt</option>
                            </select>
                        </div>
                    </div>
                    <div class="col-auto">
                        <span class="badge bg-light text-dark px-3 py-2">
                            <i class="bi bi-info-circle me-1"></i>
                            Toplam <?php echo number_format($totalUploads); ?> kayıt bulundu
                        </span>
                    </div>
                </div>
            </div>
        </form>
    </div>
</div>

<!-- Modern Confirmation Modal -->
<div class="modal fade" id="processConfirmModal" tabindex="-1" aria-labelledby="processConfirmModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content border-0 shadow-lg">
            <div class="modal-header bg-gradient-primary text-white border-0">
                <h5 class="modal-title d-flex align-items-center" id="processConfirmModalLabel">
                    <i class="bi bi-exclamation-triangle me-2"></i>
                    Dosya İşleme Onayı
                </h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Kapat"></button>
            </div>
            <div class="modal-body text-center py-4">
                <div class="mb-4">
                    <div class="mx-auto mb-3 d-flex align-items-center justify-content-center" style="width: 80px; height: 80px; background: linear-gradient(135deg, #ff6b6b, #ffa500); border-radius: 50%;">
                        <i class="bi bi-folder2-open text-white fa-2x"></i>
                    </div>
                    <h6 class="mb-2 text-dark">Bu dosyayı işleme almak istediğinizden emin misiniz?</h6>
                    <p class="text-muted mb-0">Bu işlem dosyanın durumunu "İşleniyor" olarak değiştirecek ve dosya detay sayfasına yönlendirecektir.</p>
                </div>
                <div class="alert alert-info d-flex align-items-center mb-0">
                    <i class="bi bi-info-circle me-2"></i>
                    <small>Bu işlem geri alınamaz. Devam etmek istediğinizden emin olun.</small>
                </div>
            </div>
            <div class="modal-footer border-0 pt-3">
                <button type="button" class="btn btn-secondary px-4" data-bs-dismiss="modal">
                    <i class="bi bi-trash3 me-1"></i>
                    İptal
                </button>
                <button type="button" class="btn btn-success px-4" id="confirmProcessBtn" style="box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
                    <i class="bi bi-check me-1"></i>
                    Evet, İşle
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Admin İptal Modalı -->
<div class="modal fade" id="adminCancelModal" tabindex="-1" aria-labelledby="adminCancelModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content border-0 shadow-lg">
            <div class="modal-header bg-gradient-danger text-white border-0">
                <h5 class="modal-title d-flex align-items-center" id="adminCancelModalLabel">
                    <i class="bi bi-exclamation-triangle me-2"></i>
                    Dosya İptal Onayı
                </h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Kapat"></button>
            </div>
            <form method="POST" id="adminCancelForm">
                <div class="modal-body py-4">
                    <input type="hidden" name="admin_cancel_file" value="1">
                    <input type="hidden" name="file_id" id="cancelFileId">
                    <input type="hidden" name="file_type" id="cancelFileType">
                    
                    <div class="mb-4">
                        <div class="mx-auto mb-3 d-flex align-items-center justify-content-center" style="width: 80px; height: 80px; background: linear-gradient(135deg, #dc3545, #c82333); border-radius: 50%;">
                            <i class="bi bi-trash3 text-white fa-2x"></i>
                        </div>
                        <h6 class="mb-2 text-dark text-center">Bu dosyayı iptal etmek istediğinizden emin misiniz?</h6>
                        <p class="text-muted mb-3 text-center">
                            <strong>Dosya:</strong> <span id="cancelFileName"></span>
                        </p>
                        <div class="alert alert-warning d-flex align-items-center mb-3">
                            <i class="bi bi-info-circle me-2"></i>
                            <small>Bu işlem dosyayı gizleyecek ve eğer ücretli ise kullanıcıya kredi iadesi yapacaktır.</small>
                        </div>
                    </div>
                    
                    <div class="mb-3">
                        <label for="adminNotes" class="form-label">
                            <i class="bi bi-sticky-note me-1"></i>
                            İptal Sebebi (Opsiyonel)
                        </label>
                        <textarea class="form-control" id="adminNotes" name="admin_notes" rows="3" 
                                  placeholder="İptal sebebinizi yazabilirsiniz..."></textarea>
                        <small class="text-muted">Bu not kullanıcıya gönderilecek bildirimde yer alacaktır.</small>
                    </div>
                </div>
                <div class="modal-footer border-0 pt-3">
                    <button type="button" class="btn btn-secondary px-4" data-bs-dismiss="modal">
                        <i class="bi bi-trash3 me-1"></i>
                        İptal
                    </button>
                    <button type="submit" class="btn btn-danger px-4" style="box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
                        <i class="bi bi-check me-1"></i>
                        Evet, İptal Et
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Dosya Listesi -->
<div class="card admin-card">
    <div class="card-header d-flex justify-content-between align-items-center">
        <h5 class="mb-0">
            <i class="bi bi-folder2-open-upload me-2"></i>
            Dosya Yüklemeleri
        </h5>
        <div class="text-muted small">
            <?php if ($totalPages > 1): ?>
                <span class="badge bg-light text-dark">
                    Sayfa <?php echo $page; ?> / <?php echo $totalPages; ?>
                </span>
                <span class="ms-2">
                    <?php echo $totalUploads; ?> toplam kayıt
                </span>
            <?php else: ?>
                <?php echo $totalUploads; ?> dosya
            <?php endif; ?>
        </div>
    </div>
    
    <div class="card-body p-0">
        <?php if (empty($uploads)): ?>
            <div class="text-center py-5">
                <i class="bi bi-folder2-open-upload fa-3x text-muted mb-3"></i>
                <h6 class="text-muted">
                    <?php if ($search || $status || $brand || $dateFrom || $dateTo): ?>
                        Filtreye uygun dosya bulunamadı
                    <?php else: ?>
                        Henüz dosya yüklenmemiş
                    <?php endif; ?>
                </h6>
            </div>
        <?php else: ?>
            <div class="table-responsive">
                <table class="table table-admin table-hover mb-0" id="uploadsTable">
                    <thead>
                        <tr>
                            <th>Dosya Bilgileri</th>
                            <th>Kullanıcı</th>
                            <th>Araç Bilgileri</th>
                            <th>Durum</th>
                            <th>Tarih</th>
                            <th>İşlemler</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($uploads as $upload): ?>
                            <tr>
                                <td>
                                    <div class="d-flex align-items-center">
                                        <div class="file-icon me-3">
                                            <?php 
                                            $fileExtension = strtolower(pathinfo($upload['original_name'], PATHINFO_EXTENSION));
                                            $iconClass = 'bi-file-earmark';
                                            $iconColor = 'text-primary';
                                            ?>
                                            <i class="bi <?php echo $iconClass; ?> fa-2x <?php echo $iconColor; ?>"></i>
                                        </div>
                                        <div style="min-width: 0; flex: 1;">
                                            <div class="file-name mb-1">
                                                <h6 class="mb-0 text-truncate fw-semibold" style="max-width: 250px;" 
                                                    title="<?php echo htmlspecialchars($upload['original_name']); ?>">
                                                    <?php echo htmlspecialchars($upload['original_name']); ?>
                                                </h6>
                                            </div>
                                            
                                            <?php if (!empty($upload['description'])): ?>
                                                <div class="file-description">
                                                    <small class="text-muted d-block" style="max-width: 200px;" title="<?php echo htmlspecialchars($upload['description']); ?>">
                                                        <i class="bi bi-chat-text me-1"></i>
                                                        <?php echo htmlspecialchars(substr($upload['description'], 0, 50)) . (strlen($upload['description']) > 50 ? '...' : ''); ?>
                                                    </small>
                                                </div>
                                            <?php endif; ?>
                                            
                                            <!-- Dosya durum bilgisi -->
                                            <?php if (!empty($upload['response_file'])): ?>
                                                <div class="mt-1">
                                                    <small class="text-success">
                                                        <i class="bi bi-check-circle me-1"></i>
                                                        Yanıt dosyası mevcut
                                                    </small>
                                                </div>
                                            <?php endif; ?>
                                        </div>
                                    </div>
                                </td>
                                <td>
                                    <div>
                                        <h6 class="mb-1">
                                            <?php echo htmlspecialchars($upload['first_name'] . ' ' . $upload['last_name']); ?>
                                        </h6>
                                        <small class="text-muted">
                                            @<?php echo htmlspecialchars($upload['username']); ?>
                                        </small><br>
                                        <small class="text-muted">
                                            <?php echo htmlspecialchars($upload['email']); ?>
                                        </small>
                                    </div>
                                </td>
                                <td>
                                    <div>
                                        <div class="vehicle-brand mb-1">
                                            <span class="badge text-white me-1" style="background: #0b5ed7 !important; font-size: 1rem;">
                                                        <i class="bi bi-credit-card me-1"></i>
                                                        <?php echo strtoupper(htmlspecialchars($upload['plate'])); ?>
                                            </span>
                                        </div>
                                        
                                        <div class="vehicle-details mb-2">
                                            <?php 
                                            $vehicleInfo = [];
                                            if (!empty($upload['brand_name'])) {
                                                $vehicleInfo[] = '<strong class="text-primary">'. htmlspecialchars($upload['brand_name'] ?? 'Bilinmiyor').'</strong>';
                                            }
                                            if (!empty($upload['model_name'])) {
                                                $vehicleInfo[] = '<span class="fw-semibold">' . htmlspecialchars($upload['model_name']) . '</span>';
                                            }
                                            if (!empty($upload['series_name'])) {
                                                $vehicleInfo[] = htmlspecialchars($upload['series_name']);
                                            }
                                            if (!empty($upload['engine_name'])) {
                                                $vehicleInfo[] = '<em>' . htmlspecialchars($upload['engine_name']) . '</em>';
                                            }
                                            
                                            if (!empty($vehicleInfo)) {
                                                echo '<small class="text-dark">' . implode(' • ', $vehicleInfo) . '</small>';
                                            } else {
                                                echo '<small class="text-muted"><i class="bi bi-info-circle me-1"></i>Model/Seri belirtilmemiş</small>';
                                            }
                                            ?>
                                        </div>
                                        
                                        <div class="vehicle-specs">
                                            <?php if (!empty($upload['plate'])): ?>
                                                <div class="mb-1">
                                                    <?php if (!empty($upload['kilometer'])): ?>
                                                        <span class="badge bg-info text-white">
                                                            <i class="bi bi-speedometer me-1"></i>
                                                            <?php echo number_format($upload['kilometer']); ?> km
                                                        </span>
                                                    <?php endif; ?>
                                                </div>
                                            <?php endif; ?>
                                            
                                            <?php if (!empty($upload['ecu_name']) || !empty($upload['device_name']) || !empty($upload['fuel_type']) || !empty($upload['power'])): ?>
                                                <div class="additional-specs">
                                                    <?php if (!empty($upload['ecu_name'])): ?>
                                                        <span class="badge bg-success text-white me-1">
                                                            <i class="bi bi-cpu me-1"></i>
                                                            <?php echo htmlspecialchars($upload['ecu_name']); ?>
                                                        </span>
                                                    <?php endif; ?>
                                                    
                                                    <?php if (!empty($upload['device_name'])): ?>
                                                        <span class="badge bg-secondary text-white me-1">
                                                            <i class="bi bi-hdd-network me-1"></i>
                                                            <?php echo htmlspecialchars($upload['device_name']); ?>
                                                        </span>
                                                    <?php endif; ?>

                                                    <!-- <?php if (!empty($upload['fuel_type'])): ?>
                                                        <span class="badge bg-warning text-dark me-1">
                                                            <i class="bi bi-fuel-pump me-1"></i>
                                                            <?php echo htmlspecialchars($upload['fuel_type']); ?>
                                                        </span>
                                                    <?php endif; ?> -->
                                                    
                                                    <?php if (!empty($upload['power'])): ?>
                                                        <span class="badge bg-danger text-white">
                                                            <i class="bi bi-lightning me-1"></i>
                                                            <?php echo htmlspecialchars($upload['power']); ?> HP
                                                        </span>
                                                    <?php endif; ?>
                                                </div>
                                            <?php endif; ?>
                                            
                                            <?php if (empty($upload['plate']) && empty($upload['year']) && empty($upload['fuel_type']) && empty($upload['power'])): ?>
                                                <small class="text-muted">
                                                    <i class="bi bi-info-circle me-1"></i>
                                                    Ek araç bilgisi belirtilmemiş
                                                </small>
                                            <?php endif; ?>
                                        </div>
                                    </div>
                                </td>
                                <td>
                                    <?php
                                    $statusClass = [
                                        'pending' => 'warning',
                                        'processing' => 'info',
                                        'completed' => 'success',
                                        'rejected' => 'danger'
                                    ];
                                    $statusText = [
                                        'pending' => 'Bekliyor',
                                        'processing' => 'İşleniyor',
                                        'completed' => 'Tamamlandı',
                                        'rejected' => 'Reddedildi'
                                    ];
                                    $statusIcon = [
                                        'pending' => 'clock',
                                        'processing' => 'cogs',
                                        'completed' => 'check-circle',
                                        'rejected' => 'times-circle'
                                    ];
                                    
                                    // İptal edilmiş dosyalar için durum kontrolü
                                    if (isset($upload['is_cancelled']) && $upload['is_cancelled']) {
                                        $displayStatus = 'cancelled';
                                        $displayClass = 'cancelled';
                                        $displayText = 'İptal Edildi';
                                        $displayIcon = 'x-circle';
                                    } else {
                                        $displayStatus = $upload['status'];
                                        $displayClass = $statusClass[$upload['status']] ?? 'secondary';
                                        $displayText = $statusText[$upload['status']] ?? 'Bilinmiyor';
                                        $displayIcon = $statusIcon[$upload['status']] ?? 'question';
                                    }
                                    ?>
                                    <span class="badge <?php echo $displayClass === 'cancelled' ? 'badge-cancelled' : 'bg-' . $displayClass; ?> d-flex align-items-center" style="width: fit-content;">
                                        <i class="bi bi-<?php echo $displayIcon; ?> me-1"></i>
                                        <?php echo $displayText; ?>
                                    </span>
                                    
                                    <?php if (!empty($upload['admin_notes'])): ?>
                                        <div class="mt-1">
                                            <small class="text-muted" title="<?php echo htmlspecialchars($upload['admin_notes']); ?>">
                                                <i class="bi bi-comment fa-sm"></i> Admin notu
                                            </small>
                                        </div>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <div>
                                        <strong><?php echo date('d.m.Y', strtotime($upload['upload_date'])); ?></strong><br>
                                        <small class="text-muted"><?php echo date('H:i', strtotime($upload['upload_date'])); ?></small>
                                    </div>
                                </td>
                                <td>
                                    <div class="btn-group-vertical btn-group-sm" style="width: 140px;">
                                        <button type="button" class="btn btn-outline-primary btn-sm" 
                                                onclick="window.location.href='file-detail.php?id=<?php echo $upload['id']; ?>'">
                                            <i class="bi bi-eye me-1"></i>Detay
                                        </button>
                                        
                                        <!-- Görüntü Dosyası için Görüntüle Butonu -->
                                        <?php if (isImageFile($upload['original_name'])): ?>
                                            <button type="button" class="btn btn-outline-info btn-sm" 
                                                    onclick="window.location.href='view-image.php?id=<?php echo $upload['id']; ?>&type=upload'" 
                                                    title="Görüntüyü büyük boyutta gör">
                                                <i class="bi bi-image me-1"></i>Görüntüle
                                            </button>
                                        <?php endif; ?>
                                        
                                        <?php if ($upload['status'] === 'pending' && (!isset($upload['is_cancelled']) || !$upload['is_cancelled'])): ?>
                                            <button type="button" class="btn btn-outline-success btn-sm" 
                                                    onclick="processFile('<?php echo $upload['id']; ?>')">
                                                <i class="bi bi-play me-1"></i>İşleme Al
                                            </button>
                                        <?php endif; ?>
                                        
                                        <!-- Admin İptal Butonu - Tüm durumlar için -->
                                        <?php if (!isset($upload['is_cancelled']) || !$upload['is_cancelled']): ?>
                                            <button type="button" class="btn btn-outline-danger btn-sm" 
                                                    onclick="showCancelModal('<?php echo $upload['id']; ?>', 'upload', '<?php echo htmlspecialchars($upload['original_name']); ?>')" 
                                                    title="Bu dosyayı iptal et">
                                                <i class="bi bi-trash3 me-1"></i>İptal Et
                                            </button>
                                        <?php else: ?>
                                            <span class="btn btn-secondary btn-sm disabled">
                                                <i class="bi bi-ban me-1"></i>İptal Edilmiş
                                            </span>
                                        <?php endif; ?>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            
            <!-- Advanced Pagination Navigation -->
            <?php if ($totalUploads > 0): ?>
                <div class="pagination-wrapper bg-light border-top p-4">
                    <!-- Sayfa Bilgileri ve Kontroller -->
                    <div class="row align-items-center">
                        <!-- Sol taraf - Bilgi ve Hızlı Atlama -->
                        <div class="col-md-6 mb-3 mb-md-0">
                            <div class="row align-items-center g-3">
                                <div class="col-auto">
                                    <div class="pagination-info">
                                        <span class="badge bg-primary fs-6 px-3 py-2">
                                            <i class="bi bi-list-ol me-2"></i>
                                            <?php 
                                            $start = $offset + 1;
                                            $end = min($offset + $per_page, $totalUploads);
                                            echo "$start - $end / " . number_format($totalUploads);
                                            ?>
                                        </span>
                                    </div>
                                </div>
                                
                                <!-- Hızlı Sayfa Atlama -->
                                <?php if ($totalPages > 5): ?>
                                <div class="col-auto">
                                    <div class="quick-jump-container">
                                        <div class="input-group input-group-sm">
                                            <span class="input-group-text bg-white border-end-0">
                                                <i class="bi bi-search text-muted"></i>
                                            </span>
                                            <input type="number" class="form-control border-start-0" 
                                                   id="quickJump" 
                                                   min="1" 
                                                   max="<?php echo $totalPages; ?>" 
                                                   value="<?php echo $page; ?>"
                                                   placeholder="Sayfa"
                                                   style="width: 80px;"
                                                   onkeypress="if(event.key==='Enter') quickJumpToPage()"
                                                   title="Sayfa numarası girin ve Enter'a basın">
                                            <button type="button" class="btn btn-outline-primary btn-sm" 
                                                    onclick="quickJumpToPage()" 
                                                    title="Sayfaya git">
                                                <i class="bi bi-arrow-right"></i>
                                            </button>
                                        </div>
                                        <small class="text-muted d-block mt-1">/ <?php echo $totalPages; ?> sayfa</small>
                                    </div>
                                </div>
                                <?php endif; ?>
                            </div>
                        </div>
                        
                        <!-- Sağ taraf - Pagination Kontrolleri -->
                        <div class="col-md-6">
                            <nav aria-label="Sayfa navigasyonu" class="d-flex justify-content-md-end justify-content-center">
                                <ul class="pagination pagination-lg mb-0 shadow-sm">
                                    <!-- İlk Sayfa -->
                                    <li class="page-item <?php echo $page <= 1 ? 'disabled' : ''; ?>">
                                        <a class="page-link rounded-start" 
                                           href="<?php echo $page > 1 ? buildPaginationUrl(1) : '#'; ?>" 
                                           title="İlk Sayfa" 
                                           <?php echo $page <= 1 ? 'tabindex="-1"' : ''; ?>>
                                            <i class="bi bi-angle-double-left"></i>
                                            <span class="d-none d-sm-inline ms-1">İlk</span>
                                        </a>
                                    </li>
                                    
                                    <!-- Önceki Sayfa -->
                                    <li class="page-item <?php echo $page <= 1 ? 'disabled' : ''; ?>">
                                        <a class="page-link" 
                                           href="<?php echo $page > 1 ? buildPaginationUrl($page - 1) : '#'; ?>" 
                                           title="Önceki Sayfa"
                                           <?php echo $page <= 1 ? 'tabindex="-1"' : ''; ?>>
                                            <i class="bi bi-angle-left"></i>
                                            <span class="d-none d-sm-inline ms-1">Önceki</span>
                                        </a>
                                    </li>
                                    
                                    <!-- Sayfa Numaraları -->
                                    <?php
                                    $start_page = max(1, $page - 2);
                                    $end_page = min($totalPages, $page + 2);
                                    
                                    // Mobilde daha az sayfa göster
                                    if ($totalPages > 7) {
                                        $start_page = max(1, $page - 1);
                                        $end_page = min($totalPages, $page + 1);
                                    }
                                    
                                    // İlk sayfa elipsisi
                                    if ($start_page > 1): ?>
                                        <li class="page-item">
                                            <a class="page-link" href="<?php echo buildPaginationUrl(1); ?>">1</a>
                                        </li>
                                        <?php if ($start_page > 2): ?>
                                            <li class="page-item disabled d-none d-md-block">
                                                <span class="page-link">...</span>
                                            </li>
                                        <?php endif; ?>
                                    <?php endif; ?>
                                    
                                    <!-- Sayfa numaraları -->
                                    <?php for ($i = $start_page; $i <= $end_page; $i++): ?>
                                        <li class="page-item <?php echo $i === $page ? 'active' : ''; ?>">
                                            <a class="page-link <?php echo $i === $page ? 'bg-primary border-primary' : ''; ?>" 
                                               href="<?php echo buildPaginationUrl($i); ?>">
                                                <?php echo $i; ?>
                                            </a>
                                        </li>
                                    <?php endfor; ?>
                                    
                                    <!-- Son sayfa elipsisi -->
                                    <?php if ($end_page < $totalPages): ?>
                                        <?php if ($end_page < $totalPages - 1): ?>
                                            <li class="page-item disabled d-none d-md-block">
                                                <span class="page-link">...</span>
                                            </li>
                                        <?php endif; ?>
                                        <li class="page-item">
                                            <a class="page-link" href="<?php echo buildPaginationUrl($totalPages); ?>"><?php echo $totalPages; ?></a>
                                        </li>
                                    <?php endif; ?>
                                    
                                    <!-- Sonraki Sayfa -->
                                    <li class="page-item <?php echo $page >= $totalPages ? 'disabled' : ''; ?>">
                                        <a class="page-link" 
                                           href="<?php echo $page < $totalPages ? buildPaginationUrl($page + 1) : '#'; ?>" 
                                           title="Sonraki Sayfa"
                                           <?php echo $page >= $totalPages ? 'tabindex="-1"' : ''; ?>>
                                            <span class="d-none d-sm-inline me-1">Sonraki</span>
                                            <i class="bi bi-angle-right"></i>
                                        </a>
                                    </li>
                                    
                                    <!-- Son Sayfa -->
                                    <li class="page-item <?php echo $page >= $totalPages ? 'disabled' : ''; ?>">
                                        <a class="page-link rounded-end" 
                                           href="<?php echo $page < $totalPages ? buildPaginationUrl($totalPages) : '#'; ?>" 
                                           title="Son Sayfa"
                                           <?php echo $page >= $totalPages ? 'tabindex="-1"' : ''; ?>>
                                            <span class="d-none d-sm-inline me-1">Son</span>
                                            <i class="bi bi-angle-double-right"></i>
                                        </a>
                                    </li>
                                </ul>
                            </nav>
                        </div>
                    </div>
                    
                    <!-- Alt bilgi çubuğu -->
                    <div class="row mt-3 pt-3 border-top">
                        <div class="col-md-6">
                            <small class="text-muted">
                                <i class="bi bi-info-circle me-1"></i>
                                Sayfa <strong><?php echo $page; ?></strong> / <strong><?php echo $totalPages; ?></strong> - 
                                Sayfa başına <strong><?php echo $per_page; ?></strong> kayıt gösteriliyor
                            </small>
                        </div>
                        <div class="col-md-6 text-md-end">
                            <small class="text-muted">
                                <i class="bi bi-database me-1"></i>
                                Toplam <strong><?php echo number_format($totalUploads); ?></strong> dosya kayıt bulundu
                            </small>
                        </div>
                    </div>
                </div>
            <?php endif; ?>
        <?php endif; ?>
    </div>
</div>

<?php
// Pagination URL oluşturma fonksiyonu
function buildPaginationUrl($page_num) {
    $params = $_GET;
    $params['page'] = $page_num;
    return 'uploads.php?' . http_build_query($params);
}
?>

<style>
/* Advanced Pagination Styling */
.pagination-wrapper {
    background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
    border-radius: 0.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.pagination-info .badge {
    font-size: 0.9rem;
    font-weight: 500;
    letter-spacing: 0.5px;
}

.quick-jump-container .input-group {
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    border-radius: 0.375rem;
    overflow: hidden;
}

.quick-jump-container .form-control {
    border: 2px solid #e9ecef;
    transition: all 0.15s ease-in-out;
}

.quick-jump-container .form-control:focus {
    border-color: #0d6efd;
    box-shadow: 0 0 0 0.2rem rgba(13, 110, 253, 0.25);
}

/* Enhanced Pagination Controls */
.pagination-lg .page-link {
    padding: 0.75rem 1rem;
    font-size: 1rem;
    border: 2px solid #dee2e6;
    color: #495057;
    margin: 0 3px;
    border-radius: 0.5rem;
    transition: all 0.2s ease-in-out;
    font-weight: 500;
    background: white;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
}

.pagination-lg .page-link:hover {
    background: linear-gradient(135deg, #0d6efd 0%, #0b5ed7 100%);
    border-color: #0d6efd;
    color: white;
    transform: translateY(-1px);
    box-shadow: 0 4px 8px rgba(13, 110, 253, 0.3);
}

.pagination-lg .page-item.active .page-link {
    background: linear-gradient(135deg, #0d6efd 0%, #0b5ed7 100%);
    border-color: #0d6efd;
    color: white;
    box-shadow: 0 4px 12px rgba(13, 110, 253, 0.4);
    transform: scale(1.05);
}

.pagination-lg .page-item.disabled .page-link {
    background-color: #f8f9fa;
    border-color: #dee2e6;
    color: #6c757d;
    opacity: 0.6;
    cursor: not-allowed;
    box-shadow: none;
}

.pagination-lg .page-link i {
    font-size: 0.9rem;
}

/* Per page selector enhanced styling */
.form-select {
    border: 2px solid #e9ecef;
    border-radius: 0.5rem;
    transition: all 0.15s ease-in-out;
    font-weight: 500;
}

.form-select:focus {
    border-color: #0d6efd;
    box-shadow: 0 0 0 0.2rem rgba(13, 110, 253, 0.25);
}

/* Badge enhancements */
.badge.bg-light {
    background: linear-gradient(135deg, #ffffff 0%, #f8f9fa 100%) !important;
    border: 2px solid #e9ecef;
    color: #495057 !important;
    font-weight: 500;
}

/* Responsive improvements */
@media (max-width: 768px) {
    .pagination-lg .page-link {
        padding: 0.5rem 0.75rem;
        font-size: 0.9rem;
        margin: 0 1px;
    }
    
    .pagination-wrapper {
        padding: 1rem !important;
    }
    
    .quick-jump-container {
        display: none;
    }
    
    .pagination-info .badge {
        font-size: 0.8rem;
    }
}

@media (max-width: 576px) {
    .pagination-lg .page-link {
        padding: 0.4rem 0.6rem;
        font-size: 0.85rem;
    }
    
    .pagination-lg .page-link span {
        display: none !important;
    }
}

/* Animation for page changes */
.pagination-lg .page-link {
    position: relative;
    overflow: hidden;
}

.pagination-lg .page-link::before {
    content: '';
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
    transition: left 0.5s;
}

.pagination-lg .page-link:hover::before {
    left: 100%;
}

/* Loading state for quick jump */
.quick-jump-container.loading .btn {
    pointer-events: none;
}

.quick-jump-container.loading .btn i {
    animation: spin 1s linear infinite;
}

@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}

/* İptal edilmiş dosyalar için özel stil */
.badge-cancelled {
    background-color: #dc3545 !important;
    color: white !important;
    border: 1px solid #c82333;
    font-weight: 600;
    box-shadow: 0 2px 4px rgba(220, 53, 69, 0.3);
}

.badge-cancelled:hover {
    background-color: #c82333 !important;
    box-shadow: 0 4px 8px rgba(220, 53, 69, 0.4);
}

/* Modern Process Confirmation Modal Styles */
.bg-gradient-primary {
    background: linear-gradient(135deg, #0d6efd 0%, #0b5ed7 100%) !important;
}

#processConfirmModal .modal-content {
    border-radius: 1rem;
    overflow: hidden;
}

#processConfirmModal .modal-header {
    padding: 1.5rem 2rem 1rem;
    border-bottom: none;
}

#processConfirmModal .modal-body {
    padding: 1rem 2rem 1.5rem;
}

#processConfirmModal .modal-footer {
    padding: 0rem 3rem 3rem 0rem;
    background: #f8f9fa;
    margin: 0 -2rem -2rem;
    padding-top: 1.5rem;
}

#processConfirmModal .btn-lg {
    border-radius: 0.5rem;
    transition: all 0.3s ease;
}

#processConfirmModal .btn-success:hover {
    background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
    border-color: #28a745;
    transform: translateY(-2px);
}

#processConfirmModal .btn-secondary:hover {
    background: linear-gradient(135deg, #6c757d 0%, #5a6268 100%);
    border-color: #6c757d;
    transform: translateY(-2px);
}

#processConfirmModal .alert-info {
    background: linear-gradient(135deg, #d1ecf1 0%, #bee5eb 100%);
    border: 1px solid #b6d4da;
    border-radius: 0.5rem;
}

/* Modal animation enhancements */
#processConfirmModal.fade .modal-dialog {
    transition: transform 0.4s ease-out;
    transform: scale(0.8) translateY(-50px);
}

#processConfirmModal.show .modal-dialog {
    transform: scale(1) translateY(0);
}

/* Admin Cancel Modal Styling */
.bg-gradient-danger {
    background: linear-gradient(135deg, #dc3545 0%, #c82333 100%) !important;
}

#adminCancelModal .modal-content {
    border-radius: 1rem;
    overflow: hidden;
}

#adminCancelModal .modal-header {
    padding: 1.5rem 2rem 1rem;
    border-bottom: none;
}

#adminCancelModal .modal-body {
    padding: 1rem 2rem 1.5rem;
}

#adminCancelModal .modal-footer {
    padding: 0rem 3rem 3rem 0rem;
    background: #f8f9fa;
    margin: 0 -2rem -2rem;
    padding-top: 1.5rem;
}

#adminCancelModal .btn-danger:hover {
    background: linear-gradient(135deg, #c82333 0%, #bd2130 100%);
    border-color: #c82333;
    transform: translateY(-2px);
}

#adminCancelModal .btn-secondary:hover {
    background: linear-gradient(135deg, #6c757d 0%, #5a6268 100%);
    border-color: #6c757d;
    transform: translateY(-2px);
}

/* Cancel modal animation */
#adminCancelModal.fade .modal-dialog {
    transition: transform 0.4s ease-out;
    transform: scale(0.8) translateY(-50px);
}

#adminCancelModal.show .modal-dialog {
    transform: scale(1) translateY(0);
}

/* Icon pulse animation */
#processConfirmModal .fas.fa-file-alt {
    animation: pulse 2s infinite;
}

@keyframes pulse {
    0% {
        transform: scale(1);
        opacity: 1;
    }
    50% {
        transform: scale(1.1);
        opacity: 0.8;
    }
    100% {
        transform: scale(1);
        opacity: 1;
    }
}

/* Mobile responsiveness for modal */
@media (max-width: 576px) {
    #processConfirmModal .modal-header {
        padding: 1rem 1.5rem 0.5rem;
    }
    
    #processConfirmModal .modal-body {
        padding: 0.5rem 1.5rem 1rem;
    }
    
    #processConfirmModal .modal-footer {
        padding: 1rem 1.5rem 1.5rem;
        margin: 0 -1.5rem -1.5rem;
    }
    
    #processConfirmModal .btn-lg {
        padding: 0.6rem 1.5rem;
        font-size: 0.9rem;
    }
}
</style>

<script>
// Enhanced quick jump to page function
function quickJumpToPage() {
    var input = document.getElementById('quickJump');
    var page = parseInt(input.value);
    var maxPage = <?php echo $totalPages; ?>;
    var container = input.closest('.quick-jump-container');
    
    if (isNaN(page) || page < 1 || page > maxPage) {
        // Show error animation
        input.classList.add('is-invalid');
        input.style.borderColor = '#dc3545';
        
        // Show tooltip-like error
        showQuickJumpError('Lütfen 1 ile ' + maxPage + ' arasında bir sayfa numarası girin.');
        
        // Reset after 3 seconds
        setTimeout(function() {
            input.classList.remove('is-invalid');
            input.style.borderColor = '';
        }, 3000);
        
        input.focus();
        input.select();
        return;
    }
    
    if (page === <?php echo $page; ?>) {
        showQuickJumpError('Zaten bu sayfadasınız!');
        return;
    }
    
    // Show loading state
    container.classList.add('loading');
    var button = container.querySelector('.btn');
    var originalIcon = button.innerHTML;
    button.innerHTML = '<i class="bi bi-spinner fa-spin"></i>';
    
    // Build URL with current parameters but new page
    var url = new URL(window.location);
    url.searchParams.set('page', page);
    
    // Add smooth transition effect
    document.body.style.opacity = '0.8';
    
    setTimeout(function() {
        window.location.href = url.toString();
    }, 300);
}

// Show error message for quick jump
function showQuickJumpError(message) {
    var input = document.getElementById('quickJump');
    var container = input.closest('.quick-jump-container');
    
    // Remove existing error
    var existingError = container.querySelector('.quick-jump-error');
    if (existingError) {
        existingError.remove();
    }
    
    // Create error element
    var errorEl = document.createElement('div');
    errorEl.className = 'quick-jump-error alert alert-danger alert-sm mt-1 mb-0 py-1 px-2';
    errorEl.style.fontSize = '0.75rem';
    errorEl.innerHTML = '<i class="bi bi-exclamation-triangle me-1"></i>' + message;
    
    container.appendChild(errorEl);
    
    // Auto remove after 3 seconds
    setTimeout(function() {
        if (errorEl && errorEl.parentNode) {
            errorEl.style.opacity = '0';
            setTimeout(function() {
                errorEl.remove();
            }, 300);
        }
    }, 3000);
}

// Modal styling enhancement
// Enhanced modal interactions
document.addEventListener('DOMContentLoaded', function() {
    // Add enter key support for modal
    document.addEventListener('keydown', function(e) {
        var modal = document.getElementById('processConfirmModal');
        if (modal && modal.classList.contains('show')) {
            if (e.key === 'Enter') {
                e.preventDefault();
                document.getElementById('confirmProcessBtn').click();
            } else if (e.key === 'Escape') {
                var modalInstance = bootstrap.Modal.getInstance(modal);
                modalInstance.hide();
            }
        }
    });
    
    // Add focus to confirm button when modal opens
    var processModal = document.getElementById('processConfirmModal');
    if (processModal) {
        processModal.addEventListener('shown.bs.modal', function() {
            document.getElementById('confirmProcessBtn').focus();
        });
    }
});

// Enhanced keyboard navigation
document.addEventListener('keydown', function(e) {
    // Don't interfere if user is typing in an input
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.isContentEditable) {
        return;
    }
    
    var currentPage = <?php echo $page; ?>;
    var totalPages = <?php echo $totalPages; ?>;
    
    switch(e.key) {
        case 'ArrowLeft':
        case 'h':
            if (currentPage > 1) {
                window.location.href = '<?php echo buildPaginationUrl($page - 1); ?>';
            }
            break;
        case 'ArrowRight':
        case 'l':
            if (currentPage < totalPages) {
                window.location.href = '<?php echo buildPaginationUrl($page + 1); ?>';
            }
            break;
        case 'Home':
            if (currentPage > 1) {
                window.location.href = '<?php echo buildPaginationUrl(1); ?>';
            }
            break;
        case 'End':
            if (currentPage < totalPages) {
                window.location.href = '<?php echo buildPaginationUrl($totalPages); ?>';
            }
            break;
        case 'g':
            document.getElementById('quickJump')?.focus();
            break;
    }
});

// Add smooth page transition
document.addEventListener('DOMContentLoaded', function() {
    // Add fade-in effect
    document.body.style.opacity = '0';
    setTimeout(function() {
        document.body.style.transition = 'opacity 0.3s';
        document.body.style.opacity = '1';
    }, 50);
    
    // Enhanced per-page selector
    var perPageSelect = document.getElementById('per_page');
    if (perPageSelect) {
        perPageSelect.addEventListener('change', function() {
            this.style.borderColor = '#0d6efd';
            this.style.boxShadow = '0 0 0 0.2rem rgba(13, 110, 253, 0.25)';
            
            setTimeout(function() {
                perPageSelect.form.submit();
            }, 200);
        });
    }
    
    // Add hover effects to pagination
    var pageLinks = document.querySelectorAll('.pagination .page-link');
    pageLinks.forEach(function(link) {
        link.addEventListener('mouseenter', function() {
            if (!this.closest('.page-item').classList.contains('active') && 
                !this.closest('.page-item').classList.contains('disabled')) {
                this.style.transform = 'translateY(-2px)';
            }
        });
        
        link.addEventListener('mouseleave', function() {
            this.style.transform = '';
        });
    });
});

// Process file function with modern modal
var currentProcessUploadId = null;
var currentProcessButton = null;

function processFile(uploadId) {
    console.log('ProcessFile başlatıldı - Upload ID:', uploadId);
    
    // Store current upload ID and button for later use
    currentProcessUploadId = uploadId;
    currentProcessButton = event.target;
    
    // Show modern confirmation modal
    var modal = new bootstrap.Modal(document.getElementById('processConfirmModal'));
    modal.show();
}

// Modal confirmation handler
document.addEventListener('DOMContentLoaded', function() {
    var confirmBtn = document.getElementById('confirmProcessBtn');
    if (confirmBtn) {
        confirmBtn.addEventListener('click', function() {
            if (currentProcessUploadId && currentProcessButton) {
                console.log('Kullanıcı modal ile onayladı, durum güncelleniyor...');
                
                // Modal'ı kapat
                var modal = bootstrap.Modal.getInstance(document.getElementById('processConfirmModal'));
                modal.hide();
                
                // Loading indicator göster
                var originalText = currentProcessButton.innerHTML;
                currentProcessButton.innerHTML = '<i class="bi bi-spinner fa-spin me-1"></i>Yükleniyor...';
                currentProcessButton.disabled = true;
                
                // Status güncelle
                updateFileStatus(currentProcessUploadId, 'processing', 'Dosya işleme alındı', true);
                
                // Reset variables
                currentProcessUploadId = null;
                currentProcessButton = null;
            }
        });
    }
    
    // Modal kapandığında variables'ları temizle
    var processModal = document.getElementById('processConfirmModal');
    if (processModal) {
        processModal.addEventListener('hidden.bs.modal', function() {
            currentProcessUploadId = null;
            currentProcessButton = null;
        });
    }
});

// Admin Cancel Modal Functions
function showCancelModal(fileId, fileType, fileName) {
    document.getElementById('cancelFileId').value = fileId;
    document.getElementById('cancelFileType').value = fileType;
    document.getElementById('cancelFileName').textContent = fileName;
    document.getElementById('adminNotes').value = '';
    
    var modal = new bootstrap.Modal(document.getElementById('adminCancelModal'));
    modal.show();
}

// Update file status function
function updateFileStatus(uploadId, status, notes, redirectToDetail) {
    notes = notes || '';
    redirectToDetail = redirectToDetail || false;
    
    var formData = new FormData();
    formData.append('update_status', '1');
    formData.append('upload_id', uploadId);
    formData.append('status', status);
    formData.append('admin_notes', notes);
    
    console.log('AJAX isteği gönderiliyor...');
    
    fetch('uploads.php', {
        method: 'POST',
        body: formData
    })
    .then(function(response) {
        console.log('Response alındı:', response.status, response.statusText);
        
        if (!response.ok) {
            throw new Error('HTTP hatası: ' + response.status);
        }
        
        return response.text();
    })
    .then(function(data) {
        console.log('Response data:', data.substring(0, 200) + '...');
        
        if (redirectToDetail) {
            console.log('Detay sayfasına yönlendiriliyor...');
            window.location.href = 'file-detail.php?id=' + uploadId;
        } else {
            console.log('Sayfa yenileniyor...');
            location.reload();
        }
    })
    .catch(function(error) {
        console.error('UpdateFileStatus hatası:', error);
        alert('Güncelleme sırasında hata oluştu: ' + error.message);
        
        // Button'ı eski haline döndür
        var buttons = document.querySelectorAll('button:disabled');
        for (var i = 0; i < buttons.length; i++) {
            var btn = buttons[i];
            if (btn.innerHTML.includes('Yükleniyor')) {
                btn.innerHTML = '<i class="bi bi-play me-1"></i>İşle';
                btn.disabled = false;
            }
        }
    });
}
</script>
<script>
// Bu script'i sayfanın sonuna, </body> etiketinden önce ekleyin
document.addEventListener('DOMContentLoaded', function() {
    var searchForm = document.querySelector('form[method="GET"]'); // Formu seçer
    var searchInput = document.getElementById('search');
    
    if(searchForm && searchInput) {
        searchForm.addEventListener('submit', function(e) {
            // Arama alanında değer varsa ve bu değeri biz kodlamadıysak
            if(searchInput.value) {
                // Formun normal gönderimini durdur
                e.preventDefault();
                
                // Mevcut URL'deki tüm parametreleri al
                const params = new URLSearchParams(window.location.search);
                
                // 'search' parametresini yeni kodlanmış değerle güncelle
                params.set('search', searchInput.value);
                
                // Sayfayı yeni URL ile yeniden yönlendir
                window.location.href = window.location.pathname + '?' + params.toString();
            }
        });
    }
});
</script>

<?php
// Footer include
include '../includes/admin_footer.php';
?>
