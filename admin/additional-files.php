<?php
/**
 * Mr ECU - Admin Ek Dosyalar Yönetimi
 * Additional files management with admin cancel functionality
 */

require_once '../config/config.php';
require_once '../config/database.php';
require_once '../includes/functions.php';
require_once '../includes/FileManager.php';
require_once '../includes/User.php';

// Session kontrolü
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// Admin kontrolü
if (!isLoggedIn() || !isAdmin()) {
    redirect('../login.php?error=access_denied');
}

$user = new User($pdo);
$fileManager = new FileManager($pdo);
$error = '';
$success = '';

// URL'den mesajları al
if (isset($_GET['success'])) {
    $success = sanitize($_GET['success']);
}
if (isset($_GET['error'])) {
    $error = sanitize($_GET['error']);
}

// Session mesajlarını al ve temizle
if (isset($_SESSION['error'])) {
    $error = $_SESSION['error'];
    unset($_SESSION['error']);
}
if (isset($_SESSION['success'])) {
    $success = $_SESSION['success'];
    unset($_SESSION['success']);
}

// POST işlemleri
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // Admin tarafından direkt dosya iptal etme
    if (isset($_POST['admin_cancel_file'])) {
        $cancelFileId = sanitize($_POST['file_id']);
        $cancelFileType = sanitize($_POST['file_type']);
        $adminNotes = sanitize($_POST['admin_notes']);
        
        if (!isValidUUID($cancelFileId)) {
            $_SESSION['error'] = 'Geçersiz dosya ID formatı.';
        } else {
            // FileCancellationManager'ı yükle
            require_once '../includes/FileCancellationManager.php';
            $cancellationManager = new FileCancellationManager($pdo);
            
            $result = $cancellationManager->adminDirectCancellation($cancelFileId, $cancelFileType, $_SESSION['user_id'], $adminNotes);
            
            if ($result['success']) {
                $_SESSION['success'] = $result['message'];
                $user->logAction($_SESSION['user_id'], 'admin_direct_cancel', "Ek dosya doğrudan iptal edildi: {$cancelFileId}");
            } else {
                $_SESSION['error'] = $result['message'];
            }
        }
        
        // Redirect to prevent form resubmission
        header("Location: additional-files.php");
        exit;
    }
}

// Filtreleme parametreleri
$page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
$per_page = isset($_GET['per_page']) ? max(10, min(100, intval($_GET['per_page']))) : 20;
$limit = $per_page;
$offset = ($page - 1) * $limit;
$search = isset($_GET['search']) ? sanitize($_GET['search']) : '';
$status = isset($_GET['status']) ? sanitize($_GET['status']) : '';
$sender_type = isset($_GET['sender_type']) ? sanitize($_GET['sender_type']) : '';
$dateFrom = isset($_GET['date_from']) ? sanitize($_GET['date_from']) : '';
$dateTo = isset($_GET['date_to']) ? sanitize($_GET['date_to']) : '';

// Ek dosyaları getir
try {
    $whereConditions = [];
    $params = [];
    
    if (!empty($search)) {
        $whereConditions[] = "(af.original_name LIKE ? OR af.file_name LIKE ? OR sender_user.username LIKE ? OR receiver_user.username LIKE ? OR fu.plate LIKE ? OR ecu.name LIKE ? OR d.name LIKE ?)";
        $searchTerm = "%{$search}%";
        $params = array_merge($params, [$searchTerm, $searchTerm, $searchTerm, $searchTerm, $searchTerm, $searchTerm, $searchTerm]);
    }
    
    if (!empty($status)) {
        if ($status === 'cancelled') {
            $whereConditions[] = "af.is_cancelled = 1";
        } else if ($status === 'active') {
            $whereConditions[] = "(af.is_cancelled = 0 OR af.is_cancelled IS NULL)";
        }
    }
    
    if (!empty($sender_type)) {
        $whereConditions[] = "af.sender_type = ?";
        $params[] = $sender_type;
    }
    
    if (!empty($dateFrom)) {
        $whereConditions[] = "DATE(af.upload_date) >= ?";
        $params[] = $dateFrom;
    }
    
    if (!empty($dateTo)) {
        $whereConditions[] = "DATE(af.upload_date) <= ?";
        $params[] = $dateTo;
    }
    
    $whereClause = !empty($whereConditions) ? 'WHERE ' . implode(' AND ', $whereConditions) : '';
    
    // Toplam kayıt sayısı - Tüm JOIN'ler eklendi
    $totalQuery = "
        SELECT COUNT(*) 
        FROM additional_files af
        LEFT JOIN users sender_user ON af.sender_id = sender_user.id
        LEFT JOIN users receiver_user ON af.receiver_id = receiver_user.id
        LEFT JOIN file_uploads fu ON af.related_file_id = fu.id AND af.related_file_type = 'upload'
        LEFT JOIN ecus ecu ON fu.ecu_id = ecu.id
        LEFT JOIN devices d ON fu.device_id = d.id
        $whereClause
    ";
    $totalStmt = $pdo->prepare($totalQuery);
    $totalStmt->execute($params);
    $totalRecords = $totalStmt->fetchColumn();
    
    // Sayfalama
    $totalPages = ceil($totalRecords / $limit);
    
    // Ana sorgu - Araç bilgilerini ekledik
    $query = "
        SELECT af.*,
               sender_user.username as sender_username,
               sender_user.email as sender_email,
               receiver_user.username as receiver_username,
               receiver_user.email as receiver_email,
               CASE 
                   WHEN af.related_file_type = 'upload' THEN fu.original_name
                   WHEN af.related_file_type = 'response' THEN fr.original_name
                   WHEN af.related_file_type = 'revision' THEN rf.original_name
                   ELSE 'Bilinmiyor'
               END as related_file_name,
               fu.plate as vehicle_plate,
               ecu.name as ecu_name,
               d.name as device_name
        FROM additional_files af
        LEFT JOIN users sender_user ON af.sender_id = sender_user.id
        LEFT JOIN users receiver_user ON af.receiver_id = receiver_user.id
        LEFT JOIN file_uploads fu ON af.related_file_id = fu.id AND af.related_file_type = 'upload'
        LEFT JOIN file_responses fr ON af.related_file_id = fr.id AND af.related_file_type = 'response'
        LEFT JOIN revision_files rf ON af.related_file_id = rf.id AND af.related_file_type = 'revision'
        LEFT JOIN ecus ecu ON fu.ecu_id = ecu.id
        LEFT JOIN devices d ON fu.device_id = d.id
        $whereClause
        ORDER BY af.upload_date DESC
        LIMIT $limit OFFSET $offset
    ";
    
    $stmt = $pdo->prepare($query);
    $stmt->execute($params);
    $additionalFiles = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
} catch (Exception $e) {
    $error = 'Ek dosyalar getirilirken hata oluştu: ' . $e->getMessage();
    $additionalFiles = [];
    $totalRecords = 0;
    $totalPages = 0;
}

// Sayfa başlığı
$pageTitle = 'Ek Dosyalar Yönetimi';
include '../includes/admin_header.php';
include '../includes/admin_sidebar.php';
?>

<div class="container-fluid">
    <!-- Başlık ve İstatistikler -->
    <div class="row mb-4">
        <div class="col-12">
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <h1 class="h3 mb-0">
                        <i class="bi bi-paperclip text-primary me-2"></i>
                        Ek Dosyalar Yönetimi
                    </h1>
                    <p class="text-muted mb-0">Kullanıcılar ve adminler tarafından paylaşılan ek dosyaları yönetin</p>
                </div>
                <div class="text-end">
                    <span class="badge bg-info fs-6">Toplam: <?php echo number_format($totalRecords); ?></span>
                </div>
            </div>
        </div>
    </div>

    <!-- Bildirimler -->
    <?php if ($error): ?>
        <div class="alert alert-danger alert-dismissible fade show" role="alert">
            <i class="bi bi-exclamation-circle me-2"></i><?php echo $error; ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    <?php endif; ?>

    <?php if ($success): ?>
        <div class="alert alert-success alert-dismissible fade show" role="alert">
            <i class="bi bi-check-circle me-2"></i><?php echo $success; ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    <?php endif; ?>

    <!-- Filtreler -->
    <div class="card mb-4">
        <div class="card-header bg-light">
            <h6 class="mb-0">
                <i class="bi bi-filter me-2"></i>Filtreler ve Arama
            </h6>
        </div>
        <div class="card-body">
            <form method="GET" class="row g-3 align-items-end">
                <div class="col-md-2">
                    <label class="form-label">Arama</label>
                    <input type="text" name="search" class="form-control" 
                           placeholder="Dosya adı, kullanıcı, araç..." value="<?php echo htmlspecialchars($search); ?>">
                </div>
                <div class="col-md-2">
                    <label class="form-label">Durum</label>
                    <select name="status" class="form-select">
                        <option value="">Tümü</option>
                        <option value="active" <?php echo $status === 'active' ? 'selected' : ''; ?>>Aktif</option>
                        <option value="cancelled" <?php echo $status === 'cancelled' ? 'selected' : ''; ?>>İptal Edilmiş</option>
                    </select>
                </div>
                <div class="col-md-2">
                    <label class="form-label">Gönderen</label>
                    <select name="sender_type" class="form-select">
                        <option value="">Tümü</option>
                        <option value="user" <?php echo $sender_type === 'user' ? 'selected' : ''; ?>>Kullanıcı</option>
                        <option value="admin" <?php echo $sender_type === 'admin' ? 'selected' : ''; ?>>Admin</option>
                    </select>
                </div>
                <div class="col-md-2">
                    <label class="form-label">Başlangıç Tarihi</label>
                    <input type="date" name="date_from" class="form-control" value="<?php echo htmlspecialchars($dateFrom); ?>">
                </div>
                <div class="col-md-2">
                    <label class="form-label">Bitiş Tarihi</label>
                    <input type="date" name="date_to" class="form-control" value="<?php echo htmlspecialchars($dateTo); ?>">
                </div>
                <div class="col-md-1 d-flex align-items-end">
                    <div class="d-flex flex-column gap-2">
                    <button type="submit" class="btn btn-primary me-2">
                        <i class="bi bi-search me-1"></i>Filtrele
                    </button>
                    <a href="additional-files.php" class="btn btn-outline-secondary">
                        <i class="bi bi-trash3 me-1"></i>Temizle
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
                            Toplam <?php echo number_format ($totalRecords); ?> kayıt
                        </span>
                    </div>
                </div>
            </div>
            </form>
        </div>
    </div>

    <!-- Ek Dosyalar Tablosu -->
    <div class="card">
        <div class="card-body">
            <?php if (!empty($additionalFiles)): ?>
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead class="table-light">
                            <tr>
                                <th>Dosya Bilgileri</th>
                                <th>İlgili Dosya</th>
                                <th>Araç Bilgileri</th>
                                <th>Gönderen</th>
                                <th>Alan</th>
                                <th>Kredi</th>
                                <th>Tarih</th>
                                <th>Durum</th>
                                <th>İşlemler</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($additionalFiles as $file): ?>
                                <tr>
                                    <td>
                                        <div class="d-flex align-items-center">
                                            <i class="bi bi-folder2-open text-info me-2"></i>
                                            <div style="max-width: 200px;">
                                                <div class="fw-bold text-truncate" title="<?php echo htmlspecialchars($file['original_name']); ?>">
                                                    <?php echo htmlspecialchars($file['original_name']); ?>
                                                </div>
                                                <small class="text-muted"><?php echo formatFileSize($file['file_size']); ?></small>
                                            </div>
                                        </div>
                                    </td>
                                    <td>
                                        <div style="max-width: 150px;">
                                            <span class="badge bg-secondary text-uppercase"><?php echo $file['related_file_type']; ?></span>
                                            <br><small class="text-muted text-truncate d-block" title="<?php echo htmlspecialchars($file['related_file_name']); ?>"><?php echo htmlspecialchars($file['related_file_name']); ?></small>
                                        </div>
                                    </td>
                                    <td>
                                        <div>
                                            <?php if (!empty($file['vehicle_plate'])): ?>
                                                <span class="badge bg-primary text-white mb-1">
                                                    <i class="bi bi-credit-card me-1"></i>
                                                    <?php echo strtoupper(htmlspecialchars($file['vehicle_plate'])); ?>
                                                </span>
                                                <br>
                                            <?php endif; ?>
                                            
                                            <?php if (!empty($file['ecu_name'])): ?>
                                                <span class="badge bg-success text-white me-1">
                                                    <i class="bi bi-cpu me-1"></i>
                                                    <?php echo htmlspecialchars($file['ecu_name']); ?>
                                                </span>
                                            <?php endif; ?>
                                            
                                            <?php if (!empty($file['device_name'])): ?>
                                                <span class="badge bg-secondary text-white">
                                                    <i class="bi bi-hdd-network me-1"></i>
                                                    <?php echo htmlspecialchars($file['device_name']); ?>
                                                </span>
                                            <?php endif; ?>
                                            
                                            <?php if (empty($file['vehicle_plate']) && empty($file['ecu_name']) && empty($file['device_name'])): ?>
                                                <small class="text-muted">
                                                    <i class="bi bi-info-circle me-1"></i>
                                                    Bilgi yok
                                                </small>
                                            <?php endif; ?>
                                        </div>
                                    </td>
                                    <td>
                                        <div>
                                            <span class="badge bg-<?php echo $file['sender_type'] === 'admin' ? 'warning' : 'primary'; ?>">
                                                <?php echo $file['sender_type'] === 'admin' ? 'Admin' : 'Kullanıcı'; ?>
                                            </span>
                                            <br><small class="text-muted"><?php echo htmlspecialchars($file['sender_username'] ?? 'Bilinmiyor'); ?></small>
                                        </div>
                                    </td>
                                    <td>
                                        <div>
                                            <span class="badge bg-<?php echo $file['receiver_type'] === 'admin' ? 'warning' : 'primary'; ?>">
                                                <?php echo $file['receiver_type'] === 'admin' ? 'Admin' : 'Kullanıcı'; ?>
                                            </span>
                                            <br><small class="text-muted"><?php echo htmlspecialchars($file['receiver_username'] ?? 'Bilinmiyor'); ?></small>
                                        </div>
                                    </td>
                                    <td>
                                        <?php if ($file['credits'] > 0): ?>
                                            <span class="badge bg-warning">
                                                <?php echo number_format($file['credits'], 2); ?> kredi
                                            </span>
                                        <?php else: ?>
                                            <span class="text-muted">Ücretsiz</span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <small><?php echo formatDate($file['upload_date']); ?></small>
                                    </td>
                                    <td>
                                        <?php if ($file['is_cancelled']): ?>
                                            <span class="badge bg-danger">İptal Edilmiş</span>
                                            <?php if ($file['cancelled_at']): ?>
                                                <br><small class="text-muted"><?php echo formatDate($file['cancelled_at']); ?></small>
                                            <?php endif; ?>
                                        <?php else: ?>
                                            <span class="badge bg-success">Aktif</span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <div class="btn-group">
                                            <?php if ($file['is_cancelled']): ?>
                                                <span class="btn btn-sm btn-secondary disabled">
                                                    <i class="bi bi-ban me-1"></i>İptal Edilmiş
                                                </span>
                                            <?php else: ?>
                                                <button type="button" class="btn btn-sm btn-danger" 
                                                        onclick="showCancelModal('<?php echo $file['id']; ?>', 'additional', '<?php echo htmlspecialchars($file['original_name']); ?>')">
                                                    <i class="bi bi-trash3 me-1"></i>İptal Et
                                                </button>
                                            <?php endif; ?>
                                            
                                            <?php if ($file['related_file_type'] === 'upload'): ?>
                                                <a href="file-detail.php?id=<?php echo $file['related_file_id']; ?>" 
                                                   class="btn btn-sm btn-outline-primary">
                                                    <i class="bi bi-eye me-1"></i>Ana Dosya
                                                </a>
                                            <?php endif; ?>
                                        </div>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>

                <!-- Sayfalama -->
                <?php if ($totalPages > 1): ?>
                    <nav class="mt-4">
                        <ul class="pagination justify-content-center">
                            <li class="page-item <?php echo $page <= 1 ? 'disabled' : ''; ?>">
                                <a class="page-link" href="?page=<?php echo max(1, $page-1); ?>&search=<?php echo urlencode($search); ?>&status=<?php echo urlencode($status); ?>&sender_type=<?php echo urlencode($sender_type); ?>&date_from=<?php echo urlencode($dateFrom); ?>&date_to=<?php echo urlencode($dateTo); ?>&per_page=<?php echo $per_page; ?>">Önceki</a>
                            </li>
                            
                            <?php for ($i = max(1, $page-2); $i <= min($totalPages, $page+2); $i++): ?>
                                <li class="page-item <?php echo $i == $page ? 'active' : ''; ?>">
                                    <a class="page-link" href="?page=<?php echo $i; ?>&search=<?php echo urlencode($search); ?>&status=<?php echo urlencode($status); ?>&sender_type=<?php echo urlencode($sender_type); ?>&date_from=<?php echo urlencode($dateFrom); ?>&date_to=<?php echo urlencode($dateTo); ?>&per_page=<?php echo $per_page; ?>"><?php echo $i; ?></a>
                                </li>
                            <?php endfor; ?>
                            
                            <li class="page-item <?php echo $page >= $totalPages ? 'disabled' : ''; ?>">
                                <a class="page-link" href="?page=<?php echo min($totalPages, $page+1); ?>&search=<?php echo urlencode($search); ?>&status=<?php echo urlencode($status); ?>&sender_type=<?php echo urlencode($sender_type); ?>&date_from=<?php echo urlencode($dateFrom); ?>&date_to=<?php echo urlencode($dateTo); ?>&per_page=<?php echo $per_page; ?>">Sonraki</a>
                            </li>
                        </ul>
                    </nav>
                <?php endif; ?>

            <?php else: ?>
                <div class="text-center py-5">
                    <i class="bi bi-paperclip fa-4x text-muted mb-3"></i>
                    <h5 class="text-muted">Ek dosya bulunamadı</h5>
                    <p class="text-muted">Arama kriterlerinizi değiştirerek tekrar deneyin.</p>
                </div>
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- Admin İptal Modal -->
<div class="modal fade" id="adminCancelModal" tabindex="-1" aria-labelledby="adminCancelModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content border-0 shadow-lg">
            <div class="modal-header bg-gradient-danger text-white border-0">
                <h5 class="modal-title d-flex align-items-center" id="adminCancelModalLabel">
                    <i class="bi bi-exclamation-triangle me-2"></i>
                    Ek Dosya İptal Onayı
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
                        <h6 class="mb-2 text-dark text-center">Bu ek dosyayı iptal etmek istediğinizden emin misiniz?</h6>
                        <p class="text-muted mb-3 text-center">
                            <strong>Dosya:</strong> <span id="cancelFileName"></span>
                        </p>
                        <div class="alert alert-warning d-flex align-items-center mb-3">
                            <i class="bi bi-info-circle me-2"></i>
                            <small>Bu işlem dosyayı gizleyecek ve varsa ücret iadesi yapacaktır.</small>
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
                        <i class="bi bi-trash3 me-1"></i>İptal
                    </button>
                    <button type="submit" class="btn btn-danger px-4">
                        <i class="bi bi-check me-1"></i>Evet, İptal Et
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<style>
.bg-gradient-danger {
    background: linear-gradient(135deg, #dc3545 0%, #c82333 100%) !important;
}
</style>

<script>
function showCancelModal(fileId, fileType, fileName) {
    document.getElementById('cancelFileId').value = fileId;
    document.getElementById('cancelFileType').value = fileType;
    document.getElementById('cancelFileName').textContent = fileName;
    document.getElementById('adminNotes').value = '';
    
    var modal = new bootstrap.Modal(document.getElementById('adminCancelModal'));
    modal.show();
}

// Türkçe karakter desteği için arama formu düzenleme
document.addEventListener('DOMContentLoaded', function() {
    var searchForm = document.querySelector('form[method="GET"]');
    var searchInput = document.querySelector('input[name="search"]');
    
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
                
                // Diğer form alanlarını da ekle
                var formData = new FormData(searchForm);
                for (var pair of formData.entries()) {
                    if (pair[0] !== 'search') {
                        params.set(pair[0], pair[1]);
                    }
                }
                
                // Sayfayı yeni URL ile yeniden yönlendir
                window.location.href = window.location.pathname + '?' + params.toString();
            }
        });
    }
});
</script>

<?php include '../includes/admin_footer.php'; ?>
