<?php
/**
 * Mr ECU - File Manager Class (GUID System) - CLEAN VERSION
 * GUID tabanlı dosya yönetimi sınıfı - Duplicate metodlar temizlendi
 */

// UUID oluşturma fonksiyonu
if (!function_exists('generateUUID')) {
    function generateUUID() {
        return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand(0, 0xffff), mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0x0fff) | 0x4000,
            mt_rand(0, 0x3fff) | 0x8000,
            mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
        );
    }
}

class FileManager {
    private $pdo;
    private $emailManager;
    
    public function __construct($database) {
        $this->pdo = $database;
        
        // EmailManager'ı include et ve oluştur
        if (file_exists(__DIR__ . '/EmailManager.php')) {
            require_once __DIR__ . '/EmailManager.php';
            $this->emailManager = new EmailManager($database);
        }
        
        // NotificationManager'ı include et (Bildirim entegrasyonu için)
        if (file_exists(__DIR__ . '/NotificationManager.php')) {
            require_once __DIR__ . '/NotificationManager.php';
        }
        
        // Notification integration fonksiyonlarını include et
        if (file_exists(__DIR__ . '/notification-integration.php')) {
            require_once __DIR__ . '/notification-integration.php';
        }
    }
    
    public function getCurrentDateTime() {
        return date('Y-m-d H:i:s');
    }
    
    // Araç markalarını getir
    public function getBrands() {
        try {
            $stmt = $this->pdo->query("SELECT * FROM brands ORDER BY name ASC");
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log('getBrands error: ' . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Markaya göre modelleri getir
     */
    public function getModelsByBrand($brandId) {
        try {
            if (!isValidUUID($brandId)) {
                error_log("Geçersiz brand_id: " . $brandId);
                return [];
            }
            $stmt = $this->pdo->prepare("SELECT * FROM models WHERE brand_id = ? ORDER BY name ASC");
            $stmt->execute([$brandId]);
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (Exception $e) {
            error_log("Modeller alınamadı (brand_id: $brandId): " . $e->getMessage());
            return [];
        }
    }

    /**
     * Modele göre serileri getir
     */
    public function getSeriesByModel($modelId) {
        try {
            if (!isValidUUID($modelId)) {
                error_log("Geçersiz model_id: " . $modelId);
                return [];
            }
            $stmt = $this->pdo->prepare("SELECT * FROM series WHERE model_id = ? ORDER BY name ASC");
            $stmt->execute([$modelId]);
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (Exception $e) {
            error_log("Seriler alınamadı (model_id: $modelId): " . $e->getMessage());
            return [];
        }
    }

    /**
     * Serie göre motorları getir
     */
    public function getEnginesBySeries($seriesId) {
        try {
            if (!isValidUUID($seriesId)) {
                error_log("Geçersiz series_id: " . $seriesId);
                return [];
            }
            $stmt = $this->pdo->prepare("SELECT * FROM engines WHERE series_id = ? ORDER BY name ASC");
            $stmt->execute([$seriesId]);
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (Exception $e) {
            error_log("Motorlar alınamadı (series_id: $seriesId): " . $e->getMessage());
            return [];
        }
    }
    
    // Dosya istatistiklerini getir (Admin Dashboard için)
    public function getFileStats() {
        try {
            $stmt = $this->pdo->query("
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN is_cancelled = 1 THEN 1 ELSE 0 END) as cancelled,
                    SUM(CASE WHEN status = 'pending' AND (is_cancelled IS NULL OR is_cancelled = 0) THEN 1 ELSE 0 END) as pending,
                    SUM(CASE WHEN status = 'processing' AND (is_cancelled IS NULL OR is_cancelled = 0) THEN 1 ELSE 0 END) as processing,
                    SUM(CASE WHEN status = 'completed' AND (is_cancelled IS NULL OR is_cancelled = 0) THEN 1 ELSE 0 END) as completed,
                    SUM(CASE WHEN status = 'rejected' AND (is_cancelled IS NULL OR is_cancelled = 0) THEN 1 ELSE 0 END) as rejected
                FROM file_uploads
            ");
            
            return $stmt->fetch(PDO::FETCH_ASSOC);
        } catch(PDOException $e) {
            error_log('getFileStats error: ' . $e->getMessage());
            return [
                'total' => 0,
                'cancelled' => 0,
                'pending' => 0,
                'processing' => 0,
                'completed' => 0,
                'rejected' => 0
            ];
        }
    }
    
    // Kullanıcının sadece ana dosyalarını getir (yanıt dosyaları hariç)
    public function getUserUploads($userId, $page = 1, $limit = 15, $status = '', $search = '', $filterId = '') {
        try {
            if (!isValidUUID($userId)) {
                return [];
            }
            
            $offset = ($page - 1) * $limit;
            $whereClause = "WHERE fu.user_id = ? AND (fu.is_cancelled IS NULL OR fu.is_cancelled = 0)";
            $params = [$userId];
            
            // ID ile filtreleme (bildirimden gelen dosya için)
            if ($filterId && isValidUUID($filterId)) {
                $whereClause .= " AND fu.id = ?";
                $params[] = $filterId;
            }
            
            if ($status) {
                $whereClause .= " AND fu.status = ?";
                $params[] = $status;
            }
            
            if ($search) {
                $whereClause .= " AND (fu.original_name LIKE ? OR b.name LIKE ? OR m.name LIKE ? OR fu.plate LIKE ?)";
                $searchTerm = "%$search%";
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
            }
            
            // LIMIT ve OFFSET'i güvenli şekilde string olarak ekle
            $sql = "
                SELECT fu.*, 
                       b.name as brand_name, m.name as model_name,
                       s.name as series_name, e.name as engine_name,
                       d.name as device_name, ecu.name as ecu_name
                FROM file_uploads fu
                LEFT JOIN brands b ON fu.brand_id = b.id
                LEFT JOIN models m ON fu.model_id = m.id
                LEFT JOIN series s ON fu.series_id = s.id
                LEFT JOIN engines e ON fu.engine_id = e.id
                LEFT JOIN devices d ON fu.device_id = d.id
                LEFT JOIN ecus ecu ON fu.ecu_id = ecu.id
                {$whereClause}
                ORDER BY fu.upload_date DESC
                LIMIT " . intval($limit) . " OFFSET " . intval($offset);
            
            $stmt = $this->pdo->prepare($sql);
            
            $stmt->execute($params);
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
            
        } catch(PDOException $e) {
            error_log('getUserUploads error: ' . $e->getMessage());
            return [];
        }
    }
    
    // Kullanıcının dosya sayısını getir
    public function getUserUploadCount($userId, $status = '', $search = '', $filterId = '') {
        try {
            if (!isValidUUID($userId)) {
                return 0;
            }
            
            $whereClause = "WHERE fu.user_id = ? AND (fu.is_cancelled IS NULL OR fu.is_cancelled = 0)";
            $params = [$userId];
            
            // ID ile filtreleme (bildirimden gelen dosya için)
            if ($filterId && isValidUUID($filterId)) {
                $whereClause .= " AND fu.id = ?";
                $params[] = $filterId;
            }
            
            if ($status) {
                $whereClause .= " AND fu.status = ?";
                $params[] = $status;
            }
            
            if ($search) {
                $whereClause .= " AND (fu.original_name LIKE ? OR b.name LIKE ? OR m.name LIKE ? OR fu.plate LIKE ?)";
                $searchTerm = "%$search%";
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
            }
            
            $stmt = $this->pdo->prepare("
                SELECT COUNT(*) as count
                FROM file_uploads fu
                LEFT JOIN brands b ON fu.brand_id = b.id
                LEFT JOIN models m ON fu.model_id = m.id
                LEFT JOIN series s ON fu.series_id = s.id
                LEFT JOIN engines e ON fu.engine_id = e.id
                LEFT JOIN devices d ON fu.device_id = d.id
                LEFT JOIN ecus ecu ON fu.ecu_id = ecu.id
                {$whereClause}
            ");
            
            $stmt->execute($params);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            return $result['count'] ?? 0;
            
        } catch(PDOException $e) {
            error_log('getUserUploadCount error: ' . $e->getMessage());
            return 0;
        }
    }
    
    // Kullanıcının dosya istatistiklerini getir
    public function getUserFileStats($userId) {
        try {
            if (!isValidUUID($userId)) {
                return ['total' => 0, 'pending' => 0, 'processing' => 0, 'completed' => 0, 'rejected' => 0];
            }
            
            $stmt = $this->pdo->prepare("
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
                    SUM(CASE WHEN status = 'processing' THEN 1 ELSE 0 END) as processing,
                    SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
                    SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected
                FROM file_uploads
                WHERE user_id = ? AND (is_cancelled IS NULL OR is_cancelled = 0)
            ");
            
            $stmt->execute([$userId]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            
            return $result ?: ['total' => 0, 'pending' => 0, 'processing' => 0, 'completed' => 0, 'rejected' => 0];
            
        } catch(PDOException $e) {
            error_log('getUserFileStats error: ' . $e->getMessage());
            return ['total' => 0, 'pending' => 0, 'processing' => 0, 'completed' => 0, 'rejected' => 0];
        }
    }

    public function getUserAllFiles($userId, $page = 1, $limit = 15, $status = '', $search = '') {
        try {
            if (!isValidUUID($userId)) {
                return [];
            }
            
            $offset = ($page - 1) * $limit;
            $whereClause = "WHERE fu.user_id = ? AND (fu.is_cancelled IS NULL OR fu.is_cancelled = 0)";
            $params = [$userId];
            
            if ($status) {
                $whereClause .= " AND fu.status = ?";
                $params[] = $status;
            }
            
            if ($search) {
                $whereClause .= " AND (fu.original_name LIKE ? OR b.name LIKE ? OR m.name LIKE ? OR fu.plate LIKE ?)";
                $searchTerm = "%$search%";
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
            }
            
            // LIMIT ve OFFSET'i güvenli şekilde string olarak ekle
            $sql = "
                SELECT fu.*, b.name as brand_name, m.name as model_name,
                       s.name as series_name, e.name as engine_name,
                       d.name as device_name, ecu.name as ecu_name
                FROM file_uploads fu
                LEFT JOIN brands b ON fu.brand_id = b.id
                LEFT JOIN models m ON fu.model_id = m.id
                LEFT JOIN series s ON fu.series_id = s.id
                LEFT JOIN engines e ON fu.engine_id = e.id
                LEFT JOIN devices d ON fu.device_id = d.id
                LEFT JOIN ecus ecu ON fu.ecu_id = ecu.id
                $whereClause
                ORDER BY fu.upload_date DESC
                LIMIT " . intval($limit) . " OFFSET " . intval($offset);
            
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute($params);
            
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
            
        } catch(PDOException $e) {
            error_log('getUserAllFiles error: ' . $e->getMessage());
            return [];
        }
    }
    
    // Dosya ID'sine göre upload kaydını getir
    public function getUploadById($uploadId) {
        try {
            if (!isValidUUID($uploadId)) {
                return null;
            }
            
            $stmt = $this->pdo->prepare("
                SELECT fu.*, 
                       b.name as brand_name, m.name as model_name,
                       s.name as series_name, e.name as engine_name,
                       d.name as device_name, ecu.name as ecu_name
                FROM file_uploads fu
                LEFT JOIN brands b ON fu.brand_id = b.id
                LEFT JOIN models m ON fu.model_id = m.id
                LEFT JOIN series s ON fu.series_id = s.id
                LEFT JOIN engines e ON fu.engine_id = e.id
                LEFT JOIN devices d ON fu.device_id = d.id
                LEFT JOIN ecus ecu ON fu.ecu_id = ecu.id
                WHERE fu.id = ?
            ");
            
            $stmt->execute([$uploadId]);
            return $stmt->fetch(PDO::FETCH_ASSOC);
            
        } catch(PDOException $e) {
            error_log('getUploadById error: ' . $e->getMessage());
            return null;
        }
    }
    
    // Ana dosyaya ait yanıt dosyalarını getir
    public function getFileResponses($uploadId, $userId) {
        try {
            if (!isValidUUID($uploadId) || !isValidUUID($userId)) {
                return [];
            }
            
            // Önce dosyanın kullanıcıya ait olup olmadığını kontrol et
            $stmt = $this->pdo->prepare("SELECT id FROM file_uploads WHERE id = ? AND user_id = ?");
            $stmt->execute([$uploadId, $userId]);
            if (!$stmt->fetch()) {
                return [];
            }
            
            // Yanıt dosyalarını getir (İptal edilmiş dosyaları hariç tut)
            $stmt = $this->pdo->prepare("
                SELECT fr.*, 
                       a.username as admin_username, a.first_name as admin_first_name, a.last_name as admin_last_name,
                       'response' as file_type
                FROM file_responses fr
                LEFT JOIN users a ON fr.admin_id = a.id
                WHERE fr.upload_id = ? AND (fr.is_cancelled IS NULL OR fr.is_cancelled = 0)
                ORDER BY fr.upload_date DESC
            ");
            
            $stmt->execute([$uploadId]);
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
            
        } catch(PDOException $e) {
            error_log('getFileResponses error: ' . $e->getMessage());
            return [];
        }
    }
    
    // Ana dosyaya ait revize taleplerini getir
    public function getFileRevisions($uploadId, $userId) {
        try {
            if (!isValidUUID($uploadId) || !isValidUUID($userId)) {
                return [];
            }
            
            // Önce dosyanın kullanıcıya ait olup olmadığını kontrol et
            $stmt = $this->pdo->prepare("SELECT id FROM file_uploads WHERE id = ? AND user_id = ?");
            $stmt->execute([$uploadId, $userId]);
            if (!$stmt->fetch()) {
                return [];
            }
            
            // Revize taleplerini getir
            $stmt = $this->pdo->prepare("
                SELECT r.*, 
                       a.username as admin_username, a.first_name as admin_first_name, a.last_name as admin_last_name
                FROM revisions r
                LEFT JOIN users a ON r.admin_id = a.id
                WHERE r.upload_id = ?
                ORDER BY r.requested_at DESC
            ");
            
            $stmt->execute([$uploadId]);
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
            
        } catch(PDOException $e) {
            error_log('getFileRevisions error: ' . $e->getMessage());
            return [];
        }
    }
    
    // Dosya yükle (GUID ID ile) - EKSIK METOD EKLENDİ
    public function uploadFile($userId, $fileData, $vehicleData, $notes = '') {
        try {
            // GUID format kontrolü
            if (!isValidUUID($userId)) {
                return ['success' => false, 'message' => 'Geçersiz kullanıcı ID formatı.'];
            }
            
            if (!isValidUUID($vehicleData['brand_id'])) {
                return ['success' => false, 'message' => 'Geçersiz marka ID formatı.'];
            }
            
            if (!isValidUUID($vehicleData['model_id'])) {
                return ['success' => false, 'message' => 'Geçersiz model ID formatı.'];
            }
            
            // Dosya kontrolü
            if (!isset($fileData['tmp_name']) || !is_uploaded_file($fileData['tmp_name'])) {
                return ['success' => false, 'message' => 'Dosya yükleme hatası.'];
            }
            
            if ($fileData['error'] !== UPLOAD_ERR_OK) {
                return ['success' => false, 'message' => 'Dosya yükleme hatası: ' . $fileData['error']];
            }
            
            // Dosya boyut kontrolü
            if ($fileData['size'] > MAX_FILE_SIZE) {
                return ['success' => false, 'message' => 'Dosya boyutu çok büyük. Maksimum ' . formatFileSize(MAX_FILE_SIZE) . ' olabilir.'];
            }
            
            // Dosya uzantı kontrolü kaldırıldı - Tüm dosya türlerine izin verildi
            $fileExtension = strtolower(pathinfo($fileData['name'], PATHINFO_EXTENSION));
            // Artık tüm dosya formatlarına izin veriliyor
            
            // Benzersiz dosya adı oluştur
            $fileName = $this->generateUniqueFileName($fileExtension);
            $uploadPath = UPLOAD_PATH . 'user_files/' . $fileName;
            
            // Upload dizinini oluştur
            $uploadDir = dirname($uploadPath);
            if (!is_dir($uploadDir)) {
                if (!mkdir($uploadDir, 0755, true)) {
                    return ['success' => false, 'message' => 'Upload dizini oluşturulamadı.'];
                }
            }
            
            // Dosyayı taşı
            if (!move_uploaded_file($fileData['tmp_name'], $uploadPath)) {
                return ['success' => false, 'message' => 'Dosya yükleme sırasında hata oluştu.'];
            }
            
            // UUID oluştur
            $uploadId = generateUUID();
            
            // Veritabanına kaydet - YENİ GUID ALANLARI İLE
            $stmt = $this->pdo->prepare("
                INSERT INTO file_uploads (
                    id, user_id, brand_id, model_id, series_id, engine_id, device_id, ecu_id,
                    year, plate, kilometer, gearbox_type, fuel_type, 
                    hp_power, nm_torque, original_name, filename, 
                    file_size, status, upload_notes, upload_date, file_path,
                    credits_charged, revision_count, notified
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, NOW(), ?, 0, 0, 0)
            ");
            
            $result = $stmt->execute([
                $uploadId,
                $userId,
                $vehicleData['brand_id'],
                $vehicleData['model_id'],
                $vehicleData['series_id'],
                $vehicleData['engine_id'],
                $vehicleData['device_id'],
                $vehicleData['ecu_id'],
                $vehicleData['year'],
                $vehicleData['plate'],
                $vehicleData['kilometer'],
                $vehicleData['gearbox_type'],
                $vehicleData['fuel_type'],
                $vehicleData['hp_power'],
                $vehicleData['nm_torque'],
                $fileData['name'],
                $fileName,
                $fileData['size'],
                $notes,
                $uploadPath
            ]);
            
            if ($result) {
                // Email bildirimi gönder - Admin'e dosya yükleme bildirimi
                try {
                    $uploadData = [
                        'user_id' => $userId,
                        'original_name' => $fileData['name'],
                        'brand_id' => $vehicleData['brand_id'],
                        'model_id' => $vehicleData['model_id'],
                        'series_id' => $vehicleData['series_id'],
                        'engine_id' => $vehicleData['engine_id'],
                        'year' => $vehicleData['year'],
                        'plate' => $vehicleData['plate'],
                        'fuel_type' => $vehicleData['fuel_type'],
                        'gearbox_type' => $vehicleData['gearbox_type'],
                        'upload_notes' => $notes
                    ];
                    
                    $emailResult = $this->sendFileUploadNotificationToAdmin($uploadData);
                    if ($emailResult) {
                        error_log('Upload notification email sent successfully for upload: ' . $uploadId);
                    } else {
                        error_log('Failed to send upload notification email for upload: ' . $uploadId);
                    }
                } catch (Exception $e) {
                    error_log('Email notification error after file upload: ' . $e->getMessage());
                }
                
                // Bildirim sistemi entegrasyonu
                try {
                    if (!class_exists('NotificationManager')) {
                        require_once __DIR__ . '/NotificationManager.php';
                    }
                    
                    $notificationManager = new NotificationManager($this->pdo);
                    $notificationManager->notifyFileUpload($uploadId, $userId, $fileData['name'], $vehicleData);
                } catch(Exception $e) {
                    error_log('Notification send error after file upload: ' . $e->getMessage());
                    // Bildirim hatası dosya yükleme işlemini etkilemesin
                }
                
                return [
                    'success' => true, 
                    'message' => 'Dosya başarıyla yüklendi! Admin ekibimiz en kısa sürede inceleyecektir.',
                    'upload_id' => $uploadId
                ];
            } else {
                // Dosyayı sil
                if (file_exists($uploadPath)) {
                    unlink($uploadPath);
                }
                return ['success' => false, 'message' => 'Veritabanı kaydı oluşturulamadı.'];
            }
            
        } catch (Exception $e) {
            error_log('uploadFile error: ' . $e->getMessage());
            // Dosyayı sil (eğer oluşturulduysa)
            if (isset($uploadPath) && file_exists($uploadPath)) {
                unlink($uploadPath);
            }
            return ['success' => false, 'message' => 'Dosya yükleme hatası: ' . $e->getMessage()];
        }
    }
    
    // Benzersiz dosya adı oluştur
    private function generateUniqueFileName($extension) {
        return generateUUID() . '.' . $extension;
    }
    
    
    /**
     * Yanıt dosyası için revizyon talebi oluştur
     * @param string $responseId - Yanıt dosyası ID
     * @param string $userId - Kullanıcı ID
     * @param string $requestNotes - Talep notları
     * @return array - Başarı durumu ve mesaj
     */
    public function requestResponseRevision($responseId, $userId, $requestNotes) {
        try {
            if (!isValidUUID($responseId) || !isValidUUID($userId)) {
                return ['success' => false, 'message' => 'Geçersiz ID formatı.'];
            }
            
            // Response dosyasının kullanıcıya ait olup olmadığını kontrol et
            $stmt = $this->pdo->prepare("
                SELECT fr.*, fu.id as upload_id, fu.original_name 
                FROM file_responses fr 
                LEFT JOIN file_uploads fu ON fr.upload_id = fu.id 
                WHERE fr.id = ? AND fu.user_id = ?
            ");
            $stmt->execute([$responseId, $userId]);
            $response = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$response) {
                return ['success' => false, 'message' => 'Yanıt dosyası bulunamadı veya yetkiniz yok.'];
            }
            
            // Ana upload için revizyon talebi oluştur ve response_id'yi belirt
            return $this->requestRevision($response['upload_id'], $userId, $requestNotes, $responseId);
            
        } catch(PDOException $e) {
            error_log('requestResponseRevision error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Veritabanı hatası oluştu.'];
        }
    }
    
    /**
     * Revizyon dosyası için revizyon talebi oluştur
     * @param string $revisionFileId - Revizyon dosyası ID
     * @param string $userId - Kullanıcı ID
     * @param string $requestNotes - Talep notları
     * @return array - Başarı durumu ve mesaj
     */
    public function requestRevisionFileRevision($revisionFileId, $userId, $requestNotes) {
        try {
            if (!isValidUUID($revisionFileId) || !isValidUUID($userId)) {
                return ['success' => false, 'message' => 'Geçersiz ID formatı.'];
            }
            
            // Revizyon dosyasının kullanıcıya ait olup olmadığını kontrol et
            $stmt = $this->pdo->prepare("
                SELECT rf.*, r.user_id, r.upload_id, fu.original_name 
                FROM revision_files rf 
                LEFT JOIN revisions r ON rf.revision_id = r.id 
                LEFT JOIN file_uploads fu ON r.upload_id = fu.id 
                WHERE rf.id = ? AND r.user_id = ?
            ");
            $stmt->execute([$revisionFileId, $userId]);
            $revisionFile = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$revisionFile) {
                return ['success' => false, 'message' => 'Revizyon dosyası bulunamadı veya yetkiniz yok.'];
            }
            
            // Ana upload için revizyon talebi oluştur
            return $this->requestRevision($revisionFile['upload_id'], $userId, $requestNotes);
            
        } catch(PDOException $e) {
            error_log('requestRevisionFileRevision error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Veritabanı hatası oluştu.'];
        }
    }

    public function downloadFile($fileId, $userId, $type = 'upload') {
        try {
            if (!isValidUUID($fileId) || !isValidUUID($userId)) {
                return ['success' => false, 'message' => 'Geçersiz ID formatı.'];
            }
            
            if ($type === 'response') {
                // Yanıt dosyası indirme
                $stmt = $this->pdo->prepare("
                    SELECT fr.*, fu.user_id
                    FROM file_responses fr
                    LEFT JOIN file_uploads fu ON fr.upload_id = fu.id
                    WHERE fr.id = ? AND fu.user_id = ?
                ");
                $stmt->execute([$fileId, $userId]);
                $file = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if (!$file) {
                    return ['success' => false, 'message' => 'Dosya bulunamadı veya yetkiniz yok.'];
                }
                
                $filePath = UPLOAD_PATH . 'response_files/' . $file['filename'];
                $originalName = $file['original_name'];
                
            } else {
                // Normal dosya indirme
                $stmt = $this->pdo->prepare("
                    SELECT * FROM file_uploads 
                    WHERE id = ? AND user_id = ? AND status = 'completed'
                ");
                $stmt->execute([$fileId, $userId]);
                $file = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if (!$file) {
                    return ['success' => false, 'message' => 'Dosya bulunamadı veya henüz tamamlanmamış.'];
                }
                
                // Dosya yolunu düzelt - user_files klasörü ekle
                $filePath = UPLOAD_PATH . 'user_files/' . $file['filename'];
                $originalName = $file['original_name'];
            }
            
            if (!file_exists($filePath)) {
                return ['success' => false, 'message' => 'Fiziksel dosya bulunamadı.'];
            }
            
            return [
                'success' => true,
                'file_path' => $filePath,
                'original_name' => $originalName,
                'file_size' => filesize($filePath)
            ];
            
        } catch(PDOException $e) {
            error_log('downloadFile error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Veritabanı hatası oluştu.'];
        }
    }
    
    // Admin için tüm yüklemeleri getir
    public function getAllUploads($page = 1, $limit = 20, $status = '', $search = '') {
        try {
            $offset = ($page - 1) * $limit;
            $whereClause = "WHERE 1=1";
            $params = [];
            
            if ($status) {
                $whereClause .= " AND fu.status = ?";
                $params[] = $status;
            }
            
            if ($search) {
                $whereClause .= " AND (fu.original_name LIKE ? OR u.username LIKE ? OR u.email LIKE ? OR b.name LIKE ? OR m.name LIKE ?)";
                $searchTerm = "%$search%";
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
            }
            
            // LIMIT ve OFFSET'i güvenli şekilde string olarak ekle
            $sql = "
                SELECT fu.*, u.username, u.email, u.first_name, u.last_name,
                       b.name as brand_name, m.name as model_name,
                       s.name as series_name, e.name as engine_name,
                       d.name as device_name, ecu.name as ecu_name,
                       fu.is_cancelled
                FROM file_uploads fu
                LEFT JOIN users u ON fu.user_id = u.id
                LEFT JOIN brands b ON fu.brand_id = b.id
                LEFT JOIN models m ON fu.model_id = m.id
                LEFT JOIN series s ON fu.series_id = s.id
                LEFT JOIN engines e ON fu.engine_id = e.id
                LEFT JOIN devices d ON fu.device_id = d.id
                LEFT JOIN ecus ecu ON fu.ecu_id = ecu.id
                $whereClause
                ORDER BY fu.upload_date DESC
                LIMIT " . intval($limit) . " OFFSET " . intval($offset);
            
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute($params);
            
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
            
        } catch(PDOException $e) {
            error_log('getAllUploads error: ' . $e->getMessage());
            return [];
        }
    }
    
    // Admin için tüm revize taleplerini getir
    public function getAllRevisions($page = 1, $limit = 20, $status = '', $dateFrom = '', $dateTo = '', $search = '') {
        try {
            $offset = ($page - 1) * $limit;
            $whereClause = "WHERE 1=1";
            $params = [];
            
            if ($status) {
                $whereClause .= " AND r.status = ?";
                $params[] = $status;
            }
            
            if ($dateFrom) {
                $whereClause .= " AND DATE(r.requested_at) >= ?";
                $params[] = $dateFrom;
            }
            
            if ($dateTo) {
                $whereClause .= " AND DATE(r.requested_at) <= ?";
                $params[] = $dateTo;
            }
            
            if ($search) {
                $whereClause .= " AND (r.request_notes LIKE ? OR fu.original_name LIKE ? OR u.username LIKE ? OR u.email LIKE ? OR u.first_name LIKE ? OR u.last_name LIKE ? OR b.name LIKE ? OR m.name LIKE ? OR fu.plate LIKE ?)";
                $searchTerm = "%$search%";
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
            }
            
            // LIMIT ve OFFSET'i güvenli şekilde string olarak ekle
            $sql = "
                SELECT r.*, fu.original_name, fu.filename, fu.file_size, fu.plate, fu.year,
                       u.username, u.email, u.first_name, u.last_name,
                       b.name as brand_name, m.name as model_name,
                       s.name as series_name, e.name as engine_name,
                       fr.original_name as response_original_name
                FROM revisions r
                LEFT JOIN file_uploads fu ON r.upload_id = fu.id
                LEFT JOIN users u ON r.user_id = u.id
                LEFT JOIN brands b ON fu.brand_id = b.id
                LEFT JOIN models m ON fu.model_id = m.id
                LEFT JOIN series s ON fu.series_id = s.id
                LEFT JOIN engines e ON fu.engine_id = e.id
                LEFT JOIN file_responses fr ON r.response_id = fr.id
                $whereClause
                ORDER BY r.requested_at DESC
                LIMIT " . intval($limit) . " OFFSET " . intval($offset);
            
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute($params);
            
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
            
        } catch(PDOException $e) {
            error_log('getAllRevisions error: ' . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Admin tarafından yanıt dosyası yükle (Gelişmiş Bildirim Sistemi ile)
     * @param string $uploadId - Ana dosya ID'si
     * @param array $fileData - $_FILES['response_file'] verisi
     * @param float $creditsCharged - Düşürülecek kredi miktarı
     * @param string $responseNotes - Admin yanıt notları
     * @return array - Başarı durumu ve mesaj
     */
    public function uploadResponseFile($uploadId, $fileData, $creditsCharged = 0, $responseNotes = '') {
        try {
            error_log('uploadResponseFile started - UploadId: ' . $uploadId . ', Credits: ' . $creditsCharged);
            
            if (!isValidUUID($uploadId)) {
                return ['success' => false, 'message' => 'Geçersiz dosya ID formatı.'];
            }
            
            // Ana dosya kontrolü
            $upload = $this->getUploadById($uploadId);
            if (!$upload) {
                return ['success' => false, 'message' => 'Ana dosya bulunamadı.'];
            }
            
            // Dosya yükleme kontrolü
            if (!isset($fileData['tmp_name']) || !is_uploaded_file($fileData['tmp_name'])) {
                return ['success' => false, 'message' => 'Yanıt dosyası yüklenmedi.'];
            }
            
            if ($fileData['error'] !== UPLOAD_ERR_OK) {
                return ['success' => false, 'message' => 'Dosya yükleme hatası: ' . $fileData['error']];
            }
            
            // Dosya boyutu kontrolü
            if ($fileData['size'] > MAX_FILE_SIZE) {
                return ['success' => false, 'message' => 'Dosya boyutu çok büyük. Maksimum ' . formatFileSize(MAX_FILE_SIZE) . ' olabilir.'];
            }
            
            // Benzersiz dosya adı oluştur
            $fileExtension = strtolower(pathinfo($fileData['name'], PATHINFO_EXTENSION));
            $fileName = generateUUID() . '_response.' . $fileExtension;
            $uploadDir = UPLOAD_PATH . 'response_files/';
            $uploadPath = $uploadDir . $fileName;
            
            // Upload dizinini oluştur
            if (!is_dir($uploadDir)) {
                if (!mkdir($uploadDir, 0755, true)) {
                    return ['success' => false, 'message' => 'Upload dizini oluşturulamadı.'];
                }
            }
            
            // Dosyayı taşı
            if (!move_uploaded_file($fileData['tmp_name'], $uploadPath)) {
                return ['success' => false, 'message' => 'Dosya upload edilemedi.'];
            }
            
            error_log('uploadResponseFile: File moved successfully to ' . $uploadPath);
            
            // Transaction başlat
            $this->pdo->beginTransaction();
            
            try {
                // file_responses tablosuna kaydet
                $responseId = generateUUID();
                $stmt = $this->pdo->prepare("
                    INSERT INTO file_responses (
                        id, upload_id, admin_id, filename, original_name, 
                        file_size, credits_charged, admin_notes, upload_date
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())
                ");
                
                $result = $stmt->execute([
                    $responseId,
                    $uploadId,
                    $_SESSION['user_id'] ?? null,
                    $fileName,
                    $fileData['name'],
                    $fileData['size'],
                    $creditsCharged,
                    $responseNotes
                ]);
                
                if (!$result) {
                    throw new Exception('Response dosyası kaydı oluşturulamadı.');
                }
                
                error_log('uploadResponseFile: Response record created with ID: ' . $responseId);
                
                // Ana dosya durumunu 'completed' olarak güncelle (BİLDİRİM GÖNDERMEDEn)
                // updateUploadStatus metodu kullan ama sendNotification = false
                $statusUpdateResult = $this->updateUploadStatus($uploadId, 'completed', $responseNotes, false);
                
                if (!$statusUpdateResult) {
                    throw new Exception('Ana dosya durumu güncellenemedi.');
                }
                
                error_log('uploadResponseFile: Main file status updated to completed');
                
                // Kredi düşürme işlemi (eğer belirtilmişse)
                if ($creditsCharged > 0) {
                    // User sınıfını dahil et
                    if (!class_exists('User')) {
                        require_once __DIR__ . '/User.php';
                    }
                    
                    $user = new User($this->pdo);
                    
                    // Ters kredi sistemi - kredi_used'ı artır (YENİ updateCredits metodu)
                    $creditResult = $user->updateCredits(
                        $upload['user_id'], 
                        $creditsCharged, 
                        'file_charge', 
                        [
                            'description' => 'Dosya işleme ücreti: ' . $upload['original_name'] . ' (Yanıt: ' . $fileData['name'] . ')',
                            'reference_id' => $uploadId,
                            'reference_type' => 'file_upload',
                            'admin_id' => $_SESSION['user_id'] ?? null
                        ]
                    );
                    
                    if (!$creditResult) {
                        throw new Exception('Kredi düşürme işlemi başarısız.');
                    }
                    
                    error_log('uploadResponseFile: Credits charged successfully: ' . $creditsCharged);
                }
                
                // Email bildirimi gönder - Kullanıcıya yanıt dosyası hazır bildirimi
                try {
                    $responseData = [
                        'upload_id' => $uploadId,
                        'original_name' => $fileData['name'],
                        'admin_notes' => $responseNotes,
                        'id' => $responseId
                    ];
                    
                    $emailResult = $this->sendFileResponseNotificationToUser($responseData);
                    if ($emailResult) {
                        error_log('Response notification email sent successfully for response: ' . $responseId);
                    } else {
                        error_log('Failed to send response notification email for response: ' . $responseId);
                    }
                } catch (Exception $e) {
                    error_log('Email notification error after response upload: ' . $e->getMessage());
                }
                
                // Bildirim sistemi entegrasyonu
                try {
                    if (!class_exists('NotificationManager')) {
                        require_once __DIR__ . '/NotificationManager.php';
                    }
                    
                    $notificationManager = new NotificationManager($this->pdo);
                    
                    // Yanıt dosyası yüklendiği için kullanıcıya bildirim gönder
                    $notificationTitle = "Dosya yanıtlandı";
                    $notificationMessage = $upload['original_name'] . " dosyanız için yanıt dosyası yüklendi: " . $fileData['name'];
                    
                    if ($responseNotes) {
                        $notificationMessage .= " Admin notu: " . $responseNotes;
                    }
                    
                    $actionUrl = "files.php?id=" . $uploadId;
                    
                    $notificationResult = $notificationManager->createNotification(
                        $upload['user_id'],
                        'file_response_uploaded',
                        $notificationTitle,
                        $notificationMessage,
                        $uploadId,
                        'file_upload',
                        $actionUrl
                    );
                    
                    if ($notificationResult) {
                        error_log('uploadResponseFile: Notification sent successfully to user: ' . $upload['user_id']);
                    } else {
                        error_log('uploadResponseFile: Notification failed to send to user: ' . $upload['user_id']);
                    }
                    
                } catch(Exception $e) {
                    error_log('uploadResponseFile: Notification send error: ' . $e->getMessage());
                    // Bildirim hatası ana işlemi etkilemesin
                }
                
                // Transaction commit
                $this->pdo->commit();
                
                error_log('uploadResponseFile: Transaction committed successfully');
                
                return [
                    'success' => true, 
                    'message' => 'Yanıt dosyası başarıyla yüklendi ve kullanıcıya bildirim gönderildi.',
                    'response_id' => $responseId
                ];
                
            } catch(Exception $e) {
                // Transaction rollback
                $this->pdo->rollBack();
                
                // Yüklenen dosyayı sil
                if (file_exists($uploadPath)) {
                    unlink($uploadPath);
                }
                
                error_log('uploadResponseFile: Transaction rolled back: ' . $e->getMessage());
                return ['success' => false, 'message' => 'Yanıt dosyası yükleme hatası: ' . $e->getMessage()];
            }
            
        } catch(Exception $e) {
            error_log('uploadResponseFile general error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Sistem hatası: ' . $e->getMessage()];
        }
    }
    
    /**
     * Admin tarafından revizyon dosyası yükleme
     * @param string $revisionId - Revizyon talebi ID
     * @param array $file - Yüklenen dosya bilgileri
     * @param string $adminId - Admin kullanıcı ID
     * @param float $creditsCharged - Düşürülecek kredi miktarı
     * @param string $adminNotes - Admin notları
     * @return array - Başarı durumu ve mesaj
     */
    public function uploadRevisionFile($revisionId, $file, $adminId, $creditsCharged = 0, $adminNotes = '') {
        try {
            if (!isValidUUID($revisionId)) {
                return ['success' => false, 'message' => 'Geçersiz revizyon ID formatı.'];
            }
            
            // Revizyon talebini kontrol et
            $stmt = $this->pdo->prepare("SELECT * FROM revisions WHERE id = ?");
            $stmt->execute([$revisionId]);
            $revision = $stmt->fetch();
            
            if (!$revision) {
                return ['success' => false, 'message' => 'Revizyon talebi bulunamadı.'];
            }
            
            if ($revision['status'] !== 'in_progress') {
                return ['success' => false, 'message' => 'Sadece işlemdeki revizyon talepleri için dosya yüklenebilir.'];
            }
            
            // Dosya kontrolleri
            if (!isset($file['tmp_name']) || !is_uploaded_file($file['tmp_name'])) {
                return ['success' => false, 'message' => 'Geçersiz dosya yüklemesi.'];
            }
            
            if ($file['error'] !== UPLOAD_ERR_OK) {
                return ['success' => false, 'message' => 'Dosya yükleme hatası: ' . $file['error']];
            }
            
            if ($file['size'] > MAX_FILE_SIZE) {
                return ['success' => false, 'message' => 'Dosya boyutu çok büyük. Maksimum: ' . formatFileSize(MAX_FILE_SIZE)];
            }
            
            // Dosya uzantısı kontrolü kaldırıldı - Tüm dosya türlerine izin verildi
            $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
            // Artık tüm dosya formatlarına izin veriliyor
            
            // Revizyon dosyaları dizinini kontrol et
            $uploadDir = UPLOAD_PATH . 'revision_files/';
            if (!is_dir($uploadDir)) {
                if (!mkdir($uploadDir, 0755, true)) {
                    return ['success' => false, 'message' => 'Revizyon dosyaları dizini oluşturulamadı.'];
                }
            }
            
            // Benzersiz dosya adı oluştur
            $filename = generateUUID() . '.' . $extension;
            $filePath = $uploadDir . $filename;
            
            // Dosyayı taşı
            if (!move_uploaded_file($file['tmp_name'], $filePath)) {
                return ['success' => false, 'message' => 'Dosya taşınamadı.'];
            }
            
            // revision_files tablosuna kaydet
            $revisionFileId = generateUUID();
            $stmt = $this->pdo->prepare("
                INSERT INTO revision_files (
                    id, revision_id, upload_id, admin_id, original_name, filename, 
                    file_size, file_type, admin_notes, upload_date
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
            ");
            
            $result = $stmt->execute([
                $revisionFileId,
                $revisionId,
                $revision['upload_id'],
                $adminId,
                $file['name'],
                $filename,
                $file['size'],
                $extension,
                $adminNotes
            ]);
            
            if ($result) {
                // Kredi düşür (eğer belirtilmişse)
                if ($creditsCharged > 0) {
                    $userClass = new User($this->pdo);
                    $creditResult = $userClass->deductCredits($revision['user_id'], $creditsCharged, "Revizyon dosyası için kredi düşüldü: " . $revisionId);
                    
                    if (!$creditResult['success']) {
                        // Kredi düşürülemezse dosyayı ve kayda sil
                        unlink($filePath);
                        $this->pdo->prepare("DELETE FROM revision_files WHERE id = ?")->execute([$revisionFileId]);
                        return ['success' => false, 'message' => 'Kredi düşürülemedi: ' . $creditResult['message']];
                    }
                }
                
                // Revizyon durumunu 'completed' yap
                $updateResult = $this->updateRevisionStatus(
                    $revisionId, 
                    $adminId, 
                    'completed', 
                    'Revizyon dosyası yüklendi: ' . $adminNotes,
                    $creditsCharged
                );
                
                if ($updateResult['success']) {
                    return [
                        'success' => true, 
                        'message' => 'Revizyon dosyası başarıyla yüklendi ve revizyon talebi tamamlandı.',
                        'revision_file_id' => $revisionFileId
                    ];
                } else {
                    // Dosyayı ve kaydı sil
                    unlink($filePath);
                    $this->pdo->prepare("DELETE FROM revision_files WHERE id = ?")->execute([$revisionFileId]);
                    return ['success' => false, 'message' => 'Revizyon durumu güncellenemedi: ' . $updateResult['message']];
                }
            } else {
                // Dosyayı sil
                unlink($filePath);
                return ['success' => false, 'message' => 'Veritabanı kaydı oluşturulamadı.'];
            }
            
        } catch (Exception $e) {
            error_log('uploadRevisionFile error: ' . $e->getMessage());
            // Dosyayı sil (eğer oluşturulduysa)
            if (isset($filePath) && file_exists($filePath)) {
                unlink($filePath);
            }
            return ['success' => false, 'message' => 'Revizyon dosyası yükleme hatası: ' . $e->getMessage()];
        }
    }
    
    /**
     * Revizyon talebine ait dosyaları getir
     * @param string $revisionId - Revizyon talebi ID
     * @param string $userId - Kullanıcı ID (yetki kontrolü için)
     * @return array - Revizyon dosyaları listesi
     */
    public function getRevisionFiles($revisionId, $userId = null) {
        try {
            if (!isValidUUID($revisionId)) {
                return [];
            }
            
            // Eğer userId verilmişse, revizyonun kullanıcıya ait olup olmadığını kontrol et
            if ($userId && !isValidUUID($userId)) {
                return [];
            }
            
            $whereClause = "WHERE rf.revision_id = ?";
            $params = [$revisionId];
            
            if ($userId) {
                $whereClause .= " AND r.user_id = ?";
                $params[] = $userId;
            }
            
            $stmt = $this->pdo->prepare("
            SELECT rf.*, 
            a.username as admin_username, a.first_name as admin_first_name, a.last_name as admin_last_name,
            r.status as revision_status, r.requested_at
            FROM revision_files rf
            LEFT JOIN revisions r ON rf.revision_id = r.id
            LEFT JOIN users a ON rf.admin_id = a.id
            $whereClause
            AND (rf.is_cancelled IS NULL OR rf.is_cancelled = 0)
                ORDER BY rf.upload_date DESC
        ");
            
            $stmt->execute($params);
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
            
        } catch(PDOException $e) {
            error_log('getRevisionFiles error: ' . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Upload ID'ye göre tüm revizyon dosyalarını getir
     * @param string $uploadId - Ana dosya ID
     * @param string $userId - Kullanıcı ID (yetki kontrolü için)
     * @return array - Revizyon dosyaları listesi
     */
    public function getUploadRevisionFiles($uploadId, $userId = null) {
        try {
            if (!isValidUUID($uploadId)) {
                return [];
            }
            
            // Eğer userId verilmişse, dosyanın kullanıcıya ait olup olmadığını kontrol et
            if ($userId && !isValidUUID($userId)) {
                return [];
            }
            
            $whereClause = "WHERE rf.upload_id = ?";
            $params = [$uploadId];
            
            if ($userId) {
                $whereClause .= " AND r.user_id = ?";
                $params[] = $userId;
            }
            
            $stmt = $this->pdo->prepare("
                SELECT rf.*, r.request_notes, r.status as revision_status, r.requested_at,
                       a.username as admin_username, a.first_name as admin_first_name, a.last_name as admin_last_name
                FROM revision_files rf
                LEFT JOIN revisions r ON rf.revision_id = r.id
                LEFT JOIN users a ON rf.admin_id = a.id
                $whereClause
                AND (rf.is_cancelled IS NULL OR rf.is_cancelled = 0)
                ORDER BY rf.upload_date DESC
            ");
            
            $stmt->execute($params);
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
            
        } catch(PDOException $e) {
            error_log('getUploadRevisionFiles error: ' . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Revizyon dosyası indirme kontrolü ve dosya bilgilerini getir
     * @param string $revisionFileId - Revizyon dosya ID
     * @param string $userId - Kullanıcı ID (yetki kontrolü için)
     * @return array - Dosya bilgileri veya hata
     */
    public function downloadRevisionFile($revisionFileId, $userId) {
        try {
            if (!isValidUUID($revisionFileId) || !isValidUUID($userId)) {
                return ['success' => false, 'message' => 'Geçersiz ID formatı.'];
            }
            
            // Revizyon dosyasını ve yetki kontrolünü yap (iptal edilmemiş dosyalar)
            $stmt = $this->pdo->prepare("
                SELECT rf.*, r.user_id as revision_user_id, r.status as revision_status
                FROM revision_files rf
                LEFT JOIN revisions r ON rf.revision_id = r.id
                WHERE rf.id = ? AND r.user_id = ?
                AND (rf.is_cancelled IS NULL OR rf.is_cancelled = 0)
            ");
            $stmt->execute([$revisionFileId, $userId]);
            $revisionFile = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$revisionFile) {
                return ['success' => false, 'message' => 'Revizyon dosyası bulunamadı veya yetkiniz yok.'];
            }
            
            if ($revisionFile['revision_status'] !== 'completed') {
                return ['success' => false, 'message' => 'Sadece tamamlanan revizyon dosyaları indirilebilir.'];
            }
            
            // Fiziksel dosya kontrolü
            $filePath = UPLOAD_PATH . 'revision_files/' . $revisionFile['filename'];
            
            if (!file_exists($filePath)) {
                return ['success' => false, 'message' => 'Fiziksel dosya bulunamadı.'];
            }
            
            // İndirme kaydını güncelle
            $this->pdo->prepare("
                UPDATE revision_files 
                SET downloaded = TRUE, download_date = NOW() 
                WHERE id = ?
            ")->execute([$revisionFileId]);
            
            return [
                'success' => true,
                'file_path' => $filePath,
                'original_name' => $revisionFile['original_name'],
                'file_size' => $revisionFile['file_size'],
                'file_type' => $revisionFile['file_type']
            ];
            
        } catch(PDOException $e) {
            error_log('downloadRevisionFile error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Veritabanı hatası oluştu.'];
        }
    }
    
    /**
     * Revizyon ID'sine göre revizyon detaylarını getir
     * @param string $revisionId - Revizyon ID
     * @param string $userId - Kullanıcı ID (yetki kontrolü için)
     * @return array|null - Revizyon detayları
     */
    public function getRevisionDetail($revisionId, $userId = null) {
        try {
            if (!isValidUUID($revisionId)) {
                return null;
            }
            
            $whereClause = "WHERE r.id = ?";
            $params = [$revisionId];
            
            if ($userId && isValidUUID($userId)) {
                $whereClause .= " AND r.user_id = ?";
                $params[] = $userId;
            }
            
            $stmt = $this->pdo->prepare("
                SELECT r.*, fu.original_name, fu.filename, fu.file_size,
                       u.username, u.first_name, u.last_name, u.email,
                       a.username as admin_username, a.first_name as admin_first_name, a.last_name as admin_last_name,
                       b.name as brand_name, m.name as model_name,
                       fr.original_name as response_original_name, fr.filename as response_filename
                FROM revisions r
                LEFT JOIN file_uploads fu ON r.upload_id = fu.id
                LEFT JOIN users u ON r.user_id = u.id
                LEFT JOIN users a ON r.admin_id = a.id
                LEFT JOIN brands b ON fu.brand_id = b.id
                LEFT JOIN models m ON fu.model_id = m.id
                LEFT JOIN file_responses fr ON r.response_id = fr.id
                $whereClause
            ");
            
            $stmt->execute($params);
            return $stmt->fetch(PDO::FETCH_ASSOC);
            
        } catch(PDOException $e) {
            error_log('getRevisionDetail error: ' . $e->getMessage());
            return null;
        }
    }
    
    /**
     * Revizyon istatistiklerini getir (Admin Dashboard için)
     * @return array - Revizyon istatistikleri
     */
    public function getRevisionStats() {
        try {
            $stmt = $this->pdo->query("
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
                    SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END) as in_progress,
                    SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
                    SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected
                FROM revisions
            ");
            
            return $stmt->fetch(PDO::FETCH_ASSOC);
        } catch(PDOException $e) {
            error_log('getRevisionStats error: ' . $e->getMessage());
            return [
                'total' => 0,
                'pending' => 0,
                'in_progress' => 0,
                'completed' => 0,
                'rejected' => 0
            ];
        }
    }
    
    /**
     * Dosya upload durumunu güncelle (Bildirim Entegrasyonu ile)
     * @param string $uploadId - Upload ID
     * @param string $status - Yeni durum
     * @param string $adminNotes - Admin notları
     * @param bool $sendNotification - Bildirim gönderilsin mi?
     * @return bool - Başarı durumu
     */
    public function updateUploadStatus($uploadId, $status, $adminNotes = '', $sendNotification = true) {
        try {
            if (!isValidUUID($uploadId)) {
                error_log('updateUploadStatus: Geçersiz UUID - ' . $uploadId);
                return false;
            }
            
            // Önce dosyayı al
            $upload = $this->getUploadById($uploadId);
            if (!$upload) {
                error_log('updateUploadStatus: Dosya bulunamadı - ' . $uploadId);
                return false;
            }
            
            // Durumu güncelle
            $stmt = $this->pdo->prepare("
                UPDATE file_uploads 
                SET status = ?, admin_notes = ?
                WHERE id = ?
            ");
            
            $result = $stmt->execute([$status, $adminNotes, $uploadId]);
            
            if ($result) {
                // Email bildirimi gönder - Durum değişikliği için kullanıcıya
                if ($sendNotification) {
                    try {
                        // Sadece önemli durum değişikliklerinde email gönder
                        if (in_array($status, ['processing', 'completed', 'rejected'])) {
                            $statusMessages = [
                                'processing' => 'Dosyanız işleme alındı',
                                'completed' => 'Dosyanız tamamlandı',
                                'rejected' => 'Dosyanız reddedildi'
                            ];
                            
                            // Kullanıcı email bilgilerini al
                            $stmt = $this->pdo->prepare("
                                SELECT u.email, CONCAT(u.first_name, ' ', u.last_name) as full_name, f.plate
                                FROM users u
                                JOIN file_uploads f ON f.user_id = u.id
                                WHERE f.id = ?
                            ");
                            $stmt->execute([$uploadId]);
                            $user = $stmt->fetch(PDO::FETCH_ASSOC);
                            
                            if ($user && $this->emailManager) {
                                $emailData = [
                                    'user_name' => $user['full_name'],
                                    'user_email' => $user['email'],
                                    'file_name' => $upload['original_name'],
                                    'plate' => $user['plate'] ?? $upload['plate'] ?? '',
                                    'status' => $status,
                                    'status_message' => $statusMessages[$status],
                                    'admin_notes' => $adminNotes,
                                    'update_time' => date('d.m.Y H:i:s'),
                                    'user_dashboard_url' => (getenv('SITE_URL') ?: 'http://localhost') . '/user/files.php',
                                    'contact_url' => (getenv('SITE_URL') ?: 'http://localhost') . '/contact.php'
                                ];
                                
                                $emailResult = $this->sendFileStatusUpdateNotificationToUser($emailData);
                                if ($emailResult) {
                                    error_log('Status update email sent successfully for upload: ' . $uploadId);
                                } else {
                                    error_log('Failed to send status update email for upload: ' . $uploadId);
                                }
                            }
                        }
                    } catch (Exception $e) {
                        error_log('Email notification error after status update: ' . $e->getMessage());
                    }
                }
                
                // Sadece bildirim gönderilmesi isteniyorsa gönder
                if ($sendNotification) {
                    try {
                        if (!class_exists('NotificationManager')) {
                            require_once __DIR__ . '/NotificationManager.php';
                        }
                        
                        $notificationManager = new NotificationManager($this->pdo);
                        $notificationManager->notifyFileStatusUpdate($uploadId, $upload['user_id'], $upload['original_name'], $status, $adminNotes);
                    } catch(Exception $e) {
                        error_log('Notification send error after status update: ' . $e->getMessage());
                        // Bildirim hatası durum güncelleme işlemini etkilemesin
                    }
                }
                
                error_log('updateUploadStatus: Başarılı - ' . $uploadId . ' durumu ' . $status . ' olarak güncellendi');
                return true;
            } else {
                error_log('updateUploadStatus: Başarısız - ' . $uploadId . ' durum güncellenemedi');
                return false;
            }
            
        } catch(PDOException $e) {
            error_log('updateUploadStatus error: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Revizyon durumunu güncelle (Bildirim Entegrasyonu ile)
     * @param string $revisionId - Revizyon ID
     * @param string $adminId - Admin kullanıcı ID
     * @param string $status - Yeni durum
     * @param string $adminNotes - Admin notları
     * @param float $creditsCharged - Düşürülecek kredi miktarı
     * @return array - Başarı durumu ve mesaj
     */
    public function updateRevisionStatus($revisionId, $adminId, $status, $adminNotes = '', $creditsCharged = 0) {
        try {
            if (!isValidUUID($revisionId) || !isValidUUID($adminId)) {
                return ['success' => false, 'message' => 'Geçersiz ID formatı.'];
            }
            
            // Revize talebini getir
            $stmt = $this->pdo->prepare("SELECT * FROM revisions WHERE id = ?");
            $stmt->execute([$revisionId]);
            $revision = $stmt->fetch();
            
            if (!$revision) {
                return ['success' => false, 'message' => 'Revize talebi bulunamadı.'];
            }
            
            // Revize durumunu güncelle
            $updateFields = [];
            $updateParams = [];
            
            $updateFields[] = "status = ?";
            $updateParams[] = $status;
            
            $updateFields[] = "admin_id = ?";
            $updateParams[] = $adminId;
            
            if ($adminNotes) {
                $updateFields[] = "admin_notes = ?";
                $updateParams[] = $adminNotes;
            }
            
            if ($creditsCharged > 0) {
                $updateFields[] = "credits_charged = ?";
                $updateParams[] = $creditsCharged;
            }
            
            if ($status === 'completed') {
                $updateFields[] = "completed_at = NOW()";
            }
            
            // WHERE koşulu için revisionId'yi en sona ekle
            $updateParams[] = $revisionId;
            
            $updateQuery = "UPDATE revisions SET " . implode(", ", $updateFields) . " WHERE id = ?";
            
            $stmt = $this->pdo->prepare($updateQuery);
            $result = $stmt->execute($updateParams);
            
            if ($result) {
                // Eğer kredi düşürülecekse ve status in_progress ise krediyi düşür
                if ($creditsCharged > 0 && $status === 'in_progress') {
                    $userClass = new User($this->pdo);
                    $creditResult = $userClass->deductCredits($revision['user_id'], $creditsCharged, "Revize talebi için kredi düşüldü: " . $revisionId);
                    
                    if (!$creditResult['success']) {
                        // Kredi düşürülemezse revize durumunu geri al
                        $stmt = $this->pdo->prepare("UPDATE revisions SET status = 'pending', admin_id = NULL, admin_notes = NULL, credits_charged = 0 WHERE id = ?");
                        $stmt->execute([$revisionId]);
                        
                        return ['success' => false, 'message' => 'Kredi düşürülemedi: ' . $creditResult['message']];
                    }
                }
                
                // Bildirim sistemi entegrasyonu
                try {
                    if (!class_exists('NotificationManager')) {
                        require_once __DIR__ . '/NotificationManager.php';
                    }
                    
                    $notificationManager = new NotificationManager($this->pdo);
                    $notificationManager->notifyRevisionResponse($revisionId, $revision['user_id'], $revision['upload_id'], $status, $adminNotes);
                } catch(Exception $e) {
                    error_log('Notification send error after revision status update: ' . $e->getMessage());
                    // Bildirim hatası revizyon güncelleme işlemini etkilemesin
                }
                
                return ['success' => true, 'message' => 'Revize durumu başarıyla güncellendi.'];
            } else {
                return ['success' => false, 'message' => 'Revize durumu güncellenemedi.'];
            }
            
        } catch(PDOException $e) {
            error_log('updateRevisionStatus error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Veritabanı hatası oluştu: ' . $e->getMessage()];
        }
    }
    
    
    /**
     * Dosya durumunu güncelle ve kullanıcıya bildirim gönder
     * @param string $uploadId - Dosya ID
     * @param string $newStatus - Yeni durum
     * @param string $adminNotes - Admin notları
     * @param string $adminId - Admin ID
     * @return array - Sonuç
     */
    public function updateFileStatus($uploadId, $newStatus, $adminNotes = '', $adminId = null) {
        try {
            // Validasyon
            if (!isValidUUID($uploadId)) {
                return ['success' => false, 'message' => 'Geçersiz dosya ID formatı.'];
            }
            
            $allowedStatuses = ['pending', 'processing', 'completed', 'rejected', 'revision_requested'];
            if (!in_array($newStatus, $allowedStatuses)) {
                return ['success' => false, 'message' => 'Geçersiz durum.'];
            }
            
            // Dosya bilgilerini al
            $stmt = $this->pdo->prepare("
                SELECT fu.*, u.email, u.first_name, u.last_name
                FROM file_uploads fu
                LEFT JOIN users u ON fu.user_id = u.id
                WHERE fu.id = ?
            ");
            $stmt->execute([$uploadId]);
            $file = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$file) {
                return ['success' => false, 'message' => 'Dosya bulunamadı.'];
            }
            
            // Durumu güncelle
            $this->pdo->beginTransaction();
            
            try {
                $stmt = $this->pdo->prepare("
                    UPDATE file_uploads 
                    SET status = ?, admin_notes = ?, updated_at = NOW()
                    WHERE id = ?
                ");
                $stmt->execute([$newStatus, $adminNotes, $uploadId]);
                
                // Eğer revizyon talebi varsa ve durum değişiyorsa, revizyon talebini güncelle
                if ($newStatus === 'processing' || $newStatus === 'completed') {
                    $stmt = $this->pdo->prepare("
                        UPDATE revision_requests 
                        SET status = 'processed', updated_at = NOW()
                        WHERE upload_id = ? AND status = 'pending'
                    ");
                    $stmt->execute([$uploadId]);
                }
                
                // Kullanıcıya bildirim gönder
                try {
                    $statusMessages = [
                        'pending' => 'Dosyanız beklemede',
                        'processing' => 'Dosyanız işleniyor',
                        'completed' => 'Dosyanız tamamlandı',
                        'rejected' => 'Dosyanız reddedildi',
                        'revision_requested' => 'Revizyon talebi alındı'
                    ];
                    
                    $statusData = [
                        'user_name' => $file['first_name'] . ' ' . $file['last_name'],
                        'user_email' => $file['email'],
                        'file_name' => $file['original_name'],
                        'status' => $newStatus,
                        'status_message' => $statusMessages[$newStatus],
                        'admin_notes' => $adminNotes,
                        'update_time' => date('d.m.Y H:i:s')
                    ];
                    
                    $this->sendFileStatusUpdateNotificationToUser($statusData);
                    
                } catch(Exception $e) {
                    error_log('Status update notification error: ' . $e->getMessage());
                }
                
                $this->pdo->commit();
                
                return [
                    'success' => true,
                    'message' => 'Dosya durumu başarıyla güncellendi.',
                    'new_status' => $newStatus
                ];
                
            } catch(Exception $e) {
                $this->pdo->rollBack();
                throw $e;
            }
            
        } catch (Exception $e) {
            error_log('updateFileStatus error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Sistem hatası: ' . $e->getMessage()];
        }
    }
    
    /**
     * Revizyon talebine cevap olarak dosya yükle
     * @param string $revisionId - Revizyon talebi ID
     * @param array $fileData - Dosya verileri
     * @param string $adminNotes - Admin notları
     * @param string $adminId - Admin ID
     * @return array - Sonuç
     */
    public function uploadRevisionResponse($revisionId, $fileData, $adminNotes = '', $adminId = null) {
        try {
            // Validasyon
            if (!isValidUUID($revisionId)) {
                return ['success' => false, 'message' => 'Geçersiz revizyon ID formatı.'];
            }
            
            // Revizyon talebini al
            $stmt = $this->pdo->prepare("
                SELECT rr.*, fu.user_id, fu.original_name,
                       u.email, u.first_name, u.last_name
                FROM revision_requests rr
                LEFT JOIN file_uploads fu ON rr.upload_id = fu.id
                LEFT JOIN users u ON fu.user_id = u.id
                WHERE rr.id = ? AND rr.status = 'pending'
            ");
            $stmt->execute([$revisionId]);
            $revision = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$revision) {
                return ['success' => false, 'message' => 'Revizyon talebi bulunamadı veya zaten işlenmiş.'];
            }
            
            // Dosya kontrolleri
            $maxSize = 50 * 1024 * 1024; // 50MB
            if ($fileData['size'] > $maxSize) {
                return ['success' => false, 'message' => 'Dosya boyutu çok büyük (Max: 50MB).'];
            }
            
            // Upload dizini oluştur
            $uploadDir = __DIR__ . '/../uploads/revision_files/';
            if (!is_dir($uploadDir)) {
                mkdir($uploadDir, 0755, true);
            }
            
            // Dosya adı oluştur
            $fileExtension = pathinfo($fileData['name'], PATHINFO_EXTENSION);
            $newFileName = generateUUID() . '_revision.' . $fileExtension;
            $uploadPath = $uploadDir . $newFileName;
            
            // Dosyayı taşı
            if (!move_uploaded_file($fileData['tmp_name'], $uploadPath)) {
                return ['success' => false, 'message' => 'Dosya yükleme başarısız.'];
            }
            
            // Veritabanına kaydet
            $this->pdo->beginTransaction();
            
            try {
                $responseFileId = generateUUID();
                
                // Revizyon yanıt dosyasını kaydet
                $stmt = $this->pdo->prepare("
                    INSERT INTO revision_response_files (
                        id, revision_id, original_name, file_name, file_path, 
                        file_size, file_type, admin_notes, uploaded_by, upload_date
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
                ");
                
                $stmt->execute([
                    $responseFileId,
                    $revisionId,
                    $fileData['name'],
                    $newFileName,
                    $uploadPath,
                    $fileData['size'],
                    $fileData['type'],
                    $adminNotes,
                    $adminId
                ]);
                
                // Revizyon talebini tamamlanmış olarak işaretle
                $stmt = $this->pdo->prepare("
                    UPDATE revision_requests 
                    SET status = 'completed', updated_at = NOW()
                    WHERE id = ?
                ");
                $stmt->execute([$revisionId]);
                
                // Ana dosyanın durumunu tamamlanmış olarak güncelle
                $stmt = $this->pdo->prepare("
                    UPDATE file_uploads 
                    SET status = 'completed', admin_notes = ?, updated_at = NOW()
                    WHERE id = ?
                ");
                $stmt->execute([$adminNotes, $revision['upload_id']]);
                
                // Kullanıcıya email bildirim gönder
                try {
                    $emailData = [
                        'user_name' => $revision['first_name'] . ' ' . $revision['last_name'],
                        'user_email' => $revision['email'],
                        'original_file_name' => $revision['original_name'],
                        'response_file_name' => $fileData['name'],
                        'admin_notes' => $adminNotes,
                        'response_time' => date('d.m.Y H:i:s'),
                        'download_url' => (getenv('SITE_URL') ?: 'http://localhost') . '/user/revisions.php'
                    ];
                    
                    $this->sendFileResponseNotificationToUser($emailData, $revision['email']);
                    
                } catch(Exception $e) {
                    error_log('Revision response notification error: ' . $e->getMessage());
                }
                
                $this->pdo->commit();
                
                return [
                    'success' => true,
                    'message' => 'Revizyon yanıtı başarıyla yüklendi.',
                    'response_file_id' => $responseFileId
                ];
                
            } catch(Exception $e) {
                $this->pdo->rollBack();
                
                // Yüklenen dosyayı sil
                if (file_exists($uploadPath)) {
                    unlink($uploadPath);
                }
                
                throw $e;
            }
            
        } catch (Exception $e) {
            error_log('uploadRevisionResponse error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Sistem hatası: ' . $e->getMessage()];
        }
    }
    
    /**
     * Tüm ek dosyaları getir (Admin için)
     * @param int $page - Sayfa numarası
     * @param int $limit - Sayfa başına dosya sayısı
     * @param string $search - Arama terimi
     * @return array - Ek dosyalar listesi
     */
    public function getAllAdditionalFiles($page = 1, $limit = 20, $search = '') {
        try {
            $offset = ($page - 1) * $limit;
            $whereClause = "WHERE 1=1";
            $params = [];
            
            if ($search) {
                $whereClause .= " AND (af.original_name LIKE ? OR af.notes LIKE ? OR sender.first_name LIKE ? OR receiver.first_name LIKE ?)";
                $searchTerm = "%$search%";
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
            }
            
            $sql = "
                SELECT af.*, 
                       sender.username as sender_username, sender.first_name as sender_first_name, sender.last_name as sender_last_name,
                       receiver.username as receiver_username, receiver.first_name as receiver_first_name, receiver.last_name as receiver_last_name,
                       fu.original_name as related_file_name
                FROM additional_files af
                LEFT JOIN users sender ON af.sender_id = sender.id
                LEFT JOIN users receiver ON af.receiver_id = receiver.id
                LEFT JOIN file_uploads fu ON af.related_file_id = fu.id
                {$whereClause}
                ORDER BY af.upload_date DESC
                LIMIT " . intval($limit) . " OFFSET " . intval($offset);
            
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute($params);
            
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
            
        } catch(PDOException $e) {
            error_log('getAllAdditionalFiles error: ' . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Tüm ek dosya sayısını getir (Admin için)
     * @param string $search - Arama terimi
     * @return int - Toplam dosya sayısı
     */
    public function getAllAdditionalFilesCount($search = '') {
        try {
            $whereClause = "WHERE 1=1";
            $params = [];
            
            if ($search) {
                $whereClause .= " AND (af.original_name LIKE ? OR af.notes LIKE ? OR sender.first_name LIKE ? OR receiver.first_name LIKE ?)";
                $searchTerm = "%$search%";
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
            }
            
            $sql = "
                SELECT COUNT(*) as count
                FROM additional_files af
                LEFT JOIN users sender ON af.sender_id = sender.id
                LEFT JOIN users receiver ON af.receiver_id = receiver.id
                {$whereClause}
            ";
            
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute($params);
            
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            return $result['count'] ?? 0;
            
        } catch(PDOException $e) {
            error_log('getAllAdditionalFilesCount error: ' . $e->getMessage());
            return 0;
        }
    }
    
    /**
     * Araç bilgilerini al
     * @param array $uploadData - Yükleme verileri
     * @return array - Araç bilgileri
     */
    private function getVehicleInfo($uploadData) {
        $vehicleInfo = [
            'brand' => 'Bilinmiyor',
            'model' => 'Bilinmiyor',
            'series' => 'Bilinmiyor',
            'engine' => 'Bilinmiyor'
        ];
        
        try {
            // Marka adını al
            if (!empty($uploadData['brand_id'])) {
                $stmt = $this->pdo->prepare("SELECT name FROM brands WHERE id = ?");
                $stmt->execute([$uploadData['brand_id']]);
                $brand = $stmt->fetch(PDO::FETCH_ASSOC);
                if ($brand) $vehicleInfo['brand'] = $brand['name'];
            }
            
            // Model adını al
            if (!empty($uploadData['model_id'])) {
                $stmt = $this->pdo->prepare("SELECT name FROM models WHERE id = ?");
                $stmt->execute([$uploadData['model_id']]);
                $model = $stmt->fetch(PDO::FETCH_ASSOC);
                if ($model) $vehicleInfo['model'] = $model['name'];
            }
            
            // Seri adını al
            if (!empty($uploadData['series_id'])) {
                $stmt = $this->pdo->prepare("SELECT name FROM series WHERE id = ?");
                $stmt->execute([$uploadData['series_id']]);
                $series = $stmt->fetch(PDO::FETCH_ASSOC);
                if ($series) $vehicleInfo['series'] = $series['name'];
            }
            
            // Motor adını al
            if (!empty($uploadData['engine_id'])) {
                $stmt = $this->pdo->prepare("SELECT name FROM engines WHERE id = ?");
                $stmt->execute([$uploadData['engine_id']]);
                $engine = $stmt->fetch(PDO::FETCH_ASSOC);
                if ($engine) $vehicleInfo['engine'] = $engine['name'];
            }
            
        } catch (Exception $e) {
            error_log('getVehicleInfo error: ' . $e->getMessage());
        }
        
        return $vehicleInfo;
    }
    
    /**
     * Admin email adreslerini getir
     * @return array - Admin email listesi
     */
    private function getAdminEmails() {
        try {
            $stmt = $this->pdo->prepare("SELECT email FROM users WHERE role = 'admin' AND status = 'active' AND email_verified = 1");
            $stmt->execute();
            
            $emails = [];
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $emails[] = $row['email'];
            }
            
            // Fallback admin email
            if (empty($emails)) {
                $emails[] = 'admin@mrecu.com'; // Varsayılan admin email
            }
            
            return $emails;
            
        } catch(PDOException $e) {
            error_log('getAdminEmails error: ' . $e->getMessage());
            return ['admin@mrecu.com']; // Fallback
        }
    }
    
    /**
     * Kullanıcı dosya yüklediğinde admin'e email gönder
     * @param array $uploadData - Yükleme verileri
     * @return bool - Başarı durumu
     */
    public function sendFileUploadNotificationToAdmin($uploadData) {
        if (!$this->emailManager) {
            error_log('EmailManager not available for file upload notification');
            return false;
        }
        
        try {
            // Kullanıcı bilgilerini al
            $stmt = $this->pdo->prepare("
                SELECT email, first_name, last_name, phone 
                FROM users WHERE id = ?
            ");
            $stmt->execute([$uploadData['user_id']]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$user) {
                error_log('User not found for file upload notification: ' . $uploadData['user_id']);
                return false;
            }
            
            // Araç bilgilerini al
            $vehicleInfo = $this->getVehicleInfo($uploadData);
            
            // Admin email adresini al
            $adminEmails = $this->getAdminEmails();
            
            $emailData = [
                'user_name' => $user['first_name'] . ' ' . $user['last_name'],
                'user_email' => $user['email'],
                'user_phone' => $user['phone'] ?? '',
                'file_name' => $uploadData['original_name'],
                'plate' => $uploadData['plate'] ?? '',
                'vehicle_brand' => $vehicleInfo['brand'],
                'vehicle_model' => $vehicleInfo['model'],
                'vehicle_series' => $vehicleInfo['series'],
                'vehicle_engine' => $vehicleInfo['engine'],
                'vehicle_year' => $uploadData['year'] ?? '',
                'fuel_type' => $uploadData['fuel_type'] ?? '',
                'gearbox_type' => $uploadData['gearbox_type'] ?? '',
                'upload_notes' => $uploadData['upload_notes'] ?? '',
                'upload_time' => date('d.m.Y H:i:s'),
                'admin_url' => (getenv('SITE_URL') ?: 'http://localhost') . '/admin/uploads.php'
            ];
            
            // Tüm admin'lere email gönder
            $success = true;
            foreach ($adminEmails as $adminEmail) {
                $result = $this->emailManager->sendFileUploadNotificationToAdmin($emailData, $adminEmail);
                if (!$result) {
                    $success = false;
                    error_log('Failed to send upload notification to admin: ' . $adminEmail);
                }
            }
            
            return $success;
            
        } catch (Exception $e) {
            error_log('sendFileUploadNotificationToAdmin error: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Admin dosya yanıtladığında kullanıcıya bildirim gönder
     * @param array $responseData - Yanıt verileri
     * @return bool - Başarı durumu
     */
    public function sendFileResponseNotificationToUser($responseData) {
        if (!$this->emailManager) {
            error_log('EmailManager not available for file response notification');
            return false;
        }
        
        try {
            // Orijinal dosya ve kullanıcı bilgilerini al
            $stmt = $this->pdo->prepare("
                SELECT fu.original_name as original_file, fu.plate, fu.user_id,
                       u.email, u.first_name, u.last_name
                FROM file_uploads fu
                INNER JOIN users u ON fu.user_id = u.id
                WHERE fu.id = ?
            ");
            $stmt->execute([$responseData['upload_id']]);
            $uploadInfo = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$uploadInfo) {
                error_log('Upload info not found for response notification');
                return false;
            }
            
            $emailData = [
                'user_name' => $uploadInfo['first_name'] . ' ' . $uploadInfo['last_name'],
                'plate' => $uploadInfo['plate'] ?? '',
                'original_file_name' => $uploadInfo['original_file'],
                'response_file_name' => $responseData['original_name'],
                'admin_notes' => $responseData['admin_notes'] ?? '',
                'response_time' => date('d.m.Y H:i:s'),
                'download_url' => (getenv('SITE_URL') ?: 'http://localhost') . '/user/files.php'
            ];
            
            return $this->emailManager->sendFileResponseNotificationToUser($emailData, $uploadInfo['email']);
            
        } catch (Exception $e) {
            error_log('sendFileResponseNotificationToUser error: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Kullanıcı revizyon talep ettiğinde admin'e bildirim gönder
     * @param array $revisionData - Revizyon verileri
     * @return bool - Başarı durumu
     */
    public function sendRevisionRequestNotificationToAdmin($revisionData) {
        if (!$this->emailManager) {
            error_log('EmailManager not available for revision notification');
            return false;
        }
        
        try {
            // Kullanıcı ve dosya bilgilerini al
            $stmt = $this->pdo->prepare("
                SELECT fu.original_name, fu.user_id,
                       u.email, u.first_name, u.last_name
                FROM file_uploads fu
                INNER JOIN users u ON fu.user_id = u.id
                WHERE fu.id = ?
            ");
            $stmt->execute([$revisionData['upload_id']]);
            $uploadInfo = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$uploadInfo) {
                error_log('Upload info not found for revision notification');
                return false;
            }
            
            // Admin email adreslerini al
            $adminEmails = $this->getAdminEmails();
            
            $emailData = [
                'user_name' => $uploadInfo['first_name'] . ' ' . $uploadInfo['last_name'],
                'user_email' => $uploadInfo['email'],
                'file_name' => $uploadInfo['original_name'],
                'revision_notes' => $revisionData['request_notes'] ?? '',
                'request_time' => date('d.m.Y H:i:s'),
                'admin_url' => (getenv('SITE_URL') ?: 'http://localhost') . '/admin/revisions.php'
            ];
            
            // Tüm admin'lere email gönder
            $success = true;
            foreach ($adminEmails as $adminEmail) {
                $result = $this->emailManager->sendRevisionRequestNotificationToAdmin($emailData, $adminEmail);
                if (!$result) {
                    $success = false;
                    error_log('Failed to send revision notification to admin: ' . $adminEmail);
                }
            }
            
            return $success;
            
        } catch (Exception $e) {
            error_log('sendRevisionRequestNotificationToAdmin error: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Dosya durumu güncellendiğinde kullanıcıya bildirim gönder
     * @param array $statusData - Durum verileri
     * @return bool - Başarı durumu
     */
    public function sendFileStatusUpdateNotificationToUser($statusData) {
        if (!$this->emailManager) {
            error_log('EmailManager not available for status update notification');
            return false;
        }
        
        try {
            // Gerekli alanları kontrol et
            if (!isset($statusData['user_email']) || !isset($statusData['file_name'])) {
                error_log('Missing required fields for status update notification');
                return false;
            }
            
            // Varsayılan değerleri ayarla
            if (!isset($statusData['status_message'])) {
                $statusMessages = [
                    'pending' => 'Dosyanız beklemede',
                    'processing' => 'Dosyanız işleniyor',
                    'completed' => 'Dosyanız tamamlandı',
                    'rejected' => 'Dosyanız reddedildi'
                ];
                $statusData['status_message'] = $statusMessages[$statusData['status']] ?? 'Dosya durumu güncellendi';
            }
            
            if (!isset($statusData['update_time'])) {
                $statusData['update_time'] = date('d.m.Y H:i:s');
            }
            
            if (!isset($statusData['user_dashboard_url'])) {
                $statusData['user_dashboard_url'] = (getenv('SITE_URL') ?: 'http://localhost') . '/user/files.php';
            }
            
            if (!isset($statusData['contact_url'])) {
                $statusData['contact_url'] = (getenv('SITE_URL') ?: 'http://localhost') . '/contact.php';
            }
            
            // EmailManager'a yönlendir
            return $this->emailManager->sendFileStatusUpdateNotificationToUser($statusData);
            
        } catch (Exception $e) {
            error_log('FileManager::sendFileStatusUpdateNotificationToUser error: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Ek dosya yükle
     * @param string $relatedFileId - İlgili dosya ID
     * @param string $relatedFileType - İlgili dosya tipi (upload/response)
     * @param string $senderId - Gönderen ID
     * @param string $senderType - Gönderen tipi (user/admin)
     * @param string $receiverId - Alıcı ID
     * @param string $receiverType - Alıcı tipi (user/admin)
     * @param array $fileData - Dosya verileri
     * @param string $notes - Notlar
     * @param float $credits - Kredi miktarı
     * @return array - Sonuç
     */
    public function uploadAdditionalFile($relatedFileId, $relatedFileType, $senderId, $senderType, $receiverId, $receiverType, $fileData, $notes = '', $credits = 0) {
        try {
            // Validasyon
            if (!isValidUUID($relatedFileId) || !isValidUUID($senderId) || !isValidUUID($receiverId)) {
                return ['success' => false, 'message' => 'Geçersiz ID formatı.'];
            }
            
            // Dosya kontrolleri
            $allowedTypes = ['application/zip', 'application/x-zip-compressed', 'application/octet-stream', 'text/plain', 'image/jpeg', 'image/png', 'image/gif'];
            $maxSize = 50 * 1024 * 1024; // 50MB
            
            if ($fileData['size'] > $maxSize) {
                return ['success' => false, 'message' => 'Dosya boyutu çok büyük (Max: 50MB).'];
            }
            
            // Upload dizini oluştur
            $uploadDir = __DIR__ . '/../uploads/additional_files/';
            if (!is_dir($uploadDir)) {
                mkdir($uploadDir, 0755, true);
            }
            
            // Dosya adı oluştur
            $fileExtension = pathinfo($fileData['name'], PATHINFO_EXTENSION);
            $newFileName = generateUUID() . '_additional.' . $fileExtension;
            $uploadPath = $uploadDir . $newFileName;
            
            // Dosyayı taşı
            if (!move_uploaded_file($fileData['tmp_name'], $uploadPath)) {
                return ['success' => false, 'message' => 'Dosya yükleme başarısız.'];
            }
            
            // Veritabanına kaydet
            $this->pdo->beginTransaction();
            
            try {
                $additionalFileId = generateUUID();
                
                $stmt = $this->pdo->prepare("
                    INSERT INTO additional_files (
                        id, related_file_id, related_file_type, 
                        sender_id, sender_type, receiver_id, receiver_type,
                        original_name, file_name, file_path, file_size, file_type,
                        notes, credits, upload_date, is_read, is_cancelled
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), 0, 0)
                ");
                
                $stmt->execute([
                    $additionalFileId,
                    $relatedFileId,
                    $relatedFileType,
                    $senderId,
                    $senderType,
                    $receiverId,
                    $receiverType,
                    $fileData['name'],
                    $newFileName,
                    $uploadPath,
                    $fileData['size'],
                    $fileData['type'],
                    $notes,
                    $credits
                ]);
                
                // Kredi düşürme işlemi (eğer belirtilmişse ve gönderen admin ise)
                if ($credits > 0 && $senderType === 'admin') {
                    // User sınıfını dahil et
                    if (!class_exists('User')) {
                        require_once __DIR__ . '/User.php';
                    }
                    
                    $user = new User($this->pdo);
                    
                    // Kullanıcıdan kredi düşür (YENİ updateCredits metodu)
                    $creditResult = $user->updateCredits(
                        $receiverId, 
                        $credits, 
                        'additional_file_charge', 
                        [
                            'description' => 'Ek dosya ücreti: ' . $fileData['name'] . ' (Gönderen: ' . ($senderType === 'admin' ? 'Admin' : 'Kullanıcı') . ')',
                            'reference_id' => $additionalFileId,
                            'reference_type' => 'additional_file',
                            'admin_id' => ($senderType === 'admin' ? $senderId : null)
                        ]
                    );
                    
                    if (!$creditResult) {
                        // Kredi düşürülemezse işlemi geri al
                        $this->pdo->rollBack();
                        
                        // Yüklenen dosyayı sil
                        if (file_exists($uploadPath)) {
                            unlink($uploadPath);
                        }
                        
                        return ['success' => false, 'message' => 'Kredi düşürme işlemi başarısız. Yetersiz bakiye.'];
                    }
                    
                    error_log('uploadAdditionalFile: Credits charged successfully: ' . $credits . ' to user: ' . $receiverId);
                }
                
                // İlgili dosya adını al
                $relatedFileName = 'Bilinmiyor';
                try {
                    if ($relatedFileType === 'upload') {
                        $stmt = $this->pdo->prepare("SELECT original_name FROM file_uploads WHERE id = ?");
                        $stmt->execute([$relatedFileId]);
                        $related = $stmt->fetch(PDO::FETCH_ASSOC);
                        if ($related) $relatedFileName = $related['original_name'];
                    }
                    error_log('uploadAdditionalFile: Related file name: ' . $relatedFileName);
                } catch(Exception $e) {
                    error_log('uploadAdditionalFile: Related file name fetch error: ' . $e->getMessage());
                }
                
                // Bildirim gönder (sistem bildirimi) - DETAYLI DEBUG
                error_log('uploadAdditionalFile: Starting notification process...');
                error_log('uploadAdditionalFile: Sender: ' . $senderId . ' (' . $senderType . '), Receiver: ' . $receiverId . ' (' . $receiverType . ')');
                
                if (!class_exists('NotificationManager')) {
                    error_log('uploadAdditionalFile: Including NotificationManager.php');
                    require_once __DIR__ . '/NotificationManager.php';
                }
                
                try {
                    $notificationManager = new NotificationManager($this->pdo);
                    error_log('uploadAdditionalFile: NotificationManager created successfully');
                    
                    // Gönderici ve alıcı tipine göre doğru bildirimi gönder
                    if ($senderType === 'user' && $receiverType === 'admin') {
                        // Kullanıcıdan Admin'e
                        error_log('uploadAdditionalFile: Sending notification from user to admin');
                        $notificationResult = $notificationManager->notifyAdditionalFileToAdmin(
                            $additionalFileId,
                            $senderId,
                            $fileData['name'],
                            $notes,
                            $relatedFileName,
                            $relatedFileId
                        );
                        error_log('uploadAdditionalFile: User to admin notification result: ' . ($notificationResult ? 'success' : 'failed'));
                        
                    } elseif ($senderType === 'admin' && $receiverType === 'user') {
                        // Admin'den Kullanıcıya
                        error_log('uploadAdditionalFile: Sending notification from admin to user');
                        $notificationResult = $notificationManager->notifyAdditionalFileToUser(
                            $additionalFileId,
                            $receiverId,
                            $fileData['name'],
                            $notes,
                            $credits,
                            $relatedFileName,
                            $relatedFileId
                        );
                        error_log('uploadAdditionalFile: Admin to user notification result: ' . ($notificationResult ? 'success' : 'failed'));
                        
                    } else {
                        // Diğer durumlar için genel bildirim
                        error_log('uploadAdditionalFile: Sending generic notification');
                        $notificationTitle = 'Yeni Ek Dosya';
                        $notificationMessage = 'Yeni ek dosya aldınız: ' . $fileData['name'];
                        
                        if ($notes) {
                            $notificationMessage .= ' - Not: ' . $notes;
                        }
                        
                        if ($credits > 0) {
                            $notificationMessage .= ' (Ücret: ' . $credits . ' kredi)';
                        }
                        
                        $notificationResult = $notificationManager->createNotification(
                            $receiverId,
                            'additional_file',
                            $notificationTitle,
                            $notificationMessage,
                            $additionalFileId,
                            'additional_file',
                            'additional-files.php'
                        );
                        error_log('uploadAdditionalFile: Generic notification result: ' . ($notificationResult ? 'success' : 'failed'));
                    }
                    
                    if ($notificationResult) {
                        error_log('uploadAdditionalFile: Notification sent successfully to: ' . $receiverId);
                    } else {
                        error_log('uploadAdditionalFile: Notification failed to send to: ' . $receiverId);
                        // Manuel notification database kontrolü
                        try {
                            $stmt = $this->pdo->prepare("SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 5 MINUTE)");
                            $stmt->execute([$receiverId]);
                            $recentNotifCount = $stmt->fetch(PDO::FETCH_ASSOC)['count'];
                            error_log('uploadAdditionalFile: Recent notifications for user ' . $receiverId . ': ' . $recentNotifCount);
                        } catch(Exception $e) {
                            error_log('uploadAdditionalFile: Error checking recent notifications: ' . $e->getMessage());
                        }
                    }
                    
                } catch(Exception $e) {
                    error_log('uploadAdditionalFile: Notification error: ' . $e->getMessage());
                    error_log('uploadAdditionalFile: Notification error stack: ' . $e->getTraceAsString());
                    // Bildirim hatası ana işlemi etkilemesin
                }
                
                // Email bildirim gönder
                try {
                    $this->sendAdditionalFileNotification(
                        $additionalFileId,
                        $relatedFileId,
                        'additional_file',
                        $senderId . '/' . $senderType
                    );
                } catch(Exception $e) {
                    error_log('Additional file email notification error: ' . $e->getMessage());
                }
                
                // Transaction commit
                $this->pdo->commit();
                
                return [
                    'success' => true,
                    'message' => 'Ek dosya başarıyla yüklendi.',
                    'file_id' => $additionalFileId
                ];
                
            } catch(Exception $e) {
                // Transaction rollback
                $this->pdo->rollBack();
                
                // Yüklenen dosyayı sil
                if (file_exists($uploadPath)) {
                    unlink($uploadPath);
                }
                
                return ['success' => false, 'message' => 'Dosya yükleme hatası: ' . $e->getMessage()];
            }
            
        } catch(Exception $e) {
            error_log('uploadAdditionalFile error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Sistem hatası: ' . $e->getMessage()];
        }
    }
    
    /**
     * İlgili dosyaya ait ek dosyaları getir
     * @param string $relatedFileId - İlgili dosya ID
     * @param string $userId - Kullanıcı ID (yetki kontrolü için)
     * @param string $userType - Kullanıcı tipi (user/admin)
     * @return array - Ek dosyalar listesi
     */
    public function getAdditionalFiles($relatedFileId, $userId, $userType = 'user') {
        try {
            if (!isValidUUID($relatedFileId) || !isValidUUID($userId)) {
                return [];
            }
            
            // Admin her şeyi görebilir, user sadece iptal edilmemiş dosyaları görür
            $cancelledCondition = ($userType === 'admin') ? '' : 'AND (af.is_cancelled = 0 OR af.is_cancelled IS NULL)';
            
            $stmt = $this->pdo->prepare("
                SELECT af.*, 
                       sender.username as sender_username, sender.first_name as sender_first_name, sender.last_name as sender_last_name,
                       receiver.username as receiver_username, receiver.first_name as receiver_first_name, receiver.last_name as receiver_last_name
                FROM additional_files af
                LEFT JOIN users sender ON af.sender_id = sender.id
                LEFT JOIN users receiver ON af.receiver_id = receiver.id
                WHERE af.related_file_id = ?
                AND ((af.sender_id = ? AND af.sender_type = ?) OR (af.receiver_id = ? AND af.receiver_type = ?) OR ? = 'admin')
                {$cancelledCondition}
                ORDER BY af.upload_date DESC
            ");
            
            $stmt->execute([$relatedFileId, $userId, $userType, $userId, $userType, $userType]);
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
            
        } catch(PDOException $e) {
            error_log('getAdditionalFiles error: ' . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Ek dosya indirme
     * @param string $fileId - Ek dosya ID
     * @param string $userId - Kullanıcı ID (yetki kontrolü için)
     * @param string $userType - Kullanıcı tipi (user/admin)
     * @return array - Dosya bilgileri veya hata
     */
    public function downloadAdditionalFile($fileId, $userId, $userType = 'user') {
        try {
            if (!isValidUUID($fileId) || !isValidUUID($userId)) {
                return ['success' => false, 'message' => 'Geçersiz ID formatı.'];
            }
            
            // Admin iptal edilmiş dosyaları da indirebilir, user sadece aktif dosyaları
            $cancelledCondition = ($userType === 'admin') ? '' : 'AND (is_cancelled = 0 OR is_cancelled IS NULL)';
            
            $stmt = $this->pdo->prepare("
                SELECT * FROM additional_files
                WHERE id = ?
                AND ((sender_id = ? AND sender_type = ?) OR (receiver_id = ? AND receiver_type = ?) OR ? = 'admin')
                {$cancelledCondition}
            ");
            $stmt->execute([$fileId, $userId, $userType, $userId, $userType, $userType]);
            $file = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$file) {
                $errorMessage = ($userType === 'admin') ? 
                    'Dosya bulunamadı veya yetkiniz yok.' : 
                    'Dosya bulunamadı, iptal edilmiş veya yetkiniz yok.';
                return ['success' => false, 'message' => $errorMessage];
            }
            
            // Fiziksel dosya kontrolü
            if (!file_exists($file['file_path'])) {
                return ['success' => false, 'message' => 'Fiziksel dosya bulunamadı.'];
            }
            
            // Eğer alıcıysa ve okumadıysa, okundu olarak işaretle
            if ($file['receiver_id'] === $userId && !$file['is_read']) {
                $this->pdo->prepare("
                    UPDATE additional_files 
                    SET is_read = 1, read_date = NOW() 
                    WHERE id = ?
                ")->execute([$fileId]);
            }
            
            return [
                'success' => true,
                'file_path' => $file['file_path'],
                'original_name' => $file['original_name'],
                'file_size' => $file['file_size'],
                'file_type' => $file['file_type'],
                'is_cancelled' => $file['is_cancelled'] ?? 0
            ];
            
        } catch(PDOException $e) {
            error_log('downloadAdditionalFile error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Veritabanı hatası oluştu.'];
        }
    }
    
    /**
     * Okunmamış ek dosya sayısını getir
     * @param string $userId - Kullanıcı ID
     * @param string $userType - Kullanıcı tipi (user/admin)
     * @return int - Okunmamış dosya sayısı
     */
    public function getUnreadAdditionalFilesCount($userId, $userType = 'user') {
        try {
            if (!isValidUUID($userId)) {
                return 0;
            }
            
            $stmt = $this->pdo->prepare("
                SELECT COUNT(*) as count
                FROM additional_files
                WHERE receiver_id = ? AND receiver_type = ? AND is_read = 0
                AND (is_cancelled = 0 OR is_cancelled IS NULL)
            ");
            
            $stmt->execute([$userId, $userType]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            return $result['count'] ?? 0;
            
        } catch(PDOException $e) {
            error_log('getUnreadAdditionalFilesCount error: ' . $e->getMessage());
            return 0;
        }
    }
    
    /**
     * Ek dosya bildirimini gönder
     * @param string $fileId - Ek dosya ID
     * @param string $relatedFileId - İlgili dosya ID
     * @param string $notificationType - Bildirim tipi
     * @param string $actionUrl - Eylem URL'i
     * @return bool - Başarı durumu
     */
    public function sendAdditionalFileNotification($fileId, $relatedFileId, $notificationType, $actionUrl) {
        try {
            if (!$this->emailManager) {
                error_log('EmailManager not available for additional file notification');
                return false;
            }
            
            // Ek dosya bilgilerini al
            $stmt = $this->pdo->prepare("
                SELECT af.*, 
                       sender.email as sender_email, sender.first_name as sender_first_name, sender.last_name as sender_last_name,
                       receiver.email as receiver_email, receiver.first_name as receiver_first_name, receiver.last_name as receiver_last_name
                FROM additional_files af
                LEFT JOIN users sender ON af.sender_id = sender.id
                LEFT JOIN users receiver ON af.receiver_id = receiver.id
                WHERE af.id = ?
            ");
            $stmt->execute([$fileId]);
            $fileData = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$fileData) {
                error_log('Additional file not found for notification: ' . $fileId);
                return false;
            }
            
            // İlgili dosya adını ve plaka bilgisini al
            $relatedFileName = 'Bilinmiyor';
            $plate = '';
            if ($fileData['related_file_type'] === 'upload') {
                $stmt = $this->pdo->prepare("SELECT original_name, plate FROM file_uploads WHERE id = ?");
                $stmt->execute([$relatedFileId]);
                $related = $stmt->fetch(PDO::FETCH_ASSOC);
                if ($related) {
                    $relatedFileName = $related['original_name'];
                    $plate = $related['plate'] ?? '';
                }
            }
            
            $emailData = [
                'sender_name' => $fileData['sender_first_name'] . ' ' . $fileData['sender_last_name'],
                'sender_email' => $fileData['sender_email'],
                'receiver_name' => $fileData['receiver_first_name'] . ' ' . $fileData['receiver_last_name'],
                'receiver_email' => $fileData['receiver_email'],
                'plate' => $plate,
                'file_name' => $fileData['original_name'],
                'notes' => $fileData['notes'] ?? '',
                'related_file_name' => $relatedFileName,
                'upload_time' => date('d.m.Y H:i:s'),
                'admin_url' => (getenv('SITE_URL') ?: 'http://localhost') . '/admin/additional-files.php',
                'download_url' => (getenv('SITE_URL') ?: 'http://localhost') . '/user/additional-files.php'
            ];
            
            // Alıcıya göre email gönder
            $isToAdmin = ($fileData['receiver_type'] === 'admin');
            return $this->emailManager->sendAdditionalFileNotification($emailData, $isToAdmin);
            
        } catch (Exception $e) {
            error_log('sendAdditionalFileNotification error: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
 * Revizyon talebi oluştur
 * @param string $uploadId - Dosya ID
 * @param string $userId - Kullanıcı ID
 * @param string $revisionNotes - Revizyon notları
 * @param string $responseId - Yanıt dosyası ID (opsiyonel)
 * @return array - Sonuç
 */
public function requestRevision($uploadId, $userId, $revisionNotes, $responseId = null) {
    try {
        // Validasyon
        if (!isValidUUID($uploadId) || !isValidUUID($userId)) {
            return ['success' => false, 'message' => 'Geçersiz ID formatı.'];
        }
        
        if (empty(trim($revisionNotes))) {
            return ['success' => false, 'message' => 'Revizyon notları gereklidir.'];
        }
        
        // Dosyanın kullanıcıya ait olup olmadığını kontrol et
        $stmt = $this->pdo->prepare("SELECT * FROM file_uploads WHERE id = ? AND user_id = ?");
        $stmt->execute([$uploadId, $userId]);
        $file = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$file) {
            return ['success' => false, 'message' => 'Dosya bulunamadı veya yetkiniz yok.'];
        }
        
        // Dosyanın durumunu kontrol et
        if ($file['status'] !== 'completed') {
            return ['success' => false, 'message' => 'Sadece tamamlanmış dosyalar için revizyon talebi oluşturulabilir.'];
        }
        
        // Aktif revizyon talebi var mı kontrol et
        $stmt = $this->pdo->prepare("
            SELECT COUNT(*) as count 
            FROM revisions 
            WHERE upload_id = ? AND status = 'pending'
        ");
        $stmt->execute([$uploadId]);
        $activeRequests = $stmt->fetch(PDO::FETCH_ASSOC)['count'];
        
        if ($activeRequests > 0) {
            return ['success' => false, 'message' => 'Bu dosya için zaten aktif bir revizyon talebi var.'];
        }
        
        // Revizyon talebi oluştur
        $this->pdo->beginTransaction();
        
        try {
            $revisionId = generateUUID();
            
            $stmt = $this->pdo->prepare("
                INSERT INTO revisions (
                    id, upload_id, user_id, request_notes, 
                    status, requested_at, response_id
                ) VALUES (?, ?, ?, ?, 'pending', NOW(), ?)
            ");
            
            $stmt->execute([$revisionId, $uploadId, $userId, $revisionNotes, $responseId]);
            
            // Ana dosyanın revizyon sayısını artır
            $stmt = $this->pdo->prepare("
                UPDATE file_uploads 
                SET revision_count = COALESCE(revision_count, 0) + 1
                WHERE id = ?
            ");
            $stmt->execute([$uploadId]);
            
            // Admin'e bildirim gönder
            try {
                // NotificationManager ile bildirim
                if (!class_exists('NotificationManager')) {
                    require_once __DIR__ . '/NotificationManager.php';
                }
                
                $notificationManager = new NotificationManager($this->pdo);
                $notificationManager->notifyRevisionRequest($revisionId, $userId, $uploadId, $file['original_name'], $revisionNotes);
                
                // Ekstra: Eski fonksiyonla mail gönderimi
                $this->sendRevisionRequestNotificationToAdmin([
                    'upload_id' => $uploadId,
                    'request_notes' => $revisionNotes
                ]);
                
            } catch(Exception $e) {
                error_log('Revision notification error: ' . $e->getMessage());
            }
            
            $this->pdo->commit();
            
            return [
                'success' => true,
                'message' => 'Revizyon talebi başarıyla oluşturuldu.',
                'revision_id' => $revisionId
            ];
            
        } catch(Exception $e) {
            $this->pdo->rollBack();
            throw $e;
        }
        
    } catch (Exception $e) {
        error_log('requestRevision error: ' . $e->getMessage());
        return ['success' => false, 'message' => 'Sistem hatası: ' . $e->getMessage()];
    }
}
    
    /**
     * Kullanıcının revizyon taleplerini getir
     * @param string $userId - Kullanıcı ID
     * @param string $status - Durum filtresi (opsiyonel)
     * @return array - Revizyon talepleri
     */
    public function getUserRevisions($userId, $status = null) {
        try {
            if (!isValidUUID($userId)) {
                return [];
            }
            
            $whereClause = "WHERE r.user_id = ?";
            $params = [$userId];
            
            if ($status) {
                $whereClause .= " AND r.status = ?";
                $params[] = $status;
            }
            
            $stmt = $this->pdo->prepare("
                SELECT r.*, fu.original_name, fu.status as file_status,
                       admin.first_name as admin_first_name, admin.last_name as admin_last_name
                FROM revisions r
                LEFT JOIN file_uploads fu ON r.upload_id = fu.id
                LEFT JOIN users admin ON r.admin_id = admin.id
                {$whereClause}
                ORDER BY r.requested_at DESC
            ");
            
            $stmt->execute($params);
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
            
        } catch(PDOException $e) {
            error_log('getUserRevisions error: ' . $e->getMessage());
            return [];
        }
    }
}
?>
