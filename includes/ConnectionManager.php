<?php
/**
 * Mr ECU - Database Connection Manager
 * "Too many connections" sorununu çözmek için merkezi bağlantı yönetimi
 */

class ConnectionManager {
    private static $activeConnections = 0;
    private static $maxConnections = 10; // Aynı anda maximum bağlantı sayısı
    private static $connectionLog = [];
    
    /**
     * Yeni bağlantı kaydı tut
     */
    public static function registerConnection($source = 'unknown') {
        self::$activeConnections++;
        self::$connectionLog[] = [
            'source' => $source,
            'time' => microtime(true),
            'memory' => memory_get_usage(true)
        ];
        
        if (self::$activeConnections > self::$maxConnections) {
            error_log("WARNING: Too many active connections: " . self::$activeConnections);
        }
        
        if (getenv('DEBUG') === 'true' || (isset($_ENV['DEBUG']) && $_ENV['DEBUG'] === 'true')) {
            error_log("Connection registered from $source (Total: " . self::$activeConnections . ")");
        }
    }
    
    /**
     * Bağlantı kapatıldığında kaydı sil
     */
    public static function unregisterConnection($source = 'unknown') {
        self::$activeConnections--;
        
        if (getenv('DEBUG') === 'true' || (isset($_ENV['DEBUG']) && $_ENV['DEBUG'] === 'true')) {
            error_log("Connection closed from $source (Remaining: " . self::$activeConnections . ")");
        }
    }
    
    /**
     * Aktif bağlantı sayısını döndür
     */
    public static function getActiveConnections() {
        return self::$activeConnections;
    }
    
    /**
     * Bağlantı loglarını döndür
     */
    public static function getConnectionLog() {
        return self::$connectionLog;
    }
    
    /**
     * Tüm bağlantıları temizle (emergency)
     */
    public static function resetConnections() {
        self::$activeConnections = 0;
        self::$connectionLog = [];
        
        error_log("All connections reset by ConnectionManager");
    }
    
    /**
     * Connection status raporu
     */
    public static function getStatus() {
        return [
            'active' => self::$activeConnections,
            'max' => self::$maxConnections,
            'log_count' => count(self::$connectionLog),
            'warning' => self::$activeConnections > self::$maxConnections
        ];
    }
}

/**
 * Script sonunda bağlantı durumunu raporla
 */
register_shutdown_function(function() {
    $status = ConnectionManager::getStatus();
    
    if ($status['warning']) {
        error_log("CRITICAL: Script ended with " . $status['active'] . " active connections!");
        error_log("Connection log: " . print_r(ConnectionManager::getConnectionLog(), true));
    }
    
    if (getenv('DEBUG') === 'true' || (isset($_ENV['DEBUG']) && $_ENV['DEBUG'] === 'true')) {
        error_log("Script shutdown - Connection status: " . print_r($status, true));
    }
});
?>
