<?php
/**
 * Mr ECU - Database Connection Diagnostics
 * "Too many connections" sorununu debug etmek için
 * 
 * KULLANIM:
 * https://mrecutuning.com/debug/check-connections.php
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Database Connection Diagnostics</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .status { padding: 15px; margin: 10px 0; border-radius: 5px; font-weight: bold; }
        .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .warning { background: #fff3cd; color: #856404; border: 1px solid #ffeaa7; }
        .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #007bff; color: white; }
        tr:hover { background: #f5f5f5; }
        code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; }
        pre { background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }
        .metric { display: inline-block; margin: 10px 20px 10px 0; }
        .metric-value { font-size: 32px; font-weight: bold; color: #007bff; }
        .metric-label { font-size: 14px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Database Connection Diagnostics</h1>
        <p>Bu sayfa veritabanı bağlantı sorunlarını tespit etmek için kullanılır.</p>

        <?php
        // .env dosyasını yükle
        function loadEnvFile($path) {
            if (!file_exists($path)) return false;
            
            $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            foreach ($lines as $line) {
                if (strpos($line, '#') === 0 || strpos($line, '=') === false) continue;
                list($key, $value) = explode('=', $line, 2);
                $_ENV[trim($key)] = trim($value, '"');
            }
            return true;
        }

        loadEnvFile(__DIR__ . '/../.env');

        // Database bağlantı bilgileri
        $db_host = $_ENV['DB_HOST'] ?? '127.0.0.1';
        $db_port = $_ENV['DB_PORT'] ?? '3306';
        $db_name = $_ENV['DB_NAME'] ?? 'mrecu_db_guid';
        $db_user = $_ENV['DB_USERNAME'] ?? 'root';
        $db_pass = $_ENV['DB_PASSWORD'] ?? 'root';

        echo "<h2>📊 Bağlantı Bilgileri</h2>";
        echo "<div class='info status'>";
        echo "Host: <code>$db_host:$db_port</code><br>";
        echo "Database: <code>$db_name</code><br>";
        echo "User: <code>$db_user</code>";
        echo "</div>";

        // Test bağlantısı
        echo "<h2>🔌 Bağlantı Testi</h2>";
        $connectionStart = microtime(true);
        
        try {
            $dsn = "mysql:host=$db_host;port=$db_port;dbname=$db_name;charset=utf8mb4";
            $pdo = new PDO($dsn, $db_user, $db_pass, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_TIMEOUT => 5,
                PDO::ATTR_PERSISTENT => false
            ]);
            
            $connectionTime = round((microtime(true) - $connectionStart) * 1000, 2);
            
            echo "<div class='success status'>";
            echo "✅ Bağlantı başarılı! ($connectionTime ms)";
            echo "</div>";
            
            // MySQL Version
            $version = $pdo->query("SELECT VERSION() as version")->fetch();
            echo "<div class='info status'>";
            echo "MySQL Version: <code>{$version['version']}</code>";
            echo "</div>";
            
        } catch (PDOException $e) {
            echo "<div class='error status'>";
            echo "❌ Bağlantı başarısız: " . htmlspecialchars($e->getMessage());
            echo "</div>";
            echo "</div></body></html>";
            exit;
        }

        // MySQL Status Variables
        echo "<h2>📈 MySQL Status</h2>";
        
        $statusVars = [
            'Threads_connected' => 'Aktif Bağlantılar',
            'Max_used_connections' => 'En Fazla Kullanılan Bağlantı',
            'Aborted_connects' => 'Başarısız Bağlantılar',
            'Connections' => 'Toplam Bağlantı Denemesi',
            'Uptime' => 'Çalışma Süresi (saniye)'
        ];

        $metrics = [];
        foreach ($statusVars as $var => $label) {
            try {
                $result = $pdo->query("SHOW STATUS LIKE '$var'")->fetch();
                if ($result) {
                    $metrics[$var] = $result['Value'];
                    
                    echo "<div class='metric'>";
                    echo "<div class='metric-value'>" . number_format($result['Value']) . "</div>";
                    echo "<div class='metric-label'>$label</div>";
                    echo "</div>";
                }
            } catch (PDOException $e) {
                // Skip
            }
        }

        // MySQL Variables (max_connections)
        echo "<h2>⚙️ MySQL Konfigürasyonu</h2>";
        
        $configVars = [
            'max_connections' => 'Maximum Bağlantı Limiti',
            'max_user_connections' => 'Kullanıcı Başına Max Bağlantı',
            'wait_timeout' => 'Bekleme Timeout (saniye)',
            'interactive_timeout' => 'Interactive Timeout (saniye)'
        ];

        echo "<table>";
        echo "<tr><th>Değişken</th><th>Değer</th><th>Açıklama</th></tr>";
        
        foreach ($configVars as $var => $label) {
            try {
                $result = $pdo->query("SHOW VARIABLES LIKE '$var'")->fetch();
                if ($result) {
                    $value = $result['Value'];
                    $class = '';
                    $note = '';
                    
                    // max_connections kontrolü
                    if ($var === 'max_connections') {
                        if ($value < 50) {
                            $class = 'error';
                            $note = '⚠️ Çok düşük! En az 100 olmalı';
                        } elseif ($value < 100) {
                            $class = 'warning';
                            $note = '⚠️ Düşük! 150+ önerilir';
                        } else {
                            $class = 'success';
                            $note = '✅ İyi';
                        }
                        
                        // Kullanım oranı
                        if (isset($metrics['Threads_connected'])) {
                            $usage = round(($metrics['Threads_connected'] / $value) * 100, 1);
                            $note .= " (Kullanım: $usage%)";
                            
                            if ($usage > 80) {
                                $note .= " 🔴 KRİTİK!";
                            } elseif ($usage > 60) {
                                $note .= " ⚠️ YÜKSEK";
                            }
                        }
                    }
                    
                    echo "<tr class='$class'>";
                    echo "<td><code>$var</code></td>";
                    echo "<td><strong>" . htmlspecialchars($value) . "</strong></td>";
                    echo "<td>$label $note</td>";
                    echo "</tr>";
                }
            } catch (PDOException $e) {
                // Skip
            }
        }
        echo "</table>";

        // Process List - Aktif sorgular
        echo "<h2>🔍 Aktif Bağlantılar (Process List)</h2>";
        
        try {
            $processes = $pdo->query("SHOW FULL PROCESSLIST")->fetchAll();
            
            echo "<div class='info status'>";
            echo "Toplam " . count($processes) . " aktif process bulundu";
            echo "</div>";
            
            echo "<table>";
            echo "<tr><th>ID</th><th>User</th><th>Host</th><th>Database</th><th>Command</th><th>Time</th><th>State</th><th>Info</th></tr>";
            
            $sleepCount = 0;
            foreach ($processes as $process) {
                $rowClass = '';
                if ($process['Command'] === 'Sleep') {
                    $sleepCount++;
                    $rowClass = 'warning';
                }
                if ($process['Time'] > 60) {
                    $rowClass = 'error';
                }
                
                echo "<tr class='$rowClass'>";
                echo "<td>" . htmlspecialchars($process['Id']) . "</td>";
                echo "<td>" . htmlspecialchars($process['User']) . "</td>";
                echo "<td>" . htmlspecialchars($process['Host']) . "</td>";
                echo "<td>" . htmlspecialchars($process['db'] ?? '') . "</td>";
                echo "<td>" . htmlspecialchars($process['Command']) . "</td>";
                echo "<td>" . htmlspecialchars($process['Time']) . "s</td>";
                echo "<td>" . htmlspecialchars($process['State'] ?? '') . "</td>";
                echo "<td>" . htmlspecialchars(substr($process['Info'] ?? '', 0, 50)) . "</td>";
                echo "</tr>";
            }
            echo "</table>";
            
            if ($sleepCount > 10) {
                echo "<div class='warning status'>";
                echo "⚠️ $sleepCount adet Sleep durumunda bağlantı var! Bu bağlantılar kapatılmamış olabilir.";
                echo "</div>";
            }
            
        } catch (PDOException $e) {
            echo "<div class='error status'>";
            echo "Process list alınamadı: " . htmlspecialchars($e->getMessage());
            echo "</div>";
        }

        // Öneriler
        echo "<h2>💡 Öneriler</h2>";
        
        echo "<div class='info status'>";
        echo "<h3>Hosting Ayarları:</h3>";
        echo "<pre>";
        echo "my.cnf veya Plesk'ten ayarlanmalı:\n\n";
        echo "max_connections = 150\n";
        echo "max_user_connections = 50\n";
        echo "wait_timeout = 300\n";
        echo "interactive_timeout = 300\n";
        echo "</pre>";
        echo "</div>";

        echo "<div class='warning status'>";
        echo "<h3>⚠️ \"Too Many Connections\" Hatası İçin:</h3>";
        echo "<ol>";
        echo "<li>MySQL <code>max_connections</code> değerini artırın (en az 150)</li>";
        echo "<li>PHP-FPM <code>pm.max_children</code> değerini kontrol edin (MySQL'den az olmalı)</li>";
        echo "<li>Uygulamadaki bağlantı sızıntılarını bulun (Sleep processler)</li>";
        echo "<li>Persistent connection kapatıldı, script sonunda bağlantılar otomatik kapanıyor</li>";
        echo "<li>Hosting provider'ınızın limitlerini kontrol edin</li>";
        echo "</ol>";
        echo "</div>";

        // PHP-FPM Info
        if (function_exists('posix_getpwuid')) {
            echo "<h2>🐘 PHP-FPM Bilgisi</h2>";
            echo "<div class='info status'>";
            echo "PHP Version: <code>" . PHP_VERSION . "</code><br>";
            echo "SAPI: <code>" . php_sapi_name() . "</code><br>";
            echo "Max Execution Time: <code>" . ini_get('max_execution_time') . "</code> saniye<br>";
            echo "Memory Limit: <code>" . ini_get('memory_limit') . "</code><br>";
            echo "Current Memory Usage: <code>" . round(memory_get_usage(true)/1024/1024, 2) . "</code> MB";
            echo "</div>";
        }

        // Bağlantıyı kapat
        $pdo = null;
        
        echo "<div class='success status'>";
        echo "✅ Test bağlantısı düzgün kapatıldı";
        echo "</div>";
        ?>

        <p style="margin-top: 30px; color: #666; font-size: 12px;">
            <strong>Not:</strong> Bu sayfa sadece diagnostic amaçlı kullanılmalı ve production'da public erişime kapatılmalıdır.
        </p>
    </div>
</body>
</html>
