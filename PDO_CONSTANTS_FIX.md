# PDO MySQL Sabitleri Hatası - Çözüm

## Hata
```
Undefined class constant 'MYSQL_ATTR_CONNECT_TIMEOUT'
```

## Neden Oluşur?
Bu hata şu durumlarda oluşur:
- Eski PHP versiyonları (< 7.0)
- MySQL PDO driver eksik veya yanlış yapılandırılmış
- PDO MySQL extension yüklü değil

## Çözüm
`database.php` dosyasında tüm MySQL sabitleri artık `defined()` kontrolü ile korunuyor:

```php
// ❌ YANLIŞ (Hata verir)
$options = [
    PDO::MYSQL_ATTR_CONNECT_TIMEOUT => 5,
    PDO::MYSQL_ATTR_USE_BUFFERED_QUERY => true,
];

// ✅ DOĞRU (Güvenli)
$options = [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_PERSISTENT => false,
];

// MySQL özel ayarları - sadece destekleniyorsa ekle
if (defined('PDO::MYSQL_ATTR_INIT_COMMAND')) {
    $options[PDO::MYSQL_ATTR_INIT_COMMAND] = "SET NAMES utf8mb4";
}

if (defined('PDO::MYSQL_ATTR_CONNECT_TIMEOUT')) {
    $options[PDO::MYSQL_ATTR_CONNECT_TIMEOUT] = 5;
}
```

## Güncellenen Dosya
`/config/database.php` - Tüm MySQL sabitleri artık defined() kontrolü ile korunuyor

## Kontrol Edilenler
- ✅ `PDO::MYSQL_ATTR_INIT_COMMAND`
- ✅ `PDO::MYSQL_ATTR_USE_BUFFERED_QUERY`
- ✅ `PDO::MYSQL_ATTR_CONNECT_TIMEOUT`
- ✅ `PDO::ATTR_TIMEOUT`

## Test
```php
<?php
// PDO MySQL desteğini kontrol et
echo "PDO Drivers: " . implode(', ', PDO::getAvailableDrivers()) . "\n";

// MySQL sabitleri kontrolü
$constants = [
    'PDO::MYSQL_ATTR_INIT_COMMAND',
    'PDO::MYSQL_ATTR_CONNECT_TIMEOUT',
    'PDO::MYSQL_ATTR_USE_BUFFERED_QUERY',
];

foreach ($constants as $const) {
    echo "$const: " . (defined($const) ? '✅ Tanımlı' : '❌ Tanımsız') . "\n";
}
?>
```

## Sonuç
Artık farklı PHP/MySQL versiyonlarında da sorunsuz çalışacak! 🎉
