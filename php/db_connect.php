<?php
$host = 'localhost';
$dbName = 'phishguard';
$dbUser = 'root';
$dbPass = '';

try {
    $pdo = new PDO("mysql:host={$host};dbname={$dbName};charset=utf8mb4", $dbUser, $dbPass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
} catch (PDOException $e) {
    http_response_code(503);
    echo json_encode([
        'status' => 'error',
        'message' => 'Database connection failed. Please ensure MySQL is running and the database exists.'
    ]);
    exit;
}
?>
