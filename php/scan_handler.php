<?php
session_start();
require_once __DIR__ . '/db_connect.php';

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['status' => 'error', 'message' => 'Invalid request method.']);
    exit;
}

$type = $_POST['type'] ?? '';
$url = trim($_POST['url'] ?? '');
$email = trim($_POST['email'] ?? '');

if ($type === 'url') {
    if (empty($url)) {
        echo json_encode(['status' => 'error', 'message' => 'URL is required.']);
        exit;
    }

    $hasHttps = preg_match('/^https:\/\//i', $url) === 1;
    $suspicious = preg_match('/login|verify|secure|update|bank|paypal|confirm|account|reset|claim/i', $url) === 1;
    $hasIp = preg_match('/\d+\.\d+\.\d+\.\d+/', $url) === 1;
    $lengthPenalty = strlen($url) > 70 ? 24 : 0;
    $score = min(98, 32 + ($suspicious ? 32 : 0) + (!$hasHttps ? 15 : 0) + ($hasIp ? 18 : 0) + $lengthPenalty);
    $safe = $score < 60;
    $confidence = max(10, 100 - $score);

    $result = $safe ? 'Safe' : 'Malicious';

    $userId = $_SESSION['user_id'] ?? null;
    if ($userId) {
        $stmt = $pdo->prepare('INSERT INTO url_scans (user_id, url, result, risk_score, confidence_score, scan_date) VALUES (:user_id, :url, :result, :risk_score, :confidence_score, NOW())');
        $stmt->execute([
            'user_id' => $userId,
            'url' => $url,
            'result' => $result,
            'risk_score' => round($score),
            'confidence_score' => round($confidence),
        ]);
    }

    echo json_encode([
        'status' => 'success',
        'safe' => $safe,
        'result' => $result,
        'risk_score' => round($score),
        'confidence_score' => round($confidence),
        'https_status' => $hasHttps ? 'Enabled' : 'Disabled',
        'domain' => parse_url($url, PHP_URL_HOST) ?: 'Unknown',
    ]);
    exit;
}

if ($type === 'email') {
    if (empty($email)) {
        echo json_encode(['status' => 'error', 'message' => 'Email content is required.']);
        exit;
    }

    $suspiciousTerms = preg_match('/urgent|click here|verify|password|suspended|account|winner|immediate/i', $email) === 1;
    $score = $suspiciousTerms ? 82 : 28;
    $result = $score >= 60 ? 'Phishing Email' : 'Safe Email';

    echo json_encode([
        'status' => 'success',
        'result' => $result,
        'risk_score' => $score,
        'message' => $score >= 60
            ? 'The message contains urgent language, credential requests, and suspicious wording commonly used in phishing attacks.'
            : 'No major indicators of phishing were found in the analyzed email content.'
    ]);
    exit;
}

echo json_encode(['status' => 'error', 'message' => 'Unknown scan type.']);
?>
