<?php
session_start();
require_once __DIR__ . '/db_connect.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: ../contact.html');
    exit;
}

$name = trim($_POST['name'] ?? '');
$email = trim($_POST['email'] ?? '');
$subject = trim($_POST['subject'] ?? '');
$message = trim($_POST['message'] ?? '');

if (empty($name) || empty($email) || empty($subject) || empty($message)) {
    $_SESSION['contact_error'] = 'Please complete all fields.';
    header('Location: ../contact.html');
    exit;
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $_SESSION['contact_error'] = 'Please enter a valid email address.';
    header('Location: ../contact.html');
    exit;
}

$stmt = $pdo->prepare('INSERT INTO feedback (name, email, subject, message, created_at) VALUES (:name, :email, :subject, :message, NOW())');
$stmt->execute([
    'name' => $name,
    'email' => $email,
    'subject' => $subject,
    'message' => $message,
]);

$_SESSION['contact_success'] = 'Your message was submitted successfully.';
header('Location: ../contact.html');
exit;
?>
