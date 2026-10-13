<?php
session_start();
require_once __DIR__ . '/db_connect.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: ../register.html');
    exit;
}

$fullname = trim($_POST['fullname'] ?? '');
$username = trim($_POST['username'] ?? '');
$email = trim($_POST['email'] ?? '');
$password = $_POST['password'] ?? '';
$confirmPassword = $_POST['confirmPassword'] ?? '';

if (empty($fullname) || empty($username) || empty($email) || empty($password)) {
    $_SESSION['register_error'] = 'All fields are required.';
    header('Location: ../register.html');
    exit;
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $_SESSION['register_error'] = 'Please enter a valid email address.';
    header('Location: ../register.html');
    exit;
}

if ($password !== $confirmPassword) {
    $_SESSION['register_error'] = 'Passwords do not match.';
    header('Location: ../register.html');
    exit;
}

if (strlen($password) < 8) {
    $_SESSION['register_error'] = 'Password must be at least 8 characters long.';
    header('Location: ../register.html');
    exit;
}

$stmt = $pdo->prepare('SELECT id FROM users WHERE email = :email OR username = :username LIMIT 1');
$stmt->execute(['email' => $email, 'username' => $username]);

if ($stmt->fetch()) {
    $_SESSION['register_error'] = 'A user with that email or username already exists.';
    header('Location: ../register.html');
    exit;
}

$hash = password_hash($password, PASSWORD_DEFAULT);

$stmt = $pdo->prepare('INSERT INTO users (fullname, username, email, password_hash, created_at) VALUES (:fullname, :username, :email, :password_hash, NOW())');
$stmt->execute([
    'fullname' => $fullname,
    'username' => $username,
    'email' => $email,
    'password_hash' => $hash,
]);

$_SESSION['register_success'] = 'Registration successful. Please log in.';
header('Location: ../login.html');
exit;
?>
