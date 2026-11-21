<?php
declare(strict_types=1);

/**
 * ITCS333 Project — m1_auth handler
 *
 * Endpoints:
 * POST /api/auth/register
 * POST /api/auth/login
 * POST /api/auth/logout
 * GET  /api/auth/me
 */

$rest = ltrim($GLOBALS['__route']['rest'] ?? '', '/');


// ==================================================
// REGISTER
// POST /api/auth/register
// ==================================================

if ($rest === 'register') {

    if (http_method() !== 'POST') {
        send_error(405, 'METHOD_NOT_ALLOWED');
    }

    $data = json_body();

    $username = $data['username'] ?? '';
    $password = $data['password'] ?? '';

    // Validate username
    if (!is_string($username) || trim($username) === '') {
        send_error(422, 'VALIDATION', [
            'fields' => ['username' => 'required']
        ]);
    }

    $username = trim($username);

    if (strlen($username) > 50) {
        send_error(422, 'VALIDATION', [
            'fields' => ['username' => 'max_length']
        ]);
    }

    // Validate password
    if (!is_string($password) || $password === '') {
        send_error(422, 'VALIDATION', [
            'fields' => ['password' => 'required']
        ]);
    }

    // Validate is_admin (optional, defaults to 0)
    $isAdmin = $data['is_admin'] ?? 0;

    if (!in_array($isAdmin, [0, 1], true)) {
        send_error(422, 'VALIDATION', [
            'fields' => ['is_admin' => 'invalid']
        ]);
    }

    $pdo = db();

    // Check whether username already exists
    $stmt = $pdo->prepare(
        'SELECT id FROM users WHERE username = :username'
    );

    $stmt->execute([
        'username' => $username
    ]);

    if ($stmt->fetch(PDO::FETCH_ASSOC)) {
        send_error(409, 'USERNAME_TAKEN');
    }

    // Hash password before storing it
    $passwordHash = password_hash($password, PASSWORD_BCRYPT);

    // Insert user using the project's database helper
   
try {
    $id = db_insert_and_get_id($pdo, 'users', [
        'username' => $username,
        'password_hash' => $passwordHash,
        'is_admin' => $isAdmin
    ]);
} catch (PDOException $e) {
    if ($e->getCode() === '23000') {
        send_error(409, 'USERNAME_TAKEN');
    }

    throw $e;
}


    send_json(201, [
        'id' => $id,
        'username' => $username,
        'is_admin' => $isAdmin
    ]);
}


// ==================================================
// LOGIN
// POST /api/auth/login
// ==================================================

if ($rest === 'login') {

    if (http_method() !== 'POST') {
        send_error(405, 'METHOD_NOT_ALLOWED');
    }

    $data = json_body();

    $username = $data['username'] ?? '';
    $password = $data['password'] ?? '';

    if (
        !is_string($username) ||
        !is_string($password) ||
        $username === '' ||
        $password === ''
    ) {
        send_error(401, 'INVALID_CREDENTIALS');
    }

    $pdo = db();

    // Find user by username
    $stmt = $pdo->prepare(
        'SELECT id, username, password_hash, is_admin
         FROM users
         WHERE username = :username'
    );

    $stmt->execute([
        'username' => trim($username)
    ]);

    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    // Check username and password
    if (
        !$user ||
        !password_verify($password, $user['password_hash'])
    ) {
        send_error(401, 'INVALID_CREDENTIALS');
    }

    // Regenerate session ID after successful login
    session_regenerate_id(true);

    // Store authenticated user information in session
    $_SESSION['user_id'] = (int) $user['id'];
    $_SESSION['username'] = $user['username'];
    $_SESSION['is_admin'] = (int) $user['is_admin'];

    // Generate a session-related token
    $token = bin2hex(random_bytes(32));
    $_SESSION['csrf_token'] = $token;

    send_json(200, [
        'id' => (int) $user['id'],
        'username' => $user['username'],
        'is_admin' => (int) $user['is_admin'],
        'token' => $token
    ]);
}


// ==================================================
// LOGOUT
// POST /api/auth/logout
// ==================================================

if ($rest === 'logout') {

    if (http_method() !== 'POST') {
        send_error(405, 'METHOD_NOT_ALLOWED');
    }

    // Clear session data
    $_SESSION = [];

    // Remove the session cookie
    if (ini_get('session.use_cookies')) {

        $params = session_get_cookie_params();

        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params['path'],
            $params['domain'],
            $params['secure'],
            $params['httponly']
        );
    }

    // Destroy the session
    session_destroy();

    send_json(200, [
        'ok' => true
    ]);
}


// ==================================================
// ME
// GET /api/auth/me
// ==================================================

if ($rest === 'me') {

    if (http_method() !== 'GET') {
        send_error(405, 'METHOD_NOT_ALLOWED');
    }

    // Check whether a user is logged in
    if (!isset($_SESSION['user_id'])) {
        send_error(401, 'AUTH_REQUIRED');
    }

    $pdo = db();

    // Get current user information from database
    $stmt = $pdo->prepare(
        'SELECT id, username, is_admin
         FROM users
         WHERE id = :id'
    );

    $stmt->execute([
        'id' => (int) $_SESSION['user_id']
    ]);

    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    // User may have been deleted
    if (!$user) {
        $_SESSION = [];
        session_destroy();

        send_error(401, 'AUTH_REQUIRED');
    }

    send_json(200, [
        'id' => (int) $user['id'],
        'username' => $user['username'],
        'is_admin' => (int) $user['is_admin']
    ]);
}


// ==================================================
// UNKNOWN ENDPOINT
// ==================================================

send_error(404, 'NOT_FOUND', [
    'module' => 'm1_auth',
    'rest' => $rest
]);
