<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

class EclipseAPI {
    private $pdo;
    private $secretKey = 'eclipse_secret_key_2024';
    
    public function __construct() {
        $this->connectDB();
        $this->handleRequest();
    }
    
    private function connectDB() {
        $host = getenv('DB_HOST') ?: 'localhost';
        $dbname = getenv('DB_NAME') ?: 'eclipse_auth';
        $username = getenv('DB_USER') ?: 'root';
        $password = getenv('DB_PASS') ?: '';
        
        try {
            $this->pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8mb4", $username, $password);
            $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch (PDOException $e) {
            $this->sendResponse(['success' => false, 'message' => 'Database connection failed']);
        }
    }
    
    private function handleRequest() {
        $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        $endpoint = basename($path);
        
        $method = $_SERVER['REQUEST_METHOD'];
        $input = json_decode(file_get_contents('php://input'), true) ?: [];
        
        switch($endpoint) {
            case 'register':
                if ($method === 'POST') $this->register($input);
                break;
            case 'login':
                if ($method === 'POST') $this->login($input);
                break;
            case 'apps':
                $this->handleApps($method, $input);
                break;
            case 'keys':
                $this->handleKeys($method, $input);
                break;
            case 'verify':
                if ($method === 'POST') $this->verifyKey($input);
                break;
            default:
                $this->sendResponse(['success' => false, 'message' => 'Endpoint not found']);
        }
    }
    
    private function register($data) {
        $required = ['username', 'email', 'password'];
        if (!$this->validateInput($data, $required)) {
            $this->sendResponse(['success' => false, 'message' => 'Missing required fields']);
        }
        
        $username = $data['username'];
        $email = $data['email'];
        $password = password_hash($data['password'], PASSWORD_DEFAULT);
        
        try {
            $stmt = $this->pdo->prepare("INSERT INTO users (username, email, password, created_at) VALUES (?, ?, ?, NOW())");
            $stmt->execute([$username, $email, $password]);
            
            $this->sendResponse(['success' => true, 'message' => 'User registered successfully']);
        } catch (PDOException $e) {
            $this->sendResponse(['success' => false, 'message' => 'Registration failed: ' . $e->getMessage()]);
        }
    }
    
    private function login($data) {
        $required = ['username', 'password'];
        if (!$this->validateInput($data, $required)) {
            $this->sendResponse(['success' => false, 'message' => 'Missing required fields']);
        }
        
        $username = $data['username'];
        $password = $data['password'];
        
        try {
            $stmt = $this->pdo->prepare("SELECT * FROM users WHERE username = ? OR email = ?");
            $stmt->execute([$username, $username]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($user && password_verify($password, $user['password'])) {
                $token = $this->generateToken($user['id']);
                $this->sendResponse([
                    'success' => true, 
                    'token' => $token,
                    'user' => [
                        'id' => $user['id'],
                        'username' => $user['username'],
                        'email' => $user['email']
                    ]
                ]);
            } else {
                $this->sendResponse(['success' => false, 'message' => 'Invalid credentials']);
            }
        } catch (PDOException $e) {
            $this->sendResponse(['success' => false, 'message' => 'Login failed']);
        }
    }
    
    private function handleApps($method, $data) {
        $user = $this->authenticate();
        
        switch($method) {
            case 'GET':
                $this->getUserApps($user['id']);
                break;
            case 'POST':
                $this->createApp($user['id'], $data);
                break;
            default:
                $this->sendResponse(['success' => false, 'message' => 'Method not allowed']);
        }
    }
    
    private function getUserApps($userId) {
        try {
            $stmt = $this->pdo->prepare("
                SELECT a.*, 
                       (SELECT COUNT(*) FROM licenses WHERE app_id = a.id) as keys_count,
                       (SELECT COUNT(*) FROM sessions WHERE app_id = a.id AND expires_at > NOW()) as online_users
                FROM applications a 
                WHERE user_id = ?
            ");
            $stmt->execute([$userId]);
            $apps = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            $this->sendResponse(['success' => true, 'data' => $apps]);
        } catch (PDOException $e) {
            $this->sendResponse(['success' => false, 'message' => 'Failed to fetch apps']);
        }
    }
    
    private function createApp($userId, $data) {
        $required = ['name', 'version'];
        if (!$this->validateInput($data, $required)) {
            $this->sendResponse(['success' => false, 'message' => 'Missing required fields']);
        }
        
        $name = $data['name'];
        $version = $data['version'];
        $secret = bin2hex(random_bytes(32));
        
        try {
            $stmt = $this->pdo->prepare("
                INSERT INTO applications (user_id, name, version, secret, created_at) 
                VALUES (?, ?, ?, ?, NOW())
            ");
            $stmt->execute([$userId, $name, $version, $secret]);
            
            $this->sendResponse(['success' => true, 'message' => 'Application created successfully']);
        } catch (PDOException $e) {
            $this->sendResponse(['success' => false, 'message' => 'Failed to create application']);
        }
    }
    
    private function handleKeys($method, $data) {
        $user = $this->authenticate();
        
        switch($method) {
            case 'GET':
                $appId = $_GET['app_id'] ?? null;
                $this->getAppKeys($user['id'], $appId);
                break;
            case 'POST':
                $this->generateKey($user['id'], $data);
                break;
            default:
                $this->sendResponse(['success' => false, 'message' => 'Method not allowed']);
        }
    }
    
    private function getAppKeys($userId, $appId) {
        try {
            $stmt = $this->pdo->prepare("
                SELECT l.* 
                FROM licenses l 
                JOIN applications a ON l.app_id = a.id 
                WHERE a.user_id = ? AND l.app_id = ?
            ");
            $stmt->execute([$userId, $appId]);
            $keys = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            $this->sendResponse(['success' => true, 'data' => $keys]);
        } catch (PDOException $e) {
            $this->sendResponse(['success' => false, 'message' => 'Failed to fetch keys']);
        }
    }
    
    private function generateKey($userId, $data) {
        $required = ['app_id'];
        if (!$this->validateInput($data, $required)) {
            $this->sendResponse(['success' => false, 'message' => 'Missing app_id']);
        }
        
        $appId = $data['app_id'];
        $key = strtoupper(bin2hex(random_bytes(16)));
        $expiresAt = $data['expires_at'] ?? null;
        $hwidLocked = $data['hwid_locked'] ?? false;
        
        try {
            $stmt = $this->pdo->prepare("
                INSERT INTO licenses (app_id, license_key, hwid_locked, expires_at, created_at) 
                VALUES (?, ?, ?, ?, NOW())
            ");
            $stmt->execute([$appId, $key, $hwidLocked, $expiresAt]);
            
            $this->sendResponse(['success' => true, 'key' => $key]);
        } catch (PDOException $e) {
            $this->sendResponse(['success' => false, 'message' => 'Failed to generate key']);
        }
    }
    
    private function verifyKey($data) {
        $required = ['app_name', 'owner_id', 'version', 'license_key', 'hwid'];
        if (!$this->validateInput($data, $required)) {
            $this->sendResponse(['success' => false, 'message' => 'Missing required fields']);
        }
        
        $appName = $data['app_name'];
        $ownerId = $data['owner_id'];
        $version = $data['version'];
        $licenseKey = $data['license_key'];
        $hwid = $data['hwid'];
        
        try {
            $stmt = $this->pdo->prepare("
                SELECT l.*, a.name as app_name, a.user_id as owner_id 
                FROM licenses l 
                JOIN applications a ON l.app_id = a.id 
                WHERE a.name = ? AND a.user_id = ? AND l.license_key = ?
            ");
            $stmt->execute([$appName, $ownerId, $licenseKey]);
            $license = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$license) {
                $this->sendResponse(['success' => false, 'message' => 'Invalid license key']);
            }
            
            if ($license['hwid_locked'] && $license['hwid'] && $license['hwid'] !== $hwid) {
                $this->sendResponse(['success' => false, 'message' => 'HWID mismatch']);
            }
            
            if ($license['expires_at'] && strtotime($license['expires_at']) < time()) {
                $this->sendResponse(['success' => false, 'message' => 'License expired']);
            }
            
            if ($license['hwid_locked'] && !$license['hwid']) {
                $stmt = $this->pdo->prepare("UPDATE licenses SET hwid = ? WHERE id = ?");
                $stmt->execute([$hwid, $license['id']]);
            }
            
            $sessionId = bin2hex(random_bytes(32));
            $stmt = $this->pdo->prepare("
                INSERT INTO sessions (license_id, app_id, session_id, hwid, created_at, expires_at) 
                VALUES (?, ?, ?, ?, NOW(), DATE_ADD(NOW(), INTERVAL 1 HOUR))
            ");
            $stmt->execute([$license['id'], $license['app_id'], $sessionId, $hwid]);
            
            $this->sendResponse([
                'success' => true, 
                'session_id' => $sessionId,
                'message' => 'License verified successfully'
            ]);
            
        } catch (PDOException $e) {
            $this->sendResponse(['success' => false, 'message' => 'Verification failed']);
        }
    }
    
    private function authenticate() {
        $headers = getallheaders();
        $authHeader = $headers['Authorization'] ?? '';
        
        if (!preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
            $this->sendResponse(['success' => false, 'message' => 'Authentication required'], 401);
        }
        
        $token = $matches[1];
        
        try {
            $stmt = $this->pdo->prepare("SELECT u.* FROM users u JOIN sessions s ON u.id = s.user_id WHERE s.token = ? AND s.expires_at > NOW()");
            $stmt->execute([$token]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$user) {
                $this->sendResponse(['success' => false, 'message' => 'Invalid token'], 401);
            }
            
            return $user;
        } catch (PDOException $e) {
            $this->sendResponse(['success' => false, 'message' => 'Authentication failed'], 401);
        }
    }
    
    private function generateToken($userId) {
        $token = bin2hex(random_bytes(32));
        $expiresAt = date('Y-m-d H:i:s', strtotime('+1 day'));
        
        $stmt = $this->pdo->prepare("INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)");
        $stmt->execute([$userId, $token, $expiresAt]);
        
        return $token;
    }
    
    private function validateInput($data, $required) {
        foreach ($required as $field) {
            if (empty($data[$field])) {
                return false;
            }
        }
        return true;
    }
    
    private function sendResponse($data, $httpCode = 200) {
        http_response_code($httpCode);
        echo json_encode($data);
        exit;
    }
}

new EclipseAPI();
?>
