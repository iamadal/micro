
<?php
namespace Micro;

class Router {
    private static $routes = [];
    private static $globalMiddlewares = [];
    private static $requestLimit = 100;
    private static $timeFrame = 3600;
    private static $requests = [];
    private static $csrfTokenLifetime = 3600;
    private static $authRoutes = [];

    public static function init() { 
        self::startSession(); 
    }

    private static function startSession() { 
        if (session_status() === PHP_SESSION_NONE) { 
            session_start(); 
        } 
    }

    public static function middleware($callback) {
        self::$globalMiddlewares[] = $callback;
    }

    private static function runMiddlewares($middlewares) {
        foreach ($middlewares as $middleware) {
            $response = $middleware();
            if ($response === false) {
                exit; // Stop further processing if middleware fails
            }
        }
    }

    public static function get($path, $callback, $authRequired = false, $middlewares = []) { 
        self::$routes['GET'][rtrim($path, '/')] = [
            'callback' => $callback,
            'authRequired' => $authRequired,
            'middlewares' => $middlewares
        ];
    }

    public static function post($path, $callback, $authRequired = false, $middlewares = []) { 
        self::$routes['POST'][rtrim($path, '/')] = [
            'callback' => $callback,
            'authRequired' => $authRequired,
            'middlewares' => $middlewares
        ];
    }

    public static function run() {
        self::init();
        self::setSecureHeaders();
        $method = $_SERVER['REQUEST_METHOD'];
        $path = rtrim(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), '/');

        self::limitRequests();
        self::runMiddlewares(self::$globalMiddlewares);

        if (isset(self::$routes[$method][$path])) {
            $route = self::$routes[$method][$path];

            if (self::isAuthRequired($route['authRequired']) && !self::isAuthenticated()) {
                http_response_code(401);
                exit("Unauthorized");
            }

            self::runMiddlewares($route['middlewares']);
            if ($method !== 'GET') {
                self::validateCsrfToken();
            }

            call_user_func($route['callback']);
        } else {
            http_response_code(404);
            echo "404 Not Found";
        }
    }

    private static function setSecureHeaders() {
        header("X-Content-Type-Options: nosniff");
        header("X-XSS-Protection: 1; mode=block");
        header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self';");
        header("X-Frame-Options: DENY");
        header("Referrer-Policy: no-referrer");
        header("Strict-Transport-Security: max-age=63072000; includeSubDomains; preload");
    }

    private static function limitRequests() {
        $ip = $_SERVER['REMOTE_ADDR'];
        $currentTime = time();

        if (!isset(self::$requests[$ip])) {
            self::$requests[$ip] = ['count' => 1, 'start' => $currentTime];
        } else {
            if ($currentTime - self::$requests[$ip]['start'] > self::$timeFrame) {
                self::$requests[$ip] = ['count' => 1, 'start' => $currentTime];
            } else {
                self::$requests[$ip]['count']++;
                if (self::$requests[$ip]['count'] > self::$requestLimit) {
                    http_response_code(429);
                    exit("Too many requests.");
                }
            }
        }
    }

    public static function csrf() {
        if (empty($_SESSION['csrf_token']) || empty($_SESSION['csrf_token_expiry']) || time() > $_SESSION['csrf_token_expiry']) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            $_SESSION['csrf_token_expiry'] = time() + self::$csrfTokenLifetime;
        }
        return $_SESSION['csrf_token'];
    }

    private static function validateCsrfToken() {
        if (empty($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            http_response_code(403);
            exit("Invalid CSRF token.");
        }
        if (time() > $_SESSION['csrf_token_expiry']) {
            http_response_code(403);
            exit("CSRF token has expired.");
        }
        unset($_SESSION['csrf_token'], $_SESSION['csrf_token_expiry']);
    }

    private static function isAuthRequired($authRequired) {
        return $authRequired;
    }

    private static function isAuthenticated() {
        return isset($_SESSION['user']);
    }

    public static function sanitize($data) {
        return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    }

    public static function validateInput($data, $type = 'string') {
        switch ($type) {
            case 'int':
                return filter_var($data, FILTER_VALIDATE_INT);
            case 'email':
                return filter_var($data, FILTER_VALIDATE_EMAIL);
            case 'url':
                return filter_var($data, FILTER_VALIDATE_URL);
            default:
                return self::sanitize($data);
        }
    }
}
