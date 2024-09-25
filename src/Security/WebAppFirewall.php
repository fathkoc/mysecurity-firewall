<?php

namespace Security;

class WebAppFirewall
{
    private $blockedIps = [];
    private $maxRequests = 100;
    private $requestCount = [];
    private $enableDebug = false;

    public function __construct($debug = false)
    {
        $this->enableDebug = $debug;

        if ($this->enableDebug) {
            error_reporting(E_ALL);
        } else {
            error_reporting(0);
        }
    }

    public function initializeProtection()
    {
        $this->recordRequest();
        $this->sanitizeInputData();
        $this->detectSqlInjection();
        $this->monitorDdos();
    }

    public function sanitizeInputData()
    {
        $_POST = array_map('htmlspecialchars', $_POST);
        $_GET = array_map('htmlspecialchars', $_GET);
    }

    public function detectSqlInjection()
    {
        $_POST = array_map('addslashes', $_POST);
        $_GET = array_map('addslashes', $_GET);
    }

    public function isBlockedIp($ip)
    {
        return in_array($ip, $this->blockedIps);
    }

    public function monitorDdos()
    {
        $ip = $this->retrieveClientIp();
        if ($this->isBlockedIp($ip)) {
            return;
        }

        if (!isset($this->requestCount[$ip])) {
            $this->requestCount[$ip] = 0;
        }

        $this->requestCount[$ip]++;

        if ($this->requestCount[$ip] > $this->maxRequests) {
            $this->blockedIps[] = $ip;
        }
    }

    public function createCsrfToken()
    {
        $token = bin2hex(random_bytes(16));
        $_SESSION['csrf_token'] = $token;
        return $token;
    }

    public function checkCsrfToken($token)
    {
        if (!isset($_SESSION['csrf_token']) || $_SESSION['csrf_token'] !== $token) {
            header('Location: /error.php');
            exit;
        }

        unset($_SESSION['csrf_token']);
    }

    public function recordRequest()
    {
        $logFilePath = 'webappfirewall.log';
        $logFormat = "[%s] %s %s %s\n";

        $ip = $this->retrieveClientIp();
        $url = $_SERVER['REQUEST_URI'];
        $method = $_SERVER['REQUEST_METHOD'];
        $date = date('Y-m-d H:i:s', time());

        $logEntry = sprintf($logFormat, $date, $ip, $method, $url);

        file_put_contents($logFilePath, $logEntry, FILE_APPEND);
    }

    protected function retrieveClientIp()
    {
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            return $_SERVER['HTTP_X_FORWARDED_FOR'];
        }

        return $_SERVER['REMOTE_ADDR'];
    }
}
