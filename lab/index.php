<?php
/**
 * 本地 SSRF 演示靶点（Local SSRF Lab）
 * =================================
 * 为什么需要这个文件：
 *   官方 DVWA（v1.9 / 2.0 ~ 2.5）并不包含 SSRF 模块（已核对源码树），
 *   为了让"SSRF 载荷自动验证"这条实验线可以落地，这里补一个最小演示页。
 *
 * 部署位置（与 DVWA 平级，不放进 dvwa 目录）：
 *   D:\tool\xampp\htdocs\ssrf-lab\index.php
 *
 * 访问地址：
 *   http://127.0.0.1/ssrf-lab/
 *
 * 安全约束（重要）：
 *   1. 只接受来自回环地址的访问，公网/局域网客户端一律 403；
 *   2. 仅用于本机教学演示，禁止部署到任何对外提供服务的机器。
 *
 * 三档防护语义（读取 DVWA 写入的 security Cookie，与 DVWA 安全等级联动）：
 *   low      —— 直接 file_get_contents，任何协议与目标都放行；
 *   medium   —— 黑名单：拦截 file/gopher/dict/ftp 协议与 localhost、127.0.0.1 字面量，
 *               但 127.1、2130706433 等等价写法可以绕过；
 *   high     —— 白名单：只允许精确匹配一个固定页面，其余全部拒绝。
 */

declare(strict_types=1);

const LOCAL_CLIENTS = ['127.0.0.1', '::1'];
const HIGH_ALLOW_URL = 'http://127.0.0.1/dvwa/robots.txt';

$remote = $_SERVER['REMOTE_ADDR'] ?? '';
if (!in_array($remote, LOCAL_CLIENTS, true)) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'This lab endpoint only accepts connections from localhost.';
    exit;
}

$level = $_COOKIE['lab_level'] ?? ($_COOKIE['security'] ?? 'low');
$url   = isset($_GET['url']) ? (string) $_GET['url'] : '';
$body  = '';

if ($url !== '') {
    switch ($level) {
        case 'low':
            $body = (string) @file_get_contents($url);
            break;

        case 'medium':
            $blockedScheme = preg_match('/^(file|gopher|dict|ftp):/i', $url) === 1;
            $blockedHost   = preg_match('/https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?(\/|$)/i', $url) === 1;
            if ($blockedScheme || $blockedHost) {
                $body = 'Hack attempt detected.';
            } else {
                $body = (string) @file_get_contents($url);
            }
            break;

        default: // high / impossible
            $body = ($url === HIGH_ALLOW_URL)
                ? (string) @file_get_contents($url)
                : 'Hack attempt detected.';
            break;
    }
}

function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <title>Local SSRF Lab</title>
    <style>
        body { font-family: Consolas, "Microsoft YaHei", monospace; background: #1e1f22; color: #d6d6d6; padding: 40px; }
        h1 { font-size: 20px; color: #7ec699; }
        form { margin: 24px 0; }
        input[type=text] { width: 520px; padding: 8px; background: #2b2d31; color: #d6d6d6; border: 1px solid #444; }
        input[type=submit] { padding: 8px 18px; }
        .meta { color: #888; font-size: 13px; }
        pre { white-space: pre-wrap; word-break: break-all; background: #26282c; padding: 16px; border-left: 3px solid #7ec699; }
    </style>
</head>
<body>
<h1>Local SSRF Lab</h1>
<p class="meta">当前防护等级：<?= e((string) $level) ?> ｜ 本页面仅接受 localhost 访问</p>

<form method="get" action="">
    <input type="text" name="url" value="" placeholder="http://127.0.0.1/dvwa/login.php">
    <input type="submit" value="Fetch">
</form>

<?php if ($url !== ''): ?>
    <p class="meta">服务端抓取结果：</p>
    <pre><?= e($body !== '' ? $body : '(empty response)') ?></pre>
<?php endif; ?>
</body>
</html>
