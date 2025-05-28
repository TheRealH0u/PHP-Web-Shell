<?php
/* 
?   PROTECTED LOGIN START 
*/
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
/* 
!   PROTECTED LOGIN STOP
*/

/* 
?   MAIN HTML START
*/
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Overkill</title>
</head>
<body>
    
</body>
</html>
<?php
/* 
!   MAIN HTML STOP
*/
?>