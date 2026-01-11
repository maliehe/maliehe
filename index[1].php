<?php
session_start();

// Database Configuration
$host = 'localhost';
$dbname = 'bigfive_shoes';
$username = 'root';
$password = '';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}


// Default admin if not exists or password mismatch
$stmt = $pdo->prepare("SELECT id, password FROM users WHERE LOWER(username) = LOWER(?)");
$stmt->execute(['admin@bigfive.com']);
$row = $stmt->fetch();
$adminPass = password_hash('password123', PASSWORD_DEFAULT);
if (!$row) {
    $stmt = $pdo->prepare("INSERT INTO users (full_name, username, phone, password, role) VALUES (?, ?, ?, ?, ?)");
    $stmt->execute(['Admin User', 'admin@bigfive.com', '0712568422', $adminPass, 'admin']);
} elseif (!password_verify('password123', $row['password'])) {
    $stmt = $pdo->prepare("UPDATE users SET password = ? WHERE LOWER(username) = LOWER(?)");
    $stmt->execute([$adminPass, 'admin@bigfive.com']);
}



// Handle POST actions
$action = $_POST['action'] ?? $_GET['action'] ?? '';
$message = '';
$error = '';

// Handle messages from session (for redirects)
if (isset($_SESSION['temp_message'])) {
    $message = $_SESSION['temp_message'];
    unset($_SESSION['temp_message']);
}
if (isset($_SESSION['temp_error'])) {
    $error = $_SESSION['temp_error'];
    unset($_SESSION['temp_error']);
}

function sanitize($data) {
    return htmlspecialchars(strip_tags(trim($data)));
}

function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}

function validatePhone($phone) {
    return preg_match('/^\+?\d{10,15}$/', $phone);
}

function validatePassword($password) {
    return strlen($password) >= 8 && preg_match('/[A-Z]/', $password) && preg_match('/[0-9]/', $password);
}

function validateName($name) {
    return preg_match('/^[A-Za-z\s]{2,50}$/', $name);
}

function validateAddress($address) {
    return strlen($address) >= 10;
}

function generateOrderId() {
    global $pdo;
    $today = date('Ymd');
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM bookings WHERE order_id LIKE ?");
    $stmt->execute(["BF{$today}-%"]);
    $count = $stmt->fetchColumn() + 1;
    return "BF{$today}-" . str_pad($count, 3, '0', STR_PAD_LEFT);
}

function isBusinessDay($dateStr) {
    $d = new DateTime($dateStr);
    return $d->format('N') < 6; // 1-5 Mon-Fri
}

function addBusinessDays($startDateStr, $daysToAdd) {
    $current = new DateTime($startDateStr);
    $count = 0;
    while ($count < $daysToAdd) {
        $current->add(new DateInterval('P1D'));
        if (isBusinessDay($current->format('Y-m-d'))) {
            $count++;
        }
    }
    return $current->format('Y-m-d');
}

function findNextAvailableDate($startDateStr) {
    global $pdo;
    $current = new DateTime($startDateStr);
    while (true) {
        $current->add(new DateInterval('P1D'));
        $dateStr = $current->format('Y-m-d');
        if (isBusinessDay($dateStr)) {
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM bookings WHERE preferred_date = ? AND status != 'cancelled'");
            $stmt->execute([$dateStr]);
            if ($stmt->fetchColumn() < 5) {
                return $dateStr;
            }
        }
    }
}

function calculateEstimatedReady($preferredDateStr) {
    global $pdo;
    $stmt = $pdo->prepare("SELECT preferred_date, date_booked FROM bookings WHERE status = 'pending' ORDER BY preferred_date, date_booked");
    $stmt->execute();
    $pendingBookings = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $newDropOff = new DateTime($preferredDateStr);
    $newBookTime = new DateTime();
    $queueWithNew = array_map(function($b) use ($newDropOff, $newBookTime) {
        return [
            'dropOffDate' => new DateTime($b['preferred_date']),
            'bookTime' => new DateTime($b['date_booked'])
        ];
    }, $pendingBookings);
    $queueWithNew[] = ['dropOffDate' => $newDropOff, 'bookTime' => $newBookTime];
    usort($queueWithNew, function($a, $b) {
        if ($a['dropOffDate'] == $b['dropOffDate']) {
            return $a['bookTime'] <=> $b['bookTime'];
        }
        return $a['dropOffDate'] <=> $b['dropOffDate'];
    });
    $position = count($queueWithNew); // Simplified position as last in queue

    $capacityPerDay = 5;
    $baseCleaningDays = 2;
    $processingDays = ceil($position / $capacityPerDay);
    $startProcessingDate = addBusinessDays($preferredDateStr, 1);
    return addBusinessDays($startProcessingDate, $processingDays + $baseCleaningDays - 1);
}

function analyzeSentiment($text) {
    $positive = ['amazing' => 0.8, 'great' => 0.7, 'excellent' => 0.9, 'love' => 0.8, 'recommend' => 0.7, 'new' => 0.6, 'clean' => 0.7, 'fast' => 0.6, 'reliable' => 0.8];
    $negative = ['dirty' => -0.7, 'bad' => -0.8, 'poor' => -0.9, 'disappointed' => -0.8, 'slow' => -0.6, 'overpriced' => -0.7];
    $words = explode(' ', strtolower($text));
    $score = 0;
    foreach ($words as $word) {
        if (isset($positive[$word])) $score += $positive[$word];
        if (isset($negative[$word])) $score += $negative[$word];
    }
    return count($words) > 0 ? $score / count($words) : 0;
}

if ($action === 'register') {
    $fullName = sanitize($_POST['fullName']);
    $inputUsername = sanitize($_POST['username']);
    $phone = sanitize($_POST['phone']);
    $password = trim($_POST['password']);
    $confirmPassword = trim($_POST['confirmPassword']);
    $captcha = (int)$_POST['captcha'];
    $expectedCaptcha = (int)$_POST['expectedCaptcha'];

    $lowerUsername = strtolower($inputUsername);

    if ($captcha !== $expectedCaptcha) {
        $error = 'Incorrect CAPTCHA answer';
    } elseif (!validateName($fullName)) {
        $error = 'Invalid name';
    } elseif (!validateEmail($inputUsername)) {
        $error = 'Invalid email';
    } elseif ($phone && !validatePhone($phone)) {
        $error = 'Invalid phone';
    } elseif (!validatePassword($password)) {
        $error = 'Invalid password';
    } elseif ($password !== $confirmPassword) {
        $error = 'Passwords do not match';
    } else {
        $stmt = $pdo->prepare("SELECT id FROM users WHERE LOWER(username) = ? OR phone = ?");
        $stmt->execute([$lowerUsername, $phone]);
        if ($stmt->fetch()) {
            $error = 'Email or phone already registered';
        } else {
            $hashed = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $pdo->prepare("INSERT INTO users (full_name, username, phone, password, role) VALUES (?, ?, ?, ?, ?)");
            if ($stmt->execute([$fullName, $lowerUsername, $phone, $hashed, 'customer'])) {
                $stmt = $pdo->prepare("INSERT INTO loyalty_points (username, points) VALUES (?, 0)");
                $stmt->execute([$lowerUsername]);
                $_SESSION['temp_message'] = 'Registration successful! Please sign in.';
                $_SESSION['register_email'] = $inputUsername;
                header('Location: ' . $_SERVER['PHP_SELF'] . '?section=login');
                exit;
            } else {
                $error = 'Registration failed';
            }
        }
    }
} elseif ($action === 'login') {
    $role = $_POST['role'];
    $inputUsername = sanitize($_POST['username']);
    $password = trim($_POST['password']);
    $captcha = (int)$_POST['captcha'];
    $expectedCaptcha = (int)$_POST['expectedCaptcha'];

    $lowerUsername = strtolower($inputUsername);

    if ($captcha !== $expectedCaptcha) {
        $error = 'Incorrect CAPTCHA answer';
    } elseif (!validateEmail($inputUsername)) {
        $error = 'Invalid email';
    } else {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE LOWER(username) = ?");
        $stmt->execute([$lowerUsername]);
        $user = $stmt->fetch();
        if (!$user) {
            $error = 'No user found with that email';
        } elseif (!password_verify($password, $user['password'])) {
            $error = 'Incorrect password';
        } elseif ($role === 'admin' && $user['role'] !== 'admin') {
            $error = 'Access denied for admin role';
        } else {
            $_SESSION['user'] = $user;
            $_SESSION['user']['username'] = strtolower($user['username']);
            $_SESSION['temp_message'] = 'Login successful!';
            $redirectSection = ($user['role'] === 'admin') ? 'admin' : 'customer';
            header('Location: ' . $_SERVER['PHP_SELF'] . '?section=' . $redirectSection);
            exit;
        }
    }
} elseif ($action === 'reset_password') {
    $inputUsername = sanitize($_POST['username']);
    $lowerUsername = strtolower($inputUsername);
    if (!validateEmail($inputUsername)) {
        $error = 'Invalid email';
    } else {
        $stmt = $pdo->prepare("SELECT id FROM users WHERE LOWER(username) = ?");
        $stmt->execute([$lowerUsername]);
        if (!$stmt->fetch()) {
            $error = 'No user found with that email';
        } else {
            $newPass = 'password123';
            $hashed = password_hash($newPass, PASSWORD_DEFAULT);
            $stmt = $pdo->prepare("UPDATE users SET password = ? WHERE LOWER(username) = ?");
            if ($stmt->execute([$hashed, $lowerUsername])) {
                $_SESSION['temp_message'] = "Password reset successfully! Your new password is 'password123'. Please login with this new password and consider changing it in your profile if possible.";
                header('Location: ' . $_SERVER['PHP_SELF'] . '?section=login');
                exit;
            } else {
                $error = 'Password reset failed';
            }
        }
    }
} elseif ($action === 'update_profile' && isset($_SESSION['user'])) {
    $fullName = sanitize($_POST['fullName']);
    $phone = sanitize($_POST['phone']);
    $lowerUsername = $_SESSION['user']['username']; // Already lowered

    if (!validateName($fullName)) {
        $error = 'Invalid name';
    } elseif (!validatePhone($phone)) {
        $error = 'Invalid phone';
    } else {
        $stmt = $pdo->prepare("SELECT id FROM users WHERE phone = ? AND LOWER(username) != ?");
        $stmt->execute([$phone, $lowerUsername]);
        if ($stmt->fetch()) {
            $error = 'Phone already registered';
        } else {
            $stmt = $pdo->prepare("UPDATE users SET full_name = ?, phone = ? WHERE LOWER(username) = ?");
            if ($stmt->execute([$fullName, $phone, $lowerUsername])) {
                $_SESSION['user']['full_name'] = $fullName;
                $_SESSION['user']['phone'] = $phone;
                $_SESSION['temp_message'] = 'Profile updated!';
                header('Location: ' . $_SERVER['PHP_SELF'] . '?section=customer');
                exit;
            } else {
                $error = 'Update failed';
            }
        }
    }
} elseif ($action === 'submit_feedback' && isset($_SESSION['user'])) {
    $text = sanitize($_POST['text']);
    $lowerUsername = $_SESSION['user']['username']; // Already lowered
    if ($text) {
        $sentiment = analyzeSentiment($text);
        $stmt = $pdo->prepare("INSERT INTO feedbacks (user_username, text, sentiment) VALUES (?, ?, ?)");
        if ($stmt->execute([$lowerUsername, $text, $sentiment])) {
            $_SESSION['temp_message'] = "Feedback submitted! Sentiment: " . round($sentiment, 2);
            header('Location: ' . $_SERVER['PHP_SELF'] . '?section=customer');
            exit;
        } else {
            $error = 'Feedback submission failed';
        }
    }
} elseif ($action === 'book_service' && isset($_SESSION['user'])) {
    $fullName = sanitize($_POST['fullName']);
    $phoneNumber = sanitize($_POST['phoneNumber']);
    $serviceType = sanitize($_POST['serviceType']);
    $deliveryOption = $_POST['deliveryOption'];
    $address = $deliveryOption === 'home' ? sanitize($_POST['address']) : '';
    $preferredDate = $_POST['preferredDate'];
    $redeemPoints = (int)$_POST['redeemPoints'];
    $lowerUsername = $_SESSION['user']['username']; // Already lowered

    $prices = ['Basic Cleaning' => 75, 'Premium Cleaning' => 100, 'Restoration' => 150];
    $servicePrice = $prices[$serviceType] ?? 0;
    $extra = $deliveryOption === 'home' ? 15 : 0;
    $totalPrice = $servicePrice + $extra;

    // Get loyalty points
    $stmt = $pdo->prepare("SELECT points FROM loyalty_points WHERE username = ?");
    $stmt->execute([$lowerUsername]);
    $pointsRow = $stmt->fetch();
    $availablePoints = $pointsRow ? $pointsRow['points'] : 0;

    if ($redeemPoints > $availablePoints) {
        $error = 'Insufficient points';
    } elseif (!validateName($fullName) || !validatePhone($phoneNumber) || !$preferredDate) {
        $error = 'Invalid input';
    } elseif ($deliveryOption === 'home' && (!validateAddress($address))) {
        $error = 'Invalid address';
    } else {
        $d = new DateTime($preferredDate);
        if ($d->format('N') >= 6) {
            $error = 'No weekends';
        } else {
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM bookings WHERE preferred_date = ? AND status != 'cancelled'");
            $stmt->execute([$preferredDate]);
            $count = $stmt->fetchColumn();
            if ($count >= 5) {
                $preferredDate = findNextAvailableDate($preferredDate);
            }
            $discount = floor($redeemPoints / 2);
            $totalPrice -= $discount;

            $orderId = generateOrderId();
            $estimatedReady = calculateEstimatedReady($preferredDate);

            $stmt = $pdo->prepare("INSERT INTO bookings (order_id, full_name, phone_number, service_type, price, delivery_option, address, preferred_date, user_username, redeemed_points, discount, estimated_ready, payment_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'paid')");
            if ($stmt->execute([$orderId, $fullName, $phoneNumber, $serviceType, $totalPrice, $deliveryOption, $address, $preferredDate, $lowerUsername, $redeemPoints, $discount, $estimatedReady])) {
                $newPoints = $availablePoints - $redeemPoints;
                $stmt = $pdo->prepare("INSERT INTO loyalty_points (username, points) VALUES (?, ?) ON DUPLICATE KEY UPDATE points = ?, updated_at = CURRENT_TIMESTAMP");
                $stmt->execute([$lowerUsername, $newPoints, $newPoints]);

                // Earn points
                $pointsEarned = floor($totalPrice / 10);
                $stmt = $pdo->prepare("UPDATE loyalty_points SET points = points + ? WHERE username = ?");
                $stmt->execute([$pointsEarned, $lowerUsername]);
                $_SESSION['temp_message'] = "Booking successful! Order ID: $orderId. Est. Ready: $estimatedReady";
                header('Location: ' . $_SERVER['PHP_SELF'] . '?section=customer');
                exit;
            } else {
                $error = 'Booking failed';
            }
        }
    }
} elseif ($action === 'update_status') {
    if (isset($_SESSION['user']) && $_SESSION['user']['role'] === 'admin') {
        $bookingId = $_POST['bookingId'];
        $newStatus = $_POST['newStatus'];
        $actualReady = $newStatus === 'ready' ? date('Y-m-d') : null;
        $stmt = $pdo->prepare("UPDATE bookings SET status = ?, actual_ready = ? WHERE id = ?");
        $stmt->execute([$newStatus, $actualReady, $bookingId]);
        $_SESSION['temp_message'] = 'Status updated';
        header('Location: ' . $_SERVER['PHP_SELF'] . '?section=admin');
        exit;
    }
} elseif ($action === 'delete_booking') {
    if (isset($_SESSION['user']) && $_SESSION['user']['role'] === 'admin') {
        $bookingId = $_POST['bookingId'];
        $stmt = $pdo->prepare("DELETE FROM bookings WHERE id = ?");
        $stmt->execute([$bookingId]);
        $_SESSION['temp_message'] = 'Booking deleted';
        header('Location: ' . $_SERVER['PHP_SELF'] . '?section=admin');
        exit;
    }
} elseif ($action === 'choose_return') {
    if (isset($_SESSION['user'])) {
        $bookingId = $_POST['bookingId'];
        $returnOption = $_POST['returnOption'];
        $lowerUsername = $_SESSION['user']['username']; // Already lowered
        $stmt = $pdo->prepare("UPDATE bookings SET return_option = ? WHERE id = ? AND user_username = ? AND status = 'ready'");
        $stmt->execute([$returnOption, $bookingId, $lowerUsername]);
        if ($returnOption === 'delivery' && $stmt->rowCount() > 0) {
            // Add fee if not already (assuming store delivery was chosen initially)
            $stmt = $pdo->prepare("UPDATE bookings SET price = price + 15 WHERE id = ? AND delivery_option = 'store'");
            $stmt->execute([$bookingId]);
            // Update points for extra fee
            $stmt = $pdo->prepare("UPDATE loyalty_points SET points = points + 1 WHERE username = ?"); // 15/10=1
            $stmt->execute([$lowerUsername]);
        }
        $_SESSION['temp_message'] = 'Return option updated';
        header('Location: ' . $_SERVER['PHP_SELF'] . '?section=customer');
        exit;
    }
} elseif ($action === 'logout') {
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF'] . '?section=login');
    exit;
}

// Fetch data for display
$currentUser = $_SESSION['user'] ?? null;
$isLoggedIn = $currentUser !== null;
$isAdmin = $isLoggedIn && $currentUser['role'] === 'admin';

// Fetch bookings, feedbacks, etc.
$stmt = $pdo->query("SELECT * FROM bookings ORDER BY date_booked DESC");
$paidBookings = $stmt->fetchAll();

$stmt = $pdo->query("SELECT * FROM bookings ORDER BY date_booked DESC");
$allBookings = $stmt->fetchAll();

$stmt = $pdo->query("SELECT * FROM feedbacks ORDER BY date_submitted DESC");
$allFeedbacks = $stmt->fetchAll();

if ($isLoggedIn) {
    $lowerUsername = $currentUser['username']; // Already lowered
    $stmt = $pdo->prepare("SELECT * FROM bookings WHERE user_username = ? ORDER BY date_booked DESC");
    $stmt->execute([$lowerUsername]);
    $userBookings = $stmt->fetchAll();

    $stmt = $pdo->prepare("SELECT points FROM loyalty_points WHERE username = ?");
    $stmt->execute([$lowerUsername]);
    $loyaltyRow = $stmt->fetch();
    $loyaltyPoints = $loyaltyRow ? $loyaltyRow['points'] : 0;

    // Analytics
    $totalBookings = count($paidBookings);
    $totalRevenue = array_sum(array_column($paidBookings, 'price'));
    $avgSentiment = $allFeedbacks ? round(array_sum(array_column($allFeedbacks, 'sentiment')) / count($allFeedbacks), 2) : 0;

    // Service counts
    $serviceCounts = ['Basic Cleaning' => 0, 'Premium Cleaning' => 0, 'Restoration' => 0];
    foreach ($paidBookings as $b) {
        if (isset($serviceCounts[$b['service_type']])) $serviceCounts[$b['service_type']]++;
    }

    // Revenue by date
    $revenueByDate = [];
    foreach ($paidBookings as $b) {
        $revenueByDate[$b['preferred_date']] = ($revenueByDate[$b['preferred_date']] ?? 0) + $b['price'];
    }
    ksort($revenueByDate);
}

// CAPTCHA generation (simple, per request)
$regNum1 = rand(1, 10);
$regNum2 = rand(1, 10);
$regCaptchaSum = $regNum1 + $regNum2;

$loginNum1 = rand(1, 10);
$loginNum2 = rand(1, 10);
$loginCaptchaSum = $loginNum1 + $loginNum2;

// Determine section to show
$section = 'landing';
if (isset($_GET['section'])) {
    $section = $_GET['section'];
} elseif ($isLoggedIn) {
    $section = $isAdmin ? 'admin' : 'customer';
} elseif (isset($_SESSION['register_email'])) {
    $section = 'login';
    unset($_SESSION['register_email']);
}

// For login form persistence
$selectedRole = $_POST['role'] ?? 'customer';
$loginUsername = sanitize($_POST['username'] ?? '');

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Big Five Shoes Cleaning Services</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://kit.fontawesome.com/a076d05399.js" crossorigin="anonymous"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
         :root {
            --primary: #1e3a8a;
            --secondary: #6b21a8;
            --accent: #22d3ee;
            --background: #f0f4ff;
            --card-bg: rgba(255, 255, 255, 0.15);
            --text-primary: #111827;
            --text-secondary: #6b7280;
        }
        
        body {
            background-image: url('https://th.bing.com/th/id/R.771273c6bdb3dba9f47046a0a36ba42f?rik=wi90FB7F6LmCUA&pid=ImgRaw&r=0');
            background-size: cover;
            background-position: center;
            background-attachment: fixed;
            font-family: 'Inter', 'system-ui', '-apple-system', sans-serif;
            min-height: 100vh;
            color: var(--text-primary);
            line-height: 1.6;
            font-size: 1.1rem;
        }
        
        .fade-in {
            animation: fadeIn 0.8s ease-out;
        }
        
        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .navbar {
            background: #111827;
            backdrop-filter: blur(12px);
            border-bottom: 1px solid rgba(255, 255, 255, 0.3);
            position: sticky;
            top: 0;
            z-index: 1000;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        }
        
        .hero-section {
            position: relative;
            background-image: url('https://images.unsplash.com/photo-1542291026-7eec264c27ff?ixlib=rb-4.0.3&auto=format&fit=crop&w=1400&h=700&q=85');
            background-size: cover;
            background-position: center;
            height: 600px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 1.5rem;
            overflow: hidden;
            margin-bottom: 2rem;
        }
        
        .hero-overlay {
            position: absolute;
            inset: 0;
            background: linear-gradient(to bottom, rgba(30, 58, 138, 0.4), rgba(107, 33, 168, 0.4));
        }
        
        .input-error {
            border-color: #ef4444;
            box-shadow: 0 0 0 3px rgba(239, 68, 68, 0.2);
        }
        
        .error-message {
            color: #ef4444;
            font-size: 0.9rem;
            margin-top: 0.25rem;
        }
        
        .service-section {
            position: relative;
            background-image: url('https://images.unsplash.com/photo-1605733513597-a8f834bd6461?ixlib=rb-4.0.3&auto=format&fit=crop&w=1400&q=85');
            background-size: cover;
            background-position: center;
            background-attachment: fixed;
            border-radius: 1.5rem;
            padding: 2rem;
            min-height: 400px;
            display: flex;
            align-items: center;
        }
        
        .why-choose-section {
            position: relative;
            background-image: url('https://images.unsplash.com/photo-1542291026-7eec264c27ff?ixlib=rb-4.0.3&auto=format&fit=crop&w=1400&q=85');
            background-size: cover;
            background-position: center;
            background-attachment: fixed;
            border-radius: 1.5rem;
            padding: 2rem;
            min-height: 400px;
            display: flex;
            align-items: center;
        }
        
        .testimonials-section {
            position: relative;
            background-image: url('https://images.unsplash.com/photo-1606107557195-0e29a4b5b4aa?ixlib=rb-4.0.3&auto=format&fit=crop&w=1400&q=85');
            background-size: cover;
            background-position: center;
            background-attachment: fixed;
            border-radius: 1.5rem;
            padding: 2rem;
            min-height: 400px;
            display: flex;
            align-items: center;
        }
        
        .contact-section {
            position: relative;
            background-image: url('https://images.unsplash.com/photo-1595950653106-6c9ebd18f8f8?ixlib=rb-4.0.3&auto=format&fit=crop&w=1400&q=85');
            background-size: cover;
            background-position: center;
            background-attachment: fixed;
            border-radius: 1.5rem;
            padding: 2rem;
            min-height: 400px;
            display: flex;
            align-items: center;
        }
        
        .section-overlay {
            position: absolute;
            inset: 0;
            background: linear-gradient(to bottom, rgba(255, 255, 255, 0.3), rgba(255, 255, 255, 0.3));
            border-radius: 1.5rem;
        }
        
        .service-card,
        .why-choose-card {
            background: var(--card-bg);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 1.5rem;
            box-shadow: 0 6px 25px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            padding: 2rem;
        }
        
        .service-card:hover,
        .why-choose-card:hover {
            transform: translateY(-8px);
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.15);
        }
        
        .carousel {
            position: relative;
            overflow: hidden;
            border-radius: 1.5rem;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
        }
        
        .carousel-inner {
            display: flex;
            transition: transform 0.6s ease-in-out;
        }
        
        .carousel-item {
            min-width: 100%;
            background: var(--card-bg);
            backdrop-filter: blur(10px);
            border-radius: 1.5rem;
            padding: 2rem;
        }
        
        .carousel-nav {
            position: absolute;
            top: 50%;
            transform: translateY(-50%);
            background: var(--secondary);
            color: white;
            padding: 1rem;
            border-radius: 50%;
            cursor: pointer;
            transition: background 0.3s ease, transform 0.3s ease;
        }
        
        .carousel-nav:hover {
            background: var(--accent);
            transform: translateY(-50%) scale(1.1);
        }
        
        .carousel-prev {
            left: 1.5rem;
        }
        
        .carousel-next {
            right: 1.5rem;
        }
        
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.7);
            align-items: center;
            justify-content: center;
            z-index: 2000;
        }
        
        .modal-content {
            background: white;
            padding: 2.5rem;
            border-radius: 1.5rem;
            max-width: 700px;
            width: 90%;
            box-shadow: 0 12px 50px rgba(0, 0, 0, 0.2);
        }
        
        .progress-bar {
            height: 8px;
            background: #e5e7eb;
            border-radius: 4px;
            overflow: hidden;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(to right, var(--primary), var(--accent));
            transition: width 0.4s ease;
        }
        
        button {
            transition: transform 0.2s ease, background 0.3s ease, box-shadow 0.3s ease;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
        }
        
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.15);
        }
        
        .gradient-button {
            background: linear-gradient(to right, var(--primary), var(--accent));
        }
        
        .gradient-button:hover {
            background: linear-gradient(to right, #1e40af, #06b6d4);
        }
        
        .icon-blue {
            color: var(--accent);
        }
        
        .icon-red {
            color: #ef4444;
        }
        
        .animate-icon {
            transition: transform 0.4s ease;
        }
        
        .animate-icon:hover {
            transform: rotate(360deg);
        }
        
        .animate-on-scroll {
            opacity: 0;
            transform: translateY(30px);
            transition: opacity 0.8s ease-out, transform 0.8s ease-out;
        }
        
        .animate-on-scroll.visible {
            opacity: 1;
            transform: translateY(0);
        }
        
        input,
        select {
            transition: border-color 0.3s ease, box-shadow 0.3s ease;
            font-size: 1rem;
        }
        
        input:focus,
        select:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 4px rgba(34, 211, 238, 0.3);
            outline: none;
        }
        
        .section-content {
            text-shadow: 1px 1px 2px rgba(0,0,0,0.5);
        }
        
        @media (max-width: 640px) {
            .hero-section {
                height: 400px;
            }
            .service-card,
            .why-choose-card {
                padding: 1.5rem;
            }
            .modal-content {
                padding: 1.5rem;
            }
            h1 {
                font-size: 2.5rem;
            }
            .service-section,
            .why-choose-section,
            .testimonials-section,
            .contact-section {
                background-attachment: scroll;
                min-height: 300px;
                padding: 1rem;
            }
        }
    </style>
</head>

<body class="flex flex-col min-h-screen">
    <!-- Navigation Bar -->
    <nav class="navbar p-6 text-white" role="navigation" aria-label="Main navigation">
        <div class="container mx-auto flex justify-between items-center">
            <div class="flex items-center space-x-3">
                <i class="fas fa-shoe-prints text-3xl icon-blue animate-icon"></i>
                <h1 class="text-2xl font-bold">Big Five Shoes cleaning service </h1>
            </div>
            <div class="flex space-x-6">
                <a href="?section=landing" class="hover:text-accent flex items-center text-lg" aria-label="Home"><i class="fas fa-home mr-2 icon-blue animate-icon"></i>Home</a>
                <?php if ($isLoggedIn): ?>
                    <a href="?section=<?= $isAdmin ? 'admin' : 'customer' ?>" class="hover:text-accent flex items-center text-lg" aria-label="Dashboard"><i class="fas fa-tachometer-alt mr-2 icon-blue animate-icon"></i>Dashboard</a>
                    <a href="?action=logout" class="hover:text-accent flex items-center text-lg" aria-label="Logout"><i class="fas fa-sign-out-alt mr-2 icon-red animate-icon"></i>Logout</a>
                <?php else: ?>
                    <a href="?section=services" class="hover:text-accent flex items-center text-lg" aria-label="Services"><i class="fas fa-cogs mr-2 icon-blue animate-icon"></i>Services</a>
                    <a href="?section=contact" class="hover:text-accent flex items-center text-lg" aria-label="Contact"><i class="fas fa-phone mr-2 icon-blue animate-icon"></i>Contact</a>
                    <a href="?section=login" class="hover:text-accent flex items-center text-lg" aria-label="Login"><i class="fas fa-sign-in-alt mr-2 icon-blue animate-icon"></i>Login</a>
                    <a href="?section=register" class="hover:text-accent flex items-center text-lg" aria-label="Register"><i class="fas fa-user-plus mr-2 icon-blue animate-icon"></i>Register</a>
                <?php endif; ?>
            </div>
        </div>
    </nav>

    <main id="main-container" class="container mx-auto p-6 max-w-6xl flex-grow" role="main">
        <?php if ($error): ?>
            <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <?php if ($message): ?>
            <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded mb-4"><?= htmlspecialchars($message) ?></div>
        <?php endif; ?>

        <!-- Landing Page -->
        <?php if ($section === 'landing'): ?>
            <section id="landing-page" class="fade-in">
                <header class="hero-section relative">
                    <div class="hero-overlay"></div>
                    <div class="text-center z-10">
                        <h1 class="text-5xl md:text-7xl font-extrabold mb-4 text-white tracking-tight">Big Five Shoes Cleaning Services</h1>
                        <p class="text-xl md:text-2xl mb-6 text-white font-medium">Premium, eco-friendly cleaning for your favorite footwear</p>
                        <button onclick="window.location.href='?section=register'" class="gradient-button text-white px-10 py-4 rounded-xl text-lg shadow-lg flex items-center mx-auto" aria-label="Get Started">
                            <i class="fas fa-user-plus mr-2 icon-blue animate-icon"></i> Get Started
                        </button>
                    </div>
                </header>

                <!-- Container for Prices and Types of Cleaning -->
                <div class="container mx-auto my-16 animate-on-scroll visible">
                    <section class="service-section relative" id="services" aria-label="Our Services">
                        <div class="section-overlay"></div>
                        <div class="relative z-10 section-content w-full">
                            <h2 class="text-4xl font-semibold text-gray-800 flex items-center justify-center mb-8"><i class="fas fa-cogs mr-2 icon-blue animate-icon"></i>Our Services</h2>
                            <div class="grid md:grid-cols-3 gap-8">
                                <article class="service-card p-8">
                                    <i class="fas fa-spray-can text-5xl icon-blue animate-icon mb-6"></i>
                                    <h3 class="text-2xl font-semibold text-gray-800">Basic Cleaning</h3>
                                    <p class="text-gray-600 mt-3">Quick refresh for everyday shoes</p>
                                    <p class="text-accent font-bold mt-4 text-xl">R75</p>
                                </article>
                                <article class="service-card p-8">
                                    <i class="fas fa-broom text-5xl icon-blue animate-icon mb-6"></i>
                                    <h3 class="text-2xl font-semibold text-gray-800">Premium Cleaning</h3>
                                    <p class="text-gray-600 mt-3">Deep clean with conditioning</p>
                                    <p class="text-accent font-bold mt-4 text-xl">R100</p>
                                </article>
                                <article class="service-card p-8">
                                    <i class="fas fa-tools text-5xl icon-blue animate-icon mb-6"></i>
                                    <h3 class="text-2xl font-semibold text-gray-800">Restoration</h3>
                                    <p class="text-gray-600 mt-3">Full repair and revitalization</p>
                                    <p class="text-accent font-bold mt-4 text-xl">R150</p>
                                </article>
                            </div>
                        </div>
                    </section>
                </div>

                <!-- Container for Testimonials -->
                <div class="container mx-auto my-16 animate-on-scroll visible">
                    <section class="testimonials-section relative" aria-label="Testimonials">
                        <div class="section-overlay"></div>
                        <div class="relative z-10 section-content w-full text-center">
                            <h2 class="text-4xl font-semibold text-gray-800 flex items-center justify-center mb-8"><i class="fas fa-quote-left mr-2 icon-blue animate-icon"></i>Testimonials</h2>
                            <div class="carousel mt-6 relative">
                                <div class="carousel-inner">
                                    <article class="carousel-item flex items-start">
                                        <i class="fas fa-user-circle text-4xl icon-blue animate-icon mr-4"></i>
                                        <div>
                                            <div class="flex">
                                                <i class="fas fa-star text-yellow-400"></i><i class="fas fa-star text-yellow-400"></i><i class="fas fa-star text-yellow-400"></i><i class="fas fa-star text-yellow-400"></i><i class="fas fa-star text-yellow-400"></i>
                                            </div>
                                            <p class="text-gray-600 mt-3 text-lg">"My sneakers look brand new! Amazing service!"</p>
                                            <p class="font-semibold mt-2 text-accent">- Sarah M.</p>
                                        </div>
                                    </article>
                                    <article class="carousel-item flex items-start">
                                        <i class="fas fa-user-circle text-4xl icon-blue animate-icon mr-4"></i>
                                        <div>
                                            <div class="flex">
                                                <i class="fas fa-star text-yellow-400"></i><i class="fas fa-star text-yellow-400"></i><i class="fas fa-star text-yellow-400"></i><i class="fas fa-star text-yellow-400"></i><i class="fas fa-star text-yellow-400"></i>
                                            </div>
                                            <p class="text-gray-600 mt-3 text-lg">"Fast, reliable, and eco-friendly. Highly recommend!"</p>
                                            <p class="font-semibold mt-2 text-accent">- John K.</p>
                                        </div>
                                    </article>
                                    <article class="carousel-item flex items-start">
                                        <i class="fas fa-user-circle text-4xl icon-blue animate-icon mr-4"></i>
                                        <div>
                                            <div class="flex">
                                                <i class="fas fa-star text-yellow-400"></i><i class="fas fa-star text-yellow-400"></i><i class="fas fa-star text-yellow-400"></i><i class="fas fa-star text-yellow-400"></i><i class="fas fa-star text-yellow-400"></i>
                                            </div>
                                            <p class="text-gray-600 mt-3 text-lg">"Best shoe cleaning service I've ever used!"</p>
                                            <p class="font-semibold mt-2 text-accent">- Emma L.</p>
                                        </div>
                                    </article>
                                </div>
                                <button class="carousel-nav carousel-prev" onclick="moveCarousel(-1)" aria-label="Previous Testimonial">&#10094;</button>
                                <button class="carousel-nav carousel-next" onclick="moveCarousel(1)" aria-label="Next Testimonial">&#10095;</button>
                            </div>
                        </div>
                    </section>
                </div>

                <!-- Container for Working Days and Hours -->
                <div class="container mx-auto my-16 animate-on-scroll visible">
                    <section class="contact-section relative" id="contact" aria-label="Contact Us">
                        <div class="section-overlay"></div>
                        <div class="relative z-10 section-content w-full text-center">
                            <h2 class="text-4xl font-semibold text-gray-800 flex items-center justify-center mb-8"><i class="fas fa-envelope mr-2 icon-red animate-icon"></i>Working Days & Hours</h2>
                            <p class="text-lg"><i class="fas fa-clock mr-2 icon-blue animate-icon"></i>Place: P-west Makhode</p>
                            <p class="text-lg"><i class="fas fa-clock mr-2 icon-blue animate-icon"></i>Operating Hours: Monday - Friday, 10 AM - 4 PM</p>
                            <p class="text-lg"><i class="fas fa-calendar-times mr-2 icon-red animate-icon"></i>Closed on Weekends and Public Holidays</p>
                            <p class="text-lg">For more information, call <a href="tel:0712568422" class="text-accent hover:underline" aria-label="Call us"><i class="fas fa-phone mr-1 icon-blue animate-icon"></i>071 256 8422</a> or email <a href="mailto:info@bigfiveshoes.co.za"
                                    class="text-accent hover:underline" aria-label="Email us"><i class="fas fa-envelope mr-1 icon-blue animate-icon"></i>mudaumurendiwa8@gmail.com</a></p>
                            <p class="text-sm mt-6"><a href="#" class="text-accent hover:underline" aria-label="Terms and Conditions"><i class="fas fa-file-contract mr-1 icon-blue animate-icon"></i>Terms & Conditions</a> |
                                <a href="#" class="text-accent hover:underline" aria-label="Privacy Policy"><i class="fas fa-shield-alt mr-1 icon-blue animate-icon"></i>Privacy Policy</a> |
                                <a href="#" class="text-accent hover:underline" aria-label="Customer Survey"><i class="fas fa-chart-bar mr-1 icon-blue animate-icon"></i>Customer Survey</a>
                            </p>
                        </div>
                    </section>
                </div>

                <!-- Why Choose Us Section (kept as is) -->
                <div class="container mx-auto my-16 animate-on-scroll visible">
                    <section class="why-choose-section relative" aria-label="Why Choose Us">
                        <div class="section-overlay"></div>
                        <div class="relative z-10 section-content w-full">
                            <h2 class="text-4xl font-semibold text-gray-800 flex items-center justify-center mb-8"><i class="fas fa-star mr-2 icon-red animate-icon"></i>Why Choose Us</h2>
                            <div class="grid md:grid-cols-2 gap-8">
                                <article class="why-choose-card p-8">
                                    <i class="fas fa-leaf text-4xl icon-red animate-icon mb-6"></i>
                                    <p class="text-gray-600 text-lg">Eco-friendly cleaning solutions</p>
                                </article>
                                <article class="why-choose-card p-8">
                                    <i class="fas fa-users text-4xl icon-red animate-icon mb-6"></i>
                                    <p class="text-gray-600 text-lg">Professional staff with 98% satisfaction rate</p>
                                </article>
                            </div>
                            <p class="text-gray-600 mt-8 max-w-3xl mx-auto text-lg">Trusted by thousands of happy customers. Serving over 5,000 annually with sustainable practices reducing water usage by 30%.</p>
                        </div>
                    </section>
                </div>
            </section>

        <!-- Services Page -->
        <?php elseif ($section === 'services'): ?>
            <section id="services-page" class="fade-in">
                <div class="container mx-auto my-16 animate-on-scroll visible">
                    <section class="service-section relative" id="services" aria-label="Our Services">
                        <div class="section-overlay"></div>
                        <div class="relative z-10 section-content w-full">
                            <h2 class="text-4xl font-semibold text-gray-800 flex items-center justify-center mb-8"><i class="fas fa-cogs mr-2 icon-blue animate-icon"></i>Our Services</h2>
                            <div class="grid md:grid-cols-3 gap-8">
                                <article class="service-card p-8">
                                    <i class="fas fa-spray-can text-5xl icon-blue animate-icon mb-6"></i>
                                    <h3 class="text-2xl font-semibold text-gray-800">Basic Cleaning</h3>
                                    <p class="text-gray-600 mt-3">Quick refresh for everyday shoes</p>
                                    <p class="text-accent font-bold mt-4 text-xl">R75</p>
                                </article>
                                <article class="service-card p-8">
                                    <i class="fas fa-broom text-5xl icon-blue animate-icon mb-6"></i>
                                    <h3 class="text-2xl font-semibold text-gray-800">Premium Cleaning</h3>
                                    <p class="text-gray-600 mt-3">Deep clean with conditioning</p>
                                    <p class="text-accent font-bold mt-4 text-xl">R100</p>
                                </article>
                                <article class="service-card p-8">
                                    <i class="fas fa-tools text-5xl icon-blue animate-icon mb-6"></i>
                                    <h3 class="text-2xl font-semibold text-gray-800">Restoration</h3>
                                    <p class="text-gray-600 mt-3">Full repair and revitalization</p>
                                    <p class="text-accent font-bold mt-4 text-xl">R150</p>
                                </article>
                            </div>
                        </div>
                    </section>
                </div>
                <div class="text-center">
                    <a href="?section=landing" class="gradient-button text-white px-8 py-3 rounded-xl text-lg shadow-lg flex items-center mx-auto" aria-label="Back to Home"><i class="fas fa-home mr-2 icon-blue animate-icon"></i>Back to Home</a>
                </div>
            </section>

        <!-- Contact Page -->
        <?php elseif ($section === 'contact'): ?>
            <section id="contact-page" class="fade-in">
                <div class="container mx-auto my-16 animate-on-scroll visible">
                    <section class="contact-section relative" id="contact" aria-label="Contact Us">
                        <div class="section-overlay"></div>
                        <div class="relative z-10 section-content w-full text-center">
                            <h2 class="text-4xl font-semibold text-gray-800 flex items-center justify-center mb-8"><i class="fas fa-envelope mr-2 icon-red animate-icon"></i>Working Days & Hours</h2>
                            <p class="text-lg"><i class="fas fa-clock mr-2 icon-blue animate-icon"></i>Operating Hours: Monday - Friday, 10 AM - 4 PM</p>
                            <p class="text-lg"><i class="fas fa-calendar-times mr-2 icon-red animate-icon"></i>Closed on Weekends and Public Holidays</p>
                            <p class="text-lg">For more information, call <a href="tel:0712568422" class="text-accent hover:underline" aria-label="Call us"><i class="fas fa-phone mr-1 icon-blue animate-icon"></i>071 256 8422</a> or email <a href="mailto:info@bigfiveshoes.co.za"
                                    class="text-accent hover:underline" aria-label="Email us"><i class="fas fa-envelope mr-1 icon-blue animate-icon"></i>info@bigfiveshoes.co.za</a></p>
                            <p class="text-sm mt-6"><a href="#" class="text-accent hover:underline" aria-label="Terms and Conditions"><i class="fas fa-file-contract mr-1 icon-blue animate-icon"></i>Terms & Conditions</a> |
                                <a href="#" class="text-accent hover:underline" aria-label="Privacy Policy"><i class="fas fa-shield-alt mr-1 icon-blue animate-icon"></i>Privacy Policy</a> |
                                <a href="#" class="text-accent hover:underline" aria-label="Customer Survey"><i class="fas fa-chart-bar mr-1 icon-blue animate-icon"></i>Customer Survey</a>
                            </p>
                        </div>
                    </section>
                </div>
                <div class="text-center">
                    <a href="?section=landing" class="gradient-button text-white px-8 py-3 rounded-xl text-lg shadow-lg flex items-center mx-auto" aria-label="Back to Home"><i class="fas fa-home mr-2 icon-blue animate-icon"></i>Back to Home</a>
                </div>
            </section>

        <!-- Register Form -->
        <?php elseif ($section === 'register'): ?>
            <section id="register-form" class="fade-in bg-white p-10 rounded-2xl shadow-2xl max-w-lg mx-auto" role="form" aria-label="Register Form">
                <h2 class="text-3xl font-bold text-gray-800 mb-8 text-center flex items-center justify-center"><i class="fas fa-user-plus mr-2 icon-blue animate-icon"></i>Register</h2>
                <div class="progress-bar mb-6">
                    <div class="progress-fill" style="width: 33%"></div>
                </div>
                <p class="text-green-600 hidden mb-6 text-center">Registration successful! Please sign in.</p>
                <form method="POST" action="">
                    <input type="hidden" name="action" value="register">
                    <input type="hidden" name="expectedCaptcha" value="<?= $regCaptchaSum ?>">
                    <div class="mb-6 relative">
                        <label class="block text-gray-700 font-medium flex items-center text-lg"><i class="fas fa-user mr-2 icon-blue animate-icon"></i>Full Name</label>
                        <input type="text" name="fullName" class="w-full px-5 py-3 border rounded-lg focus:outline-none pl-12 text-lg" required aria-required="true" aria-describedby="regFullNameError">
                        <p id="regFullNameError" class="error-message hidden"></p>
                    </div>
                    <div class="mb-6 relative">
                        <label class="block text-gray-700 font-medium flex items-center text-lg"><i class="fas fa-envelope mr-2 icon-blue animate-icon"></i>Email (Username)</label>
                        <input type="email" name="username" class="w-full px-5 py-3 border rounded-lg focus:outline-none pl-12 text-lg" required aria-required="true" aria-describedby="regUsernameError">
                        <p id="regUsernameError" class="error-message hidden"></p>
                    </div>
                    <div class="mb-6 relative">
                        <label class="block text-gray-700 font-medium flex items-center text-lg"><i class="fas fa-phone mr-2 icon-blue animate-icon"></i>Phone Number</label>
                        <input type="tel" name="phone" class="w-full px-5 py-3 border rounded-lg focus:outline-none pl-12 text-lg" required aria-required="true" aria-describedby="regPhoneError">
                        <p id="regPhoneError" class="error-message hidden"></p>
                    </div>
                    <div class="mb-6 relative">
                        <label class="block text-gray-700 font-medium flex items-center text-lg"><i class="fas fa-lock mr-2 icon-red animate-icon"></i>Password</label>
                        <input type="password" name="password" class="w-full px-5 py-3 border rounded-lg focus:outline-none pl-12 text-lg" required aria-required="true" aria-describedby="regPasswordError">
                        <p id="regPasswordError" class="error-message hidden"></p>
                    </div>
                    <div class="mb-6 relative">
                        <label class="block text-gray-700 font-medium flex items-center text-lg"><i class="fas fa-lock mr-2 icon-red animate-icon"></i>Confirm Password</label>
                        <input type="password" name="confirmPassword" class="w-full px-5 py-3 border rounded-lg focus:outline-none pl-12 text-lg" required aria-required="true" aria-describedby="regConfirmPasswordError">
                        <p id="regConfirmPasswordError" class="error-message hidden"></p>
                    </div>
                    <div class="mb-6 relative">
                        <label class="block text-gray-700 font-medium flex items-center text-lg"><i class="fas fa-question-circle mr-2 icon-blue animate-icon"></i>CAPTCHA: What is <?= $regNum1 ?> + <?= $regNum2 ?>?</label>
                        <input type="number" name="captcha" class="w-full px-5 py-3 border rounded-lg focus:outline-none pl-12 text-lg" required aria-required="true" aria-describedby="captchaError">
                        <p id="captchaError" class="error-message hidden"></p>
                    </div>
                    <button type="submit" class="w-full gradient-button text-white py-4 rounded-xl text-lg shadow-lg flex items-center justify-center" aria-label="Register"><i class="fas fa-user-plus mr-2 icon-blue animate-icon"></i>Register</button>
                    <a href="?section=login" class="block w-full mt-4 text-accent hover:underline text-lg flex items-center justify-center" aria-label="Already have an account? Login"><i class="fas fa-sign-in-alt mr-2 icon-blue animate-icon"></i>Already have an account? Login</a>
                    <a href="?section=landing" class="block w-full mt-2 text-accent hover:underline text-lg flex items-center justify-center" aria-label="Back to Home"><i class="fas fa-home mr-2 icon-blue animate-icon"></i>Back to Home</a>
                </form>
            </section>

        <!-- Login Form -->
        <?php elseif ($section === 'login'): ?>
            <section id="login-form" class="fade-in bg-white p-10 rounded-2xl shadow-2xl max-w-lg mx-auto" role="form" aria-label="Login Form">
                <h2 class="text-3xl font-bold text-gray-800 mb-8 text-center flex items-center justify-center"><i class="fas fa-sign-in-alt mr-2 icon-blue animate-icon"></i>Sign In</h2>
                <div class="progress-bar mb-6">
                    <div class="progress-fill" style="width: 66%"></div>
                </div>
                <form method="POST" action="">
                    <input type="hidden" name="action" value="login">
                    <input type="hidden" name="expectedCaptcha" value="<?= $loginCaptchaSum ?>">
                    <div class="mb-6">
                        <label class="block text-gray-700 font-medium flex items-center text-lg"><i class="fas fa-user-tag mr-2 icon-blue animate-icon"></i>Role</label>
                        <div class="flex space-x-6">
                            <label class="flex items-center"><input type="radio" name="role" value="customer" <?= $selectedRole === 'customer' ? 'checked' : '' ?> class="mr-2 h-5 w-5" aria-label="Customer"> <i class="fas fa-user mr-1 icon-blue animate-icon"></i>Customer</label>
                            <label class="flex items-center"><input type="radio" name="role" value="admin" <?= $selectedRole === 'admin' ? 'checked' : '' ?> class="mr-2 h-5 w-5" aria-label="Admin"> <i class="fas fa-user-shield mr-1 icon-blue animate-icon"></i>Admin</label>
                        </div>
                    </div>
                    <div class="mb-6 relative">
                        <label class="block text-gray-700 font-medium flex items-center text-lg"><i class="fas fa-envelope mr-2 icon-blue animate-icon"></i>Email (Username)</label>
                        <input type="email" name="username" class="w-full px-5 py-3 border rounded-lg focus:outline-none pl-12 text-lg" required aria-required="true" aria-describedby="loginUsernameError" value="<?= htmlspecialchars($loginUsername) ?>">
                        <p id="loginUsernameError" class="error-message hidden"></p>
                    </div>
                    <div class="mb-6 relative">
                        <label class="block text-gray-700 font-medium flex items-center text-lg"><i class="fas fa-lock mr-2 icon-red animate-icon"></i>Password</label>
                        <input type="password" name="password" class="w-full px-5 py-3 border rounded-lg focus:outline-none pl-12 text-lg" required aria-required="true" aria-describedby="loginPasswordError">
                        <p id="loginPasswordError" class="error-message hidden"></p>
                    </div>
                    <div class="mb-6 relative">
                        <label class="block text-gray-700 font-medium flex items-center text-lg"><i class="fas fa-question-circle mr-2 icon-blue animate-icon"></i>CAPTCHA: What is <?= $loginNum1 ?> + <?= $loginNum2 ?>?</label>
                        <input type="number" name="captcha" class="w-full px-5 py-3 border rounded-lg focus:outline-none pl-12 text-lg" required aria-required="true" aria-describedby="loginCaptchaError">
                        <p id="loginCaptchaError" class="error-message hidden"></p>
                    </div>
                    <button type="submit" class="w-full gradient-button text-white py-4 rounded-xl text-lg shadow-lg flex items-center justify-center" aria-label="Sign In"><i class="fas fa-sign-in-alt mr-2 icon-blue animate-icon"></i>Sign In</button>
                </form>
                <p class="text-center mt-4 text-gray-600">Or reset your password:</p>
                <form method="POST" action="">
                    <input type="hidden" name="action" value="reset_password">
                    <div class="mb-6 relative">
                        <label class="block text-gray-700 font-medium flex items-center text-lg"><i class="fas fa-envelope mr-2 icon-blue animate-icon"></i>Email (Username)</label>
                        <input type="email" name="username" class="w-full px-5 py-3 border rounded-lg focus:outline-none pl-12 text-lg" required aria-required="true">
                    </div>
                    <button type="submit" class="w-full gradient-button text-white py-4 rounded-xl text-lg shadow-lg flex items-center justify-center" aria-label="Reset Password"><i class="fas fa-sync-alt mr-2 icon-blue animate-icon"></i>Reset Password</button>
                </form>
                <a href="?section=register" class="block w-full mt-4 text-accent hover:underline text-lg flex items-center justify-center" aria-label="Need an account? Register"><i class="fas fa-user-plus mr-2 icon-blue animate-icon"></i>Need an account? Register</a>
                <a href="?section=landing" class="block w-full mt-2 text-accent hover:underline text-lg flex items-center justify-center" aria-label="Back to Home"><i class="fas fa-home mr-2 icon-blue animate-icon"></i>Back to Home</a>
            </section>

        <!-- Customer Dashboard -->
        <?php elseif ($section === 'customer'): ?>
            <section id="customer-dashboard" class="fade-in bg-white p-10 rounded-2xl shadow-2xl max-w-lg mx-auto" role="region" aria-label="Customer Dashboard">
                <h2 class="text-3xl font-bold text-gray-800 mb-8 text-center flex items-center justify-center"><i class="fas fa-tachometer-alt mr-2 icon-blue animate-icon"></i>Customer Dashboard</h2>
                <div class="progress-bar mb-6">
                    <div class="progress-fill" style="width: 100%"></div>
                </div>
                <div class="mb-6 text-center text-gray-600 flex items-center justify-center text-lg"><i class="fas fa-user mr-2 icon-blue animate-icon"></i>Logged in as: <span class="font-semibold"><?= htmlspecialchars($currentUser['username']) ?></span></div>
                <div class="mb-6 text-center text-gray-600 flex items-center justify-center text-lg"><i class="fas fa-star mr-2 text-yellow-400 animate-icon"></i>Loyalty Points: <span id="loyaltyPoints" class="font-semibold"><?= $loyaltyPoints ?></span></div>

                <!-- Profile Management -->
                <div class="mb-10">
                    <h3 class="text-2xl font-semibold text-gray-800 mb-6 flex items-center"><i class="fas fa-user-edit mr-2 icon-blue animate-icon"></i>Your Profile</h3>
                    <form method="POST" action="">
                        <input type="hidden" name="action" value="update_profile">
                        <div class="mb-6 relative">
                            <label class="block text-gray-700 font-medium flex items-center text-lg"><i class="fas fa-user mr-2 icon-blue animate-icon"></i>Full Name</label>
                            <input type="text" name="fullName" class="w-full px-5 py-3 border rounded-lg focus:outline-none pl-12 text-lg" value="<?= htmlspecialchars($currentUser['full_name']) ?>" required aria-required="true" aria-describedby="profileFullNameError">
                            <p id="profileFullNameError" class="error-message hidden"></p>
                        </div>
                        <div class="mb-6 relative">
                            <label class="block text-gray-700 font-medium flex items-center text-lg"><i class="fas fa-phone mr-2 icon-blue animate-icon"></i>Phone Number</label>
                            <input type="tel" name="phone" class="w-full px-5 py-3 border rounded-lg focus:outline-none pl-12 text-lg" value="<?= htmlspecialchars($currentUser['phone']) ?>" required aria-required="true" aria-describedby="profilePhoneError">
                            <p id="profilePhoneError" class="error-message hidden"></p>
                        </div>
                        <button type="submit" class="w-full gradient-button text-white py-4 rounded-xl text-lg shadow-lg flex items-center justify-center" aria-label="Update Profile"><i class="fas fa-save mr-2 icon-blue animate-icon"></i>Update Profile</button>
                    </form>
                </div>

                <!-- Feedback Form for Sentiment Analysis -->
                <div class="mb-10">
                    <h3 class="text-2xl font-semibold text-gray-800 mb-6 flex items-center"><i class="fas fa-comment-dots mr-2 icon-red animate-icon"></i>Leave Feedback</h3>
                    <form method="POST" action="">
                        <input type="hidden" name="action" value="submit_feedback">
                        <div class="mb-6 relative">
                            <label class="block text-gray-700 font-medium flex items-center text-lg"><i class="fas fa-quote-left mr-2 icon-blue animate-icon"></i>Feedback</label>
                            <textarea name="text" class="w-full px-5 py-3 border rounded-lg focus:outline-none text-lg" rows="3" required aria-required="true" aria-describedby="feedbackError"></textarea>
                            <p id="feedbackError" class="error-message hidden"></p>
                        </div>
                        <button type="submit" class="w-full gradient-button text-white py-4 rounded-xl text-lg shadow-lg flex items-center justify-center" aria-label="Submit Feedback"><i class="fas fa-paper-plane mr-2 icon-blue animate-icon"></i>Submit Feedback</button>
                    </form>
                </div>

                <!-- Booking Form -->
                <div class="mb-10" id="booking-section">
                    <h3 class="text-2xl font-semibold text-gray-800 mb-6 flex items-center"><i class="fas fa-calendar-plus mr-2 icon-blue animate-icon"></i>Book a Service</h3>
                    <form method="POST" action="">
                        <input type="hidden" name="action" value="book_service">
                        <div class="mb-6 relative">
                            <label class="block text-gray-700 font-medium flex items-center text-lg"><i class="fas fa-user mr-2 icon-blue animate-icon"></i>Full Name</label>
                            <input type="text" name="fullName" class="w-full px-5 py-3 border rounded-lg focus:outline-none pl-12 text-lg" value="<?= htmlspecialchars($currentUser['full_name']) ?>" required aria-required="true" aria-describedby="fullNameError">
                            <p id="fullNameError" class="error-message hidden"></p>
                        </div>
                        <div class="mb-6 relative">
                            <label class="block text-gray-700 font-medium flex items-center text-lg"><i class="fas fa-phone mr-2 icon-blue animate-icon"></i>Phone Number</label>
                            <input type="tel" name="phoneNumber" class="w-full px-5 py-3 border rounded-lg focus:outline-none pl-12 text-lg" value="<?= htmlspecialchars($currentUser['phone']) ?>" required aria-required="true" aria-describedby="phoneNumberError">
                            <p id="phoneNumberError" class="error-message hidden"></p>
                        </div>
                        <div class="mb-6 relative">
                            <label class="block text-gray-700 font-medium flex items-center text-lg"><i class="fas fa-cogs mr-2 icon-blue animate-icon"></i>Service Type</label>
                            <select name="serviceType" class="w-full px-5 py-3 border rounded-lg focus:outline-none pl-12 text-lg" required aria-required="true">
                                <option value="Basic Cleaning">Basic Cleaning - R75</option>
                                <option value="Premium Cleaning">Premium Cleaning - R100</option>
                                <option value="Restoration">Restoration - R150</option>
                            </select>
                        </div>
                        <div class="mb-6 relative">
                            <label class="block text-gray-700 font-medium flex items-center text-lg"><i class="fas fa-truck mr-2 icon-blue animate-icon"></i>Delivery Option</label>
                            <div class="flex space-x-6">
                                <label class="flex items-center"><input type="radio" name="deliveryOption" value="store" checked class="mr-2 h-5 w-5" aria-label="Bring to store"> <i class="fas fa-store mr-1 icon-blue animate-icon"></i>Bring to store</label>
                                <label class="flex items-center"><input type="radio" name="deliveryOption" value="home" class="mr-2 h-5 w-5" aria-label="Home collection"> <i class="fas fa-home mr-1 icon-blue animate-icon"></i>Home collection (+R15)</label>
                            </div>
                        </div>
                        <div id="addressSection" class="mb-6 relative hidden">
                            <label class="block text-gray-700 font-medium flex items-center text-lg"><i class="fas fa-map-marker-alt mr-2 icon-blue animate-icon"></i>Address</label>
                            <input type="text" name="address" class="w-full px-5 py-3 border rounded-lg focus:outline-none pl-12 text-lg" aria-describedby="addressError">
                            <p id="addressError" class="error-message hidden"></p>
                        </div>
                        <div class="mb-6 relative">
                            <label class="block text-gray-700 font-medium flex items-center text-lg"><i class="fas fa-coins mr-2 icon-red animate-icon"></i>Redeem Loyalty Points</label>
                            <input type="number" name="redeemPoints" class="w-full px-5 py-3 border rounded-lg focus:outline-none pl-12 text-lg" min="0" max="<?= $loyaltyPoints ?>" placeholder="Enter points to redeem (10 points = R5 off)" aria-describedby="redeemPointsError">
                            <p id="redeemPointsError" class="error-message hidden"></p>
                            <p class="text-sm text-gray-600 mt-1">Suggested: <span class="font-bold text-accent"></span></p>
                        </div>
                        <div class="mb-6 relative">
                            <label class="block text-gray-700 font-medium flex items-center text-lg"><i class="fas fa-calendar mr-2 icon-red animate-icon"></i>Preferred Date</label>
                            <input type="date" name="preferredDate" class="w-full px-5 py-3 border rounded-lg focus:outline-none pl-12 text-lg" required min="2025-10-04" aria-required="true" aria-describedby="preferredDateError">
                            <p id="preferredDateError" class="error-message hidden"></p>
                            <p class="text-sm text-gray-600 mt-1">Suggested slots: <span class="font-bold text-accent"></span></p>
                        </div>
                        <button type="submit" class="w-full gradient-button text-white py-4 rounded-xl text-lg shadow-lg flex items-center justify-center" aria-label="Book Now"><i class="fas fa-calendar-plus mr-2 icon-blue animate-icon"></i>Book Now</button>
                    </form>
                </div>

                <!-- Booking History -->
                <div>
                    <h3 class="text-2xl font-semibold text-gray-800 mb-6 flex items-center"><i class="fas fa-history mr-2 icon-red animate-icon"></i>Your Booking History</h3>
                    <div id="user-bookings-list" class="space-y-6">
                        <?php if (empty($userBookings)): ?>
                            <p class="text-gray-600 flex items-center text-lg"><i class="fas fa-info-circle mr-2 icon-blue animate-icon"></i>No bookings yet.</p>
                        <?php else: ?>
                            <?php foreach ($userBookings as $booking): ?>
                                <div class="border p-6 rounded-2xl bg-white shadow-md">
                                    <p class="text-lg flex items-center"><strong><i class="fas fa-hashtag mr-1 icon-blue animate-icon"></i>Order ID:</strong> <?= htmlspecialchars($booking['order_id']) ?></p>
                                    <p class="text-lg flex items-center"><strong><i class="fas fa-user mr-1 icon-blue animate-icon"></i>Name:</strong> <?= htmlspecialchars($booking['full_name']) ?></p>
                                    <p class="text-lg flex items-center"><strong><i class="fas fa-phone mr-1 icon-blue animate-icon"></i>Phone:</strong> <?= htmlspecialchars($booking['phone_number']) ?></p>
                                    <p class="text-lg flex items-center"><strong><i class="fas fa-cogs mr-1 icon-blue animate-icon"></i>Service:</strong> <?= htmlspecialchars($booking['service_type']) ?> - R<?= $booking['price'] ?></p>
                                    <p class="text-lg flex items-center"><strong><i class="fas fa-truck mr-1 icon-blue animate-icon"></i>Delivery:</strong> <?= $booking['delivery_option'] === 'home' ? 'Home collection (+R15)' : 'Bring to store' ?></p>
                                    <?php if ($booking['address']): ?>
                                        <p class="text-lg flex items-center"><strong><i class="fas fa-map-marker-alt mr-1 icon-blue animate-icon"></i>Address:</strong> <?= htmlspecialchars($booking['address']) ?></p>
                                    <?php endif; ?>
                                    <p class="text-lg flex items-center"><strong><i class="fas fa-calendar mr-1 icon-blue animate-icon"></i>Preferred Date:</strong> <?= $booking['preferred_date'] ?></p>
                                    <p class="text-lg flex items-center"><strong><i class="fas fa-clock mr-1 icon-blue animate-icon"></i>Booked On:</strong> <?= date('Y-m-d H:i', strtotime($booking['date_booked'])) ?></p>
                                    <p class="text-lg flex items-center"><strong><i class="fas fa-info-circle mr-1 icon-blue animate-icon"></i>Status:</strong> <?= ucfirst($booking['status']) ?></p>
                                    <?php if ($booking['redeemed_points']): ?>
                                        <p class="text-lg flex items-center"><strong><i class="fas fa-coins mr-1 icon-red animate-icon"></i>Redeemed Points:</strong> <?= $booking['redeemed_points'] ?> (Discount: R<?= $booking['discount'] ?>)</p>
                                    <?php endif; ?>
                                    <?php if ($booking['estimated_ready']): ?>
                                        <p class="text-lg flex items-center"><strong><i class="fas fa-clock mr-1 icon-blue animate-icon"></i>Est. Ready:</strong> <?= $booking['estimated_ready'] ?></p>
                                    <?php endif; ?>
                                    <?php if ($booking['actual_ready']): ?>
                                        <p class="text-lg flex items-center"><strong><i class="fas fa-clock-check mr-1 text-green-600 animate-icon"></i>Ready Date:</strong> <?= $booking['actual_ready'] ?></p>
                                    <?php endif; ?>
                                    <?php if ($booking['return_option']): ?>
                                        <p class="text-lg flex items-center"><strong><i class="fas fa-undo mr-1 icon-blue animate-icon"></i>Return Option:</strong> <?= $booking['return_option'] === 'collection' ? 'Collect at Store' : 'Delivery to Customer (+R15)' ?></p>
                                    <?php endif; ?>
                                    <?php if ($booking['status'] === 'ready' && !$booking['return_option']): ?>
                                        <div class="flex space-x-4 mt-4">
                                            <form method="POST" action="" class="inline">
                                                <input type="hidden" name="action" value="choose_return">
                                                <input type="hidden" name="bookingId" value="<?= $booking['id'] ?>">
                                                <button type="submit" name="returnOption" value="collection" class="bg-blue-500 text-white px-4 py-2 rounded-lg text-lg shadow-md flex items-center" aria-label="Choose Collection"><i class="fas fa-store mr-1 icon-blue animate-icon"></i>Collect at Store</button>
                                            </form>
                                            <form method="POST" action="" class="inline">
                                                <input type="hidden" name="action" value="choose_return">
                                                <input type="hidden" name="bookingId" value="<?= $booking['id'] ?>">
                                                <button type="submit" name="returnOption" value="delivery" class="bg-green-500 text-white px-4 py-2 rounded-lg text-lg shadow-md flex items-center" aria-label="Choose Delivery"><i class="fas fa-truck mr-1 icon-blue animate-icon"></i>Deliver to Me (+R15)</button>
                                            </form>
                                        </div>
                                    <?php endif; ?>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                </div>

                <a href="?action=logout" class="w-full mt-10 bg-red-600 text-white py-4 rounded-xl text-lg shadow-lg flex items-center justify-center" aria-label="Logout"><i class="fas fa-sign-out-alt mr-2 icon-red animate-icon"></i>Logout</a>
            </section>

        <!-- Admin Panel -->
        <?php elseif ($section === 'admin'): ?>
            <section id="admin-panel" class="fade-in bg-white p-10 rounded-2xl shadow-2xl" role="region" aria-label="Admin Panel">
                <h2 class="text-3xl font-bold text-gray-800 mb-8 text-center flex items-center justify-center"><i class="fas fa-user-shield mr-2 icon-red animate-icon"></i>Admin Panel</h2>
                <div class="mb-6 text-center text-gray-600 flex items-center justify-center text-lg"><i class="fas fa-user mr-2 icon-blue animate-icon"></i>Logged in as: <span id="currentAdmin" class="font-semibold"><?= htmlspecialchars($currentUser['username']) ?></span></div>

                <!-- Analytics Summary -->
                <div class="mb-10 p-8 bg-white rounded-2xl shadow-lg">
                    <h3 class="text-2xl font-semibold text-gray-800 mb-6 flex items-center"><i class="fas fa-chart-bar mr-2 icon-blue animate-icon"></i>Analytics</h3>
                    <p class="text-gray-700 flex items-center mb-6 text-lg"><i class="fas fa-calendar mr-2 icon-blue animate-icon"></i>Total Bookings: <?= $totalBookings ?></p>
                    <p class="text-gray-700 flex items-center mb-6 text-lg"><i class="fas fa-dollar-sign mr-2 icon-blue animate-icon"></i>Total Revenue: R<?= $totalRevenue ?></p>
                    <p class="text-gray-700 flex items-center mb-6 text-lg"><i class="fas fa-comments mr-2 icon-blue animate-icon"></i>Average Sentiment Score: <span id="sentimentScore"><?= $avgSentiment ?></span></p>
                    <div class="chart-container">
                        <canvas id="bookingChart"></canvas>
                    </div>
                    <div class="chart-container mt-6">
                        <canvas id="revenueTrendChart"></canvas>
                    </div>
                </div>

                <!-- Bookings List -->
                <div>
                    <h3 class="text-2xl font-semibold text-gray-800 mb-6 flex items-center"><i class="fas fa-list mr-2 icon-blue animate-icon"></i>Bookings List</h3>
                    <div id="bookings-list" class="space-y-6 mb-10">
                        <?php foreach ($allBookings as $booking): ?>
                            <div class="border p-6 rounded-2xl bg-white shadow-md flex justify-between items-start">
                                <div>
                                    <p class="text-lg flex items-center"><strong><i class="fas fa-hashtag mr-1 icon-blue animate-icon"></i>Order ID:</strong> <?= htmlspecialchars($booking['order_id']) ?></p>
                                    <p class="text-lg flex items-center"><strong><i class="fas fa-user mr-1 icon-blue animate-icon"></i>Name:</strong> <?= htmlspecialchars($booking['full_name']) ?></p>
                                    <p class="text-lg flex items-center"><strong><i class="fas fa-phone mr-1 icon-blue animate-icon"></i>Phone:</strong> <?= htmlspecialchars($booking['phone_number']) ?></p>
                                    <p class="text-lg flex items-center"><strong><i class="fas fa-cogs mr-1 icon-blue animate-icon"></i>Service:</strong> <?= htmlspecialchars($booking['service_type']) ?> - R<?= $booking['price'] ?></p>
                                    <p class="text-lg flex items-center"><strong><i class="fas fa-truck mr-1 icon-blue animate-icon"></i>Delivery:</strong> <?= $booking['delivery_option'] === 'home' ? 'Home collection (+R15)' : 'Bring to store' ?></p>
                                    <?php if ($booking['address']): ?>
                                        <p class="text-lg flex items-center"><strong><i class="fas fa-map-marker-alt mr-1 icon-blue animate-icon"></i>Address:</strong> <?= htmlspecialchars($booking['address']) ?></p>
                                    <?php endif; ?>
                                    <p class="text-lg flex items-center"><strong><i class="fas fa-calendar mr-1 icon-blue animate-icon"></i>Preferred Date:</strong> <?= $booking['preferred_date'] ?></p>
                                    <p class="text-lg flex items-center"><strong><i class="fas fa-clock mr-1 icon-blue animate-icon"></i>Booked On:</strong> <?= date('Y-m-d H:i', strtotime($booking['date_booked'])) ?></p>
                                    <p class="text-lg flex items-center"><strong><i class="fas fa-user mr-1 icon-blue animate-icon"></i>User:</strong> <?= htmlspecialchars($booking['user_username']) ?></p>
                                    <p class="text-lg flex items-center"><strong><i class="fas fa-info-circle mr-1 icon-blue animate-icon"></i>Status:</strong> <?= ucfirst($booking['status']) ?></p>
                                    <?php if ($booking['redeemed_points']): ?>
                                        <p class="text-lg flex items-center"><strong><i class="fas fa-coins mr-1 icon-red animate-icon"></i>Redeemed Points:</strong> <?= $booking['redeemed_points'] ?> (Discount: R<?= $booking['discount'] ?>)</p>
                                    <?php endif; ?>
                                    <?php if ($booking['estimated_ready']): ?>
                                        <p class="text-lg flex items-center"><strong><i class="fas fa-clock mr-1 icon-blue animate-icon"></i>Est. Ready:</strong> <?= $booking['estimated_ready'] ?></p>
                                    <?php endif; ?>
                                    <?php if ($booking['actual_ready']): ?>
                                        <p class="text-lg flex items-center"><strong><i class="fas fa-clock-check mr-1 text-green-600 animate-icon"></i>Ready Date:</strong> <?= $booking['actual_ready'] ?></p>
                                    <?php endif; ?>
                                    <?php if ($booking['return_option']): ?>
                                        <p class="text-lg flex items-center"><strong><i class="fas fa-undo mr-1 icon-blue animate-icon"></i>Return Option:</strong> <?= $booking['return_option'] === 'collection' ? 'Collect at Store' : 'Delivery to Customer (+R15)' ?></p>
                                    <?php endif; ?>
                                </div>
                                <div class="flex flex-col space-y-3">
                                    <form method="POST" action="" class="inline">
                                        <input type="hidden" name="action" value="update_status">
                                        <input type="hidden" name="bookingId" value="<?= $booking['id'] ?>">
                                        <button type="submit" name="newStatus" value="ready" class="bg-green-500 text-white px-4 py-2 rounded-lg text-lg shadow-md flex items-center" aria-label="Mark as Ready"><i class="fas fa-check-double mr-1 icon-blue animate-icon"></i>Mark as Ready</button>
                                    </form>
                                    <form method="POST" action="" class="inline">
                                        <input type="hidden" name="action" value="update_status">
                                        <input type="hidden" name="bookingId" value="<?= $booking['id'] ?>">
                                        <button type="submit" name="newStatus" value="cancelled" class="bg-yellow-500 text-white px-4 py-2 rounded-lg text-lg shadow-md flex items-center" aria-label="Mark as Cancelled"><i class="fas fa-times mr-1 icon-blue animate-icon"></i>Mark Cancelled</button>
                                    </form>
                                    <form method="POST" action="" class="inline">
                                        <input type="hidden" name="action" value="delete_booking">
                                        <input type="hidden" name="bookingId" value="<?= $booking['id'] ?>">
                                        <button type="submit" class="bg-red-600 text-white px-4 py-2 rounded-lg text-lg shadow-md flex items-center" aria-label="Delete Booking"><i class="fas fa-trash mr-1 icon-red animate-icon"></i>Delete</button>
                                    </form>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>

                <a href="?action=download_csv" class="w-full gradient-button text-white py-4 rounded-xl text-lg shadow-lg mb-4 flex items-center justify-center" aria-label="Download Bookings CSV"><i class="fas fa-download mr-2 icon-blue animate-icon"></i>Download Bookings CSV</a>
                <a href="?action=download_analytics" class="w-full bg-red-600 text-white py-4 rounded-xl text-lg shadow-lg mb-4 flex items-center justify-center" aria-label="Download Analytics PDF"><i class="fas fa-file-pdf mr-2 icon-red animate-icon"></i>Download Analytics PDF</a>
                <a href="?action=logout" class="w-full bg-red-600 text-white py-4 rounded-xl text-lg shadow-lg flex items-center justify-center" aria-label="Logout"><i class="fas fa-sign-out-alt mr-2 icon-red animate-icon"></i>Logout</a>
            </section>
        <?php endif; ?>

        <!-- Booking Confirmation Modal (if needed, but since redirect to Stripe, optional) -->
        <div id="bookingModal" class="modal" role="dialog" aria-label="Booking Confirmation">
            <div class="modal-content">
                <h3 class="text-2xl font-semibold text-gray-800 mb-6 flex items-center"><i class="fas fa-check-circle mr-2 text-green-600 animate-icon"></i>Booking Confirmation</h3>
                <div id="bookingDetails" class="text-lg"></div>
                <button onclick="closeModal()" class="mt-6 gradient-button text-white py-3 px-6 rounded-xl text-lg shadow-lg flex items-center justify-center" aria-label="Close"><i class="fas fa-times mr-2 icon-blue animate-icon"></i>Close</button>
            </div>
        </div>
    </main>

    <!-- Footer -->
    <footer class="bg-gray-900 text-white p-8 mt-auto" role="contentinfo">
        <div class="container mx-auto text-center">
            <p class="text-lg">&copy; 2025 Big Five Shoes Cleaning Services. All rights reserved.</p>
            <div class="flex justify-center space-x-8 mt-6">
                <a href="#" class="hover:text-accent text-xl" aria-label="Facebook"><i class="fab fa-facebook-f icon-blue animate-icon"></i></a>
                <a href="#" class="hover:text-accent text-xl" aria-label="Twitter"><i class="fab fa-twitter icon-blue animate-icon"></i></a>
                <a href="#" class="hover:text-accent text-xl" aria-label="Instagram"><i class="fab fa-instagram icon-blue animate-icon"></i></a>
                <a href="#" class="text-accent hover:underline text-lg flex items-center" aria-label="Customer Survey"><i class="fas fa-chart-bar mr-1 icon-blue animate-icon"></i>Survey</a>
            </div>
        </div>
    </footer>

    <?php if ($action === 'download_csv'): ?>
        <?php
        header('Content-Type: text/csv');
        header('Content-Disposition: attachment; filename="bookings.csv"');
        $output = fopen('php://output', 'w');
        fputcsv($output, ['Order ID', 'Full Name', 'Phone', 'Service', 'Price', 'Delivery Option', 'Address', 'Preferred Date', 'Booked On', 'User', 'Status', 'Return Option', 'Redeemed Points', 'Discount', 'Estimated Ready', 'Actual Ready']);
        foreach ($allBookings as $b) {
            fputcsv($output, [
                $b['order_id'], $b['full_name'], $b['phone_number'], $b['service_type'], $b['price'],
                $b['delivery_option'], $b['address'], $b['preferred_date'], $b['date_booked'],
                $b['user_username'], $b['status'], $b['return_option'] ?? '', $b['redeemed_points'], $b['discount'],
                $b['estimated_ready'] ?? '', $b['actual_ready'] ?? ''
            ]);
        }
        fclose($output);
        exit;
        ?>
    <?php elseif ($action === 'download_analytics'): ?>
        <?php
        header('Content-Type: text/plain');
        header('Content-Disposition: attachment; filename="analytics.txt"');
        echo "Big Five Shoes Analytics Report\n\n";
        echo "Total Bookings: $totalBookings\n";
        echo "Total Revenue: R$totalRevenue\n";
        echo "Average Sentiment: $avgSentiment\n";
        echo "Bookings by Service Type:\n";
        foreach ($serviceCounts as $service => $count) {
            echo "  $service: $count\n";
        }
        exit;
        ?>
    <?php endif; ?>

    <script>
        let carouselIndex = 0;

        function moveCarousel(direction) {
            const carousel = document.querySelector('.carousel-inner');
            carouselIndex = (carouselIndex + direction + 3) % 3;
            carousel.style.transform = `translateX(-${carouselIndex * 100}%)`;
        }

        function closeModal() {
            document.getElementById('bookingModal').style.display = 'none';
        }

        function startCarousel() {
            const carousel = document.querySelector('.carousel-inner');
            setInterval(() => {
                carouselIndex = (carouselIndex + 1) % 3;
                carousel.style.transform = `translateX(-${carouselIndex * 100}%)`;
            }, 5000);
        }

        function triggerScrollAnimations() {
            const elements = document.querySelectorAll('.animate-on-scroll');
            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        entry.target.classList.add('visible');
                    }
                });
            }, { threshold: 0.1 });

            elements.forEach(element => observer.observe(element));
        }

        document.addEventListener('DOMContentLoaded', () => {
            // Delivery option toggle
            const deliveryRadios = document.querySelectorAll('input[name="deliveryOption"]');
            deliveryRadios.forEach(radio => {
                radio.addEventListener('change', () => {
                    document.getElementById('addressSection').classList.toggle('hidden', radio.value !== 'home');
                });
            });

            // Redeem points suggestion (simple)
            const redeemInput = document.querySelector('input[name="redeemPoints"]');
            if (redeemInput) {
                redeemInput.addEventListener('input', () => {
                    const points = parseInt(redeemInput.value) || 0;
                    const max = <?= $loyaltyPoints ?>;
                    if (points > max) {
                        redeemInput.value = max;
                    }
                });
            }

            // Charts for admin
            <?php if ($section === 'admin'): ?>
                const bookingCtx = document.getElementById('bookingChart').getContext('2d');
                new Chart(bookingCtx, {
                    type: 'bar',
                    data: {
                        labels: <?= json_encode(array_keys($serviceCounts)) ?>,
                        datasets: [{
                            label: 'Bookings by Service Type',
                            data: <?= json_encode(array_values($serviceCounts)) ?>,
                            backgroundColor: ['#3b82f6', '#10b981', '#f43f5e'],
                            borderColor: ['#1e40af', '#047857', '#be123c'],
                            borderWidth: 1
                        }]
                    },
                    options: {
                        scales: {
                            y: {
                                beginAtZero: true,
                                ticks: { stepSize: 1 }
                            }
                        },
                        plugins: { legend: { display: true } }
                    }
                });

                const revenueCtx = document.getElementById('revenueTrendChart').getContext('2d');
                new Chart(revenueCtx, {
                    type: 'line',
                    data: {
                        labels: <?= json_encode(array_keys($revenueByDate)) ?>,
                        datasets: [{
                            label: 'Revenue by Date',
                            data: <?= json_encode(array_values($revenueByDate)) ?>,
                            borderColor: '#3b82f6',
                            fill: false
                        }]
                    },
                    options: {
                        scales: { y: { beginAtZero: true } },
                        plugins: { legend: { display: true } }
                    }
                });
            <?php endif; ?>

            startCarousel();
            triggerScrollAnimations();
        });
    </script>
</body>
</html>