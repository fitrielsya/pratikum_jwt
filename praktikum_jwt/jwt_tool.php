<?php
// ===============================
// JWT TOOL - Praktikum Kriptografi
// ===============================

// Secret Key Server
$SECRET_KEY = "Kunci_Super_Aman_Univ_Muh_PTK_2026";

// ===============================
// Base64URL Encode
// ===============================
function base64url_encode($data)
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

// ===============================
// Base64URL Decode
// ===============================
function base64url_decode($data)
{
    $remainder = strlen($data) % 4;

    if ($remainder) {
        $padlen = 4 - $remainder;
        $data .= str_repeat('=', $padlen);
    }

    return base64_decode(strtr($data, '-_', '+/'));
}

// ===============================
// Membuat JWT
// ===============================
function create_jwt($payload_data, $secret)
{
    // Header
    $header = [
        "typ" => "JWT",
        "alg" => "HS256"
    ];

    $header = json_encode($header);
    $payload = json_encode($payload_data);

    $base64Header = base64url_encode($header);
    $base64Payload = base64url_encode($payload);

    // Signature
    $signature = hash_hmac(
        "sha256",
        $base64Header . "." . $base64Payload,
        $secret,
        true
    );

    $base64Signature = base64url_encode($signature);

    return $base64Header . "." . $base64Payload . "." . $base64Signature;
}

// ===============================
// Verifikasi JWT
// ===============================
function verify_jwt($jwt, $secret)
{
    $tokenParts = explode(".", $jwt);

    if (count($tokenParts) != 3) {
        return [
            "valid" => false,
            "pesan" => "Format Token Salah!"
        ];
    }

    $header = $tokenParts[0];
    $payload = $tokenParts[1];
    $signature = $tokenParts[2];

    // Hitung ulang Signature
    $newSignature = hash_hmac(
        "sha256",
        $header . "." . $payload,
        $secret,
        true
    );

    $base64NewSignature = base64url_encode($newSignature);

    // Cek apakah sama
    if (!hash_equals($base64NewSignature, $signature)) {
        return [
            "valid" => false,
            "pesan" => "Token Dimodifikasi / Palsu (Signature Invalid)!"
        ];
    }

    // Decode Payload
    $payloadData = json_decode(base64url_decode($payload), true);

    // Cek Expired
    if (isset($payloadData["exp"])) {

        if (time() > $payloadData["exp"]) {

            return [
                "valid" => false,
                "pesan" => "Token Telah Kedaluwarsa (Expired)!"
            ];
        }
    }

    return [
        "valid" => true,
        "pesan" => "Token Sah!",
        "data" => $payloadData
    ];
}

// ===============================
// Controller
// ===============================
$hasil_gen = "";
$hasil_ver = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {

    $aksi = $_POST["aksi"];

    // Generate JWT
    if ($aksi == "generate") {

        $payload = [

            "iss" => "web_universitas",

            "user_id" => $_POST["userid"],

            "role" => $_POST["role"],

            "exp" => time() + 3600

        ];

        $hasil_gen = create_jwt($payload, $SECRET_KEY);
    }

    // Verifikasi JWT
    if ($aksi == "verify") {

        $token = trim($_POST["token_jwt"]);

        $cek = verify_jwt($token, $SECRET_KEY);

        if ($cek["valid"]) {

            $hasil_ver =
                "<span style='color:green;font-weight:bold;font-size:18px;'>✅ "
                . $cek["pesan"] .
                "</span><br><br>";

            $hasil_ver .=
                "<b>Payload :</b><br><pre>" .
                json_encode($cek["data"], JSON_PRETTY_PRINT) .
                "</pre>";

        } else {

            $hasil_ver =
                "<span style='color:red;font-weight:bold;font-size:18px;'>❌ "
                . $cek["pesan"] .
                "</span>";
        }
    }
}
?>

<!DOCTYPE html>
<html>

<head>

<meta charset="UTF-8">

<title>JWT Tool Praktikum</title>

<style>

body{
    font-family:Arial;
    background:#f5f5f5;
    padding:30px;
}

.box{
    background:white;
    padding:20px;
    margin-bottom:25px;
    border-radius:8px;
    box-shadow:0 0 10px rgba(0,0,0,.1);
}

input,textarea{

    width:100%;
    padding:10px;
    margin-top:8px;
    margin-bottom:15px;

    border:1px solid #ccc;
    border-radius:5px;

}

button{

    background:#0d6efd;
    color:white;
    padding:10px 20px;

    border:none;
    border-radius:5px;

    cursor:pointer;
}

button:hover{
    background:#0b5ed7;
}

pre{
    background:#efefef;
    padding:10px;
    overflow:auto;
}

</style>

</head>

<body>

<h1>🔐 Simulasi JWT API</h1>

<div class="box">

<h2>1. Generate Token JWT</h2>

<form method="POST">

<input type="hidden" name="aksi" value="generate">

<label>User ID</label>

<input
type="text"
name="userid"
value="1"
required>

<label>Role</label>

<input
type="text"
name="role"
value="User"
required>

<button type="submit">
Generate JWT
</button>

</form>

<textarea rows="8" readonly><?= htmlspecialchars($hasil_gen); ?></textarea>

</div>

<div class="box">

<h2>2. Verifikasi JWT</h2>

<form method="POST">

<input type="hidden" name="aksi" value="verify">

<label>Masukkan Token JWT</label>

<textarea
name="token_jwt"
rows="8"
required></textarea>

<button type="submit">
Verifikasi
</button>

</form>

<br>

<?= $hasil_ver; ?>

</div>

</body>
</html>