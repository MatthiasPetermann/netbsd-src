<?php
header('Content-Type: application/json');
echo json_encode([
    'service' => 'phpfpm',
    'status' => 'ok',
]);
