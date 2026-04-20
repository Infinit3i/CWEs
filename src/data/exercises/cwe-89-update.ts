import type { Exercise } from '@/data/exercises'

export const cwe89Update: Exercise = {
  cweId: 'CWE-89',
  name: 'SQL Injection - User Profile Update',
  language: 'PHP',
  vulnerableFunction: `<?php
function updateUserProfile($userId, $name, $email) {
    global $db;

    $nameQuery = "UPDATE users SET name = '" . $name . "' WHERE id = " . $userId;
    $emailQuery = "UPDATE users SET email = '" . $email . "' WHERE id = " . $userId;

    $db->query($nameQuery);
    $db->query($emailQuery);

    return array('success' => true);
}
?>`,
  vulnerableLine: `$nameQuery = "UPDATE users SET name = '" . $name . "' WHERE id = " . $userId;
    $emailQuery = "UPDATE users SET email = '" . $email . "' WHERE id = " . $userId;`,
  options: [
    {
      code: `$stmt = $db->prepare("UPDATE users SET name = ? WHERE id = ?");
$stmt->execute([$name, $userId]);
$stmt = $db->prepare("UPDATE users SET email = ? WHERE id = ?");
$stmt->execute([$email, $userId]);`,
      correct: true,
      explanation: `Use prepared statements with placeholders - database treats input as data, not code`
    },
    {
      code: `$nameQuery = "UPDATE users SET name = '" . addslashes($name) . "' WHERE id = " . $userId;
$emailQuery = "UPDATE users SET email = '" . $email . "' WHERE id = " . $userId;`,
      correct: false,
      explanation: 'addslashes() only escapes quotes and backslashes - other SQL injection techniques like UNION attacks still work'
    },
    {
      code: `$nameQuery = "UPDATE users SET name = '" . mysqli_real_escape_string($db, $name) . "' WHERE id = " . $userId;
$emailQuery = "UPDATE users SET email = '" . $email . "' WHERE id = " . $userId;`,
      correct: false,
      explanation: 'mysqli_real_escape_string() helps but only applied to name field - email field remains vulnerable'
    },
    {
      code: `$nameQuery = "UPDATE users SET name = '" . $name . "' WHERE id = '" . $userId . "'";
$emailQuery = "UPDATE users SET email = '" . $email . "' WHERE id = '" . $userId . "'";`,
      correct: false,
      explanation: 'Adding quotes around numeric fields doesn\'t prevent injection - attackers can close quotes and inject malicious SQL'
    },
    {
      code: `$nameQuery = "UPDATE users SET name = " . json_encode($name) . " WHERE id = " . $userId;
$emailQuery = "UPDATE users SET email = '" . $email . "' WHERE id = " . $userId;`,
      correct: false,
      explanation: 'json_encode() adds quotes but doesn\'t prevent all SQL injection forms - email field remains unprotected'
    },
    {
      code: `$nameQuery = "UPDATE users SET name = '$name' WHERE id = $userId";
$emailQuery = "UPDATE users SET email = '$email' WHERE id = $userId";`,
      correct: false,
      explanation: 'Double quotes vs single quotes provides no protection - variable interpolation still creates concatenated strings vulnerable to injection'
    },
    {
      code: `$nameQuery = "UPDATE users SET name = '" . urlencode($name) . "' WHERE id = " . $userId;
$emailQuery = "UPDATE users SET email = '" . $email . "' WHERE id = " . $userId;`,
      correct: false,
      explanation: 'urlencode() is for HTTP URLs, not SQL protection - characters like quotes become %27 but SQL still executes injected code'
    },
    {
      code: `$nameQuery = "UPDATE users SET name = '" . substr($name, 0, 100) . "' WHERE id = " . $userId;
$emailQuery = "UPDATE users SET email = '" . $email . "' WHERE id = " . $userId;`,
      correct: false,
      explanation: 'Truncating input doesn\'t prevent injection - short SQL payloads like \'; DROP TABLE users; -- work within length limits'
    },
    {
      code: `$nameQuery = "UPDATE users SET name = '" . strtolower($name) . "' WHERE id = " . $userId;
$emailQuery = "UPDATE users SET email = '" . $email . "' WHERE id = " . $userId;`,
      correct: false,
      explanation: 'strtolower() doesn\'t prevent SQL injection - payloads work in lowercase: \'; drop table users; --'
    },
    {
      code: `$nameQuery = "UPDATE users SET name = '" . preg_replace('/[<>]/', '', $name) . "' WHERE id = " . $userId;
$emailQuery = "UPDATE users SET email = '" . $email . "' WHERE id = " . $userId;`,
      correct: false,
      explanation: 'Removing HTML characters doesn\'t prevent SQL injection - SQL metacharacters like quotes and semicolons remain'
    }
  ]
}