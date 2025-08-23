<?php

require_once __DIR__ . '/../vendor/autoload.php';

use PHPCore\SimpleCrypto\Wallet\KeyPair\EVMKeyPair;

// Generate test vectors for key pairs
$privateKey = '0c1f67465719b8b644879372014792e573122fa21193f88095aec21df2e9b778';
$chainCode = '873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508';

$keyPair = new EVMKeyPair($privateKey, $chainCode);
echo "Key Pair Test Vector:\n";
echo "Private Key: " . $privateKey . "\n";
echo "Chain Code: " . $chainCode . "\n";
echo "Address: " . $keyPair->getAddress() . "\n\n";

// Generate test vectors for derivation paths
$seed = '000102030405060708090a0b0c0d0e0f';
$master = EVMKeyPair::fromSeed($seed);
$derived = $master->derivePath("m/44'/60'/0'/0/0");

echo "Derivation Test Vector:\n";
echo "Seed: " . $seed . "\n";
echo "Path: m/44'/60'/0'/0/0\n";
echo "Address: " . $derived->getAddress() . "\n";
