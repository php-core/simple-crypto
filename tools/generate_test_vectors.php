<?php

require_once __DIR__ . '/../vendor/autoload.php';

use PHPCore\SimpleCrypto\Wallet\KeyPair\EVMKeyPair;
use PHPCore\SimpleCrypto\Wallet\Mnemonic\BIP39Mnemonic;

// Function to generate test vectors
function generateTestVectors() {
    // Test vector 1 - Known private key
    $privateKey = '0c1f67465719b8b644879372014792e573122fa21193f88095aec21df2e9b778';
    $chainCode = '873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508';
    
    $keyPair = new EVMKeyPair($privateKey, $chainCode);
    echo "Test Vector 1:\n";
    echo "Private Key: " . $privateKey . "\n";
    echo "Chain Code: " . $chainCode . "\n";
    echo "Address: " . $keyPair->getAddress() . "\n\n";

    // Test vector 2 - Derivation path
    $seed = '000102030405060708090a0b0c0d0e0f';
    $master = EVMKeyPair::fromSeed($seed);
    $derived = $master->derivePath("m/44'/60'/0'/0/0");
    
    echo "Test Vector 2:\n";
    echo "Seed: " . $seed . "\n";
    echo "Path: m/44'/60'/0'/0/0\n";
    echo "Address: " . $derived->getAddress() . "\n\n";

    // Test vector 3 - Mnemonic to address
    $mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    $mnemonicHandler = new BIP39Mnemonic();
    $seed = $mnemonicHandler->toSeed($mnemonic);
    $wallet = EVMKeyPair::fromSeed($seed);
    $address = $wallet->derivePath("m/44'/60'/0'/0/0")->getAddress();
    
    echo "Test Vector 3:\n";
    echo "Mnemonic: " . $mnemonic . "\n";
    echo "Seed: " . $seed . "\n";
    echo "Address: " . $address . "\n";
}

// Generate and display test vectors
generateTestVectors();