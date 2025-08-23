<?php

require_once __DIR__ . '/../vendor/autoload.php';

use PHPCore\SimpleCrypto\Wallet\Mnemonic\BIP39Mnemonic;
use PHPCore\SimpleCrypto\Wallet\KeyPair\BTCKeyPair;
use PHPCore\SimpleCrypto\Wallet\KeyPair\EVMKeyPair;

// Create a new mnemonic (or use an existing one)
$mnemonic = new BIP39Mnemonic();
$phrase = $mnemonic->generate(12);
echo "Mnemonic phrase: " . $phrase . "\n\n";

// Convert mnemonic to seed
$seed = $mnemonic->toSeed($phrase);

// Create Bitcoin master key pair
$btcMaster = BTCKeyPair::fromSeed($seed);

// Create Ethereum/EVM master key pair (same seed!)
$evmMaster = EVMKeyPair::fromSeed($seed);

// Generate multiple addresses
for ($i = 0; $i < 3; $i++) {
    echo "Address Set #{$i}:\n";
    
    // Bitcoin addresses
    $btcPath = "m/84'/0'/0'/0/{$i}"; // BIP84 for native SegWit
    $btcAccount = $btcMaster->derivePath($btcPath);
    echo "Bitcoin Path: {$btcPath}\n";
    echo "Bitcoin Legacy: " . $btcAccount->getAddress('legacy') . "\n";
    echo "Bitcoin SegWit: " . $btcAccount->getAddress('segwit') . "\n";
    echo "Bitcoin Native SegWit: " . $btcAccount->getAddress('native_segwit') . "\n";
    
    // Ethereum/EVM addresses (same for Polygon, BSC, etc)
    $evmPath = "m/44'/60'/0'/0/{$i}"; // BIP44 for Ethereum
    $evmAccount = $evmMaster->derivePath($evmPath);
    echo "EVM Path: {$evmPath}\n";
    echo "EVM Address: " . $evmAccount->getAddress() . "\n";
    echo "-------------------\n";
}

// Note: Store your mnemonic phrase safely! It's the only way to recover your addresses
echo "\nIMPORTANT: Save your mnemonic phrase safely! It's needed to recover your wallet.\n";