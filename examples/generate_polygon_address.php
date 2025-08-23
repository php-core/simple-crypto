<?php

require_once __DIR__ . '/../vendor/autoload.php';

use PHPCore\SimpleCrypto\Wallet\Mnemonic\BIP39Mnemonic;
use PHPCore\SimpleCrypto\Wallet\KeyPair\EVMKeyPair;

// Create a new mnemonic (or use an existing one)
$mnemonic = new BIP39Mnemonic();
$phrase = $mnemonic->generate(12);
echo "Mnemonic phrase: " . $phrase . "\n\n";

// Convert mnemonic to seed
$seed = $mnemonic->toSeed($phrase);

// Create master key pair
$master = EVMKeyPair::fromSeed($seed);

// Generate multiple addresses (for example, first 5 addresses)
for ($i = 0; $i < 5; $i++) {
    $path = "m/44'/60'/0'/0/{$i}";
    $account = $master->derivePath($path);
    $address = $account->getAddress();
    $privateKey = $account->getPrivateKey();
    
    echo "Address #{$i}:\n";
    echo "Path: {$path}\n";
    echo "Address: {$address}\n";
    echo "Private Key: {$privateKey}\n";
    echo "-------------------\n";
}

// Note: Store your mnemonic phrase safely! It's the only way to recover your addresses
echo "\nIMPORTANT: Save your mnemonic phrase safely! It's needed to recover your wallet.\n";