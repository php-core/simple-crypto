# Simple Crypto PHP

A simple and efficient PHP library for cryptocurrency wallet generation and management. Generate addresses for Bitcoin, Ethereum, and all EVM-compatible chains (Polygon, BSC, etc.) using standard BIP protocols.

## Features

- **Multiple Chain Support**:
  - Bitcoin (BTC)
    - Legacy addresses (1...)
    - SegWit addresses (3...)
    - Native SegWit addresses (bc1...)
  - All EVM-compatible chains:
    - Ethereum (ETH)
    - Polygon (MATIC)
    - Binance Smart Chain (BSC)
    - Avalanche (AVAX)
    - And any other EVM chain

- **Standards Compliance**:
  - BIP32 (Hierarchical Deterministic Wallets)
  - BIP39 (Mnemonic Phrases)
  - BIP44 (Multi-Account Hierarchy)
  - BIP84 (Native SegWit)

- **Security Features**:
  - Message signing and verification
  - Hardened derivation support
  - Secure key generation

## Requirements

- PHP 8.3+
- GMP extension
- Sodium extension
- MBString extension

## Installation

```bash
composer require php-core/simple-crypto
```

## Quick Start

### Generate Multi-Chain Addresses

```php
use PHPCore\SimpleCrypto\Wallet\Mnemonic\BIP39Mnemonic;
use PHPCore\SimpleCrypto\Wallet\KeyPair\BTCKeyPair;
use PHPCore\SimpleCrypto\Wallet\KeyPair\EVMKeyPair;

// Create or import a mnemonic
$mnemonic = new BIP39Mnemonic();
$phrase = $mnemonic->generate(12);
$seed = $mnemonic->toSeed($phrase);

// Create master key pairs
$btcMaster = BTCKeyPair::fromSeed($seed);
$evmMaster = EVMKeyPair::fromSeed($seed);

// Generate Bitcoin addresses
$btcPath = "m/84'/0'/0'/0/0"; // BIP84 for native SegWit
$btcAccount = $btcMaster->derivePath($btcPath);

echo "Bitcoin Legacy: " . $btcAccount->getAddress('legacy') . "\n";
echo "Bitcoin SegWit: " . $btcAccount->getAddress('segwit') . "\n";
echo "Bitcoin Native SegWit: " . $btcAccount->getAddress('native_segwit') . "\n";

// Generate EVM address (works for ETH, MATIC, BSC, etc.)
$evmPath = "m/44'/60'/0'/0/0"; // BIP44 for Ethereum
$evmAccount = $evmMaster->derivePath($evmPath);
echo "EVM Address: " . $evmAccount->getAddress() . "\n";
```

### Generate Multiple Addresses

```php
// Generate multiple Bitcoin addresses
for ($i = 0; $i < 5; $i++) {
    $path = "m/84'/0'/0'/0/{$i}";
    $account = $btcMaster->derivePath($path);
    echo "Address #{$i}: " . $account->getAddress('native_segwit') . "\n";
}

// Generate multiple EVM addresses
for ($i = 0; $i < 5; $i++) {
    $path = "m/44'/60'/0'/0/{$i}";
    $account = $evmMaster->derivePath($path);
    echo "Address #{$i}: " . $account->getAddress() . "\n";
}
```

### Sign and Verify Messages

```php
// Bitcoin message signing
$btcAccount = BTCKeyPair::fromSeed($seed);
$message = "Hello, Bitcoin!";
$signature = $btcAccount->sign($message);
$isValid = $btcAccount->verify($message, $signature);

// EVM message signing
$evmAccount = EVMKeyPair::fromSeed($seed);
$message = "Hello, Ethereum!";
$signature = $evmAccount->sign($message);
$isValid = $evmAccount->verify($message, $signature);
```

## Advanced Usage

### Custom Derivation Paths

```php
// Bitcoin paths
$legacyPath = "m/44'/0'/0'/0/0";     // BIP44 legacy
$segwitPath = "m/49'/0'/0'/0/0";      // BIP49 SegWit
$nativePath = "m/84'/0'/0'/0/0";      // BIP84 Native SegWit

// EVM paths
$standardPath = "m/44'/60'/0'/0/0";   // Standard Ethereum
$ledgerPath = "m/44'/60'/0'";         // Ledger Live
$customPath = "m/44'/60'/1'/0/0";     // Custom account
```

### Working with Private Keys

```php
$account = EVMKeyPair::fromSeed($seed);

// Get private key (for import into wallets)
$privateKey = $account->getPrivateKey();

// Get public key
$publicKey = $account->getPublicKey();

// Get compressed public key
$compressedPubKey = $account->getCompressedPublicKey();
```

## Security Considerations

1. **Mnemonic Phrases**:
   - Store securely
   - Never share with anyone
   - Enables recovery of all derived addresses

2. **Private Keys**:
   - Keep offline when possible
   - Use hardware wallets for large amounts
   - Each address has its own private key

3. **Testing**:
   - Use testnet addresses during development
   - Verify addresses before sending real funds

## Contributing

1. Fork the repository
2. Create your feature branch
3. Run tests: `composer test`
4. Submit a pull request

## License

MIT License. See LICENSE file for details.

## Credits

Developed by PHPCore Team.