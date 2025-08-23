<?php

declare(strict_types=1);

namespace PHPCore\SimpleCrypto\Wallet\KeyPair;

interface KeyPairInterface
{
    /**
     * Get the private key in hex format
     *
     * @return string Hex encoded private key
     */
    public function getPrivateKey(): string;

    /**
     * Get the public key in hex format (uncompressed)
     *
     * @return string Hex encoded public key
     */
    public function getPublicKey(): string;

    /**
     * Get the compressed public key in hex format
     *
     * @return string Hex encoded compressed public key
     */
    public function getCompressedPublicKey(): string;

    /**
     * Get the chain code for HD wallet derivation
     *
     * @return string Hex encoded chain code
     */
    public function getChainCode(): string;

    /**
     * Derive a child key pair using BIP32 derivation
     *
     * @param int $index Child index
     * @param bool $hardened Whether to use hardened derivation
     * @return self New instance of key pair
     */
    public function deriveChild(int $index, bool $hardened = false): self;

    /**
     * Derive a key pair from a derivation path (e.g. "m/44'/60'/0'/0/0")
     *
     * @param string $path BIP32 derivation path
     * @return self New instance of key pair
     * @throws \InvalidArgumentException If path is invalid
     */
    public function derivePath(string $path): self;

    /**
     * Sign a message with the private key
     *
     * @param string $message Message to sign (hex encoded)
     * @return string Signature in hex format
     */
    public function sign(string $message): string;

    /**
     * Verify a signature
     *
     * @param string $message Original message (hex encoded)
     * @param string $signature Signature to verify (hex encoded)
     * @return bool True if signature is valid
     */
    public function verify(string $message, string $signature): bool;
}
