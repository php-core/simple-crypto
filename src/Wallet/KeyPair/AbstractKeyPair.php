<?php

declare(strict_types=1);

namespace PHPCore\SimpleCrypto\Wallet\KeyPair;

use Elliptic\EC;

abstract class AbstractKeyPair implements KeyPairInterface
{
    /**
     * @var EC\KeyPair The underlying elliptic curve key pair
     */
    protected EC\KeyPair $keyPair;

    /**
     * @var string The chain code for HD wallet derivation
     */
    protected string $chainCode;

    /**
     * Create a new key pair from a seed
     *
     * @param string $seed Hex encoded seed
     * @return static
     * @throws \InvalidArgumentException If seed is invalid
     */
    public static function fromSeed(string $seed): static
    {
        if (! ctype_xdigit($seed)) {
            throw new \InvalidArgumentException('Seed must be a valid hex string');
        }

        // Initialize HMAC-SHA512 with key "Bitcoin seed"
        $hmac = @hex2bin($seed);
        if ($hmac === false) {
            throw new \InvalidArgumentException('Invalid seed format');
        }

        $hmac = hash_hmac('sha512', $hmac, 'Bitcoin seed', true);

        // Split the result into master secret key and chain code
        $masterKey = substr($hmac, 0, 32);
        $chainCode = substr($hmac, 32, 32);

        return new static(bin2hex($masterKey), bin2hex($chainCode));
    }

    /**
     * Constructor
     *
     * @param string $privateKey Hex encoded private key
     * @param string $chainCode Hex encoded chain code
     * @throws \InvalidArgumentException If inputs are invalid
     */
    public function __construct(string $privateKey, string $chainCode)
    {
        if (! ctype_xdigit($privateKey) || ! ctype_xdigit($chainCode)) {
            throw new \InvalidArgumentException('Private key and chain code must be valid hex strings');
        }

        try {
            // Initialize secp256k1 curve
            $ec = new EC('secp256k1');

            // Create key pair from private key
            $this->keyPair = $ec->keyFromPrivate($privateKey, 'hex');
            $this->chainCode = $chainCode;
        } catch (\Throwable $e) {
            throw new \InvalidArgumentException('Failed to create key pair: ' . $e->getMessage());
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getPrivateKey(): string
    {
        return $this->keyPair->getPrivate('hex');
    }

    /**
     * {@inheritdoc}
     */
    public function getPublicKey(): string
    {
        return $this->keyPair->getPublic(false, 'hex');
    }

    /**
     * {@inheritdoc}
     */
    public function getCompressedPublicKey(): string
    {
        return $this->keyPair->getPublic(true, 'hex');
    }

    /**
     * {@inheritdoc}
     */
    public function getChainCode(): string
    {
        return $this->chainCode;
    }

    /**
     * {@inheritdoc}
     */
    public function derivePath(string $path): self
    {
        if (! preg_match('/^m(\/\d+\'?)*$/', $path)) {
            throw new \InvalidArgumentException('Invalid derivation path format');
        }

        $segments = explode('/', $path);
        array_shift($segments); // Remove 'm'

        $keyPair = $this;
        foreach ($segments as $segment) {
            $hardened = str_ends_with($segment, "'");
            $index = (int) rtrim($segment, "'");
            $keyPair = $keyPair->deriveChild($index, $hardened);
        }

        return $keyPair;
    }

    /**
     * Parse an integer from bytes
     *
     * @param string $bytes Raw bytes
     * @return string Decimal string
     */
    protected function parseIntFromBytes(string $bytes): string
    {
        return gmp_strval(gmp_init(bin2hex($bytes), 16), 10);
    }

    /**
     * Convert an integer to bytes
     *
     * @param int|string $int Integer or decimal string
     * @param int $length Desired length of the result in bytes
     * @return string Raw bytes
     */
    protected function intToBytes(int|string $int, int $length): string
    {
        return hex2bin(str_pad(gmp_strval(gmp_init($int, 10), 16), $length * 2, '0', STR_PAD_LEFT));
    }

    /**
     * Perform BIP32 derivation
     *
     * @param string $data Data to derive from
     * @return array{string, string} [Derived key, Chain code]
     */
    protected function deriveHmac(string $data): array
    {
        $hmac = hash_hmac('sha512', $data, hex2bin($this->chainCode), true);

        return [
            substr($hmac, 0, 32),
            substr($hmac, 32, 32),
        ];
    }
}
