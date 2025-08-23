<?php

declare(strict_types=1);

namespace PHPCore\SimpleCrypto\Wallet\KeyPair;

use Elliptic\EC;
use kornrunner\Keccak;

final class EVMKeyPair extends AbstractKeyPair
{
    /**
     * Get the Ethereum address for this key pair
     */
    public function getAddress(): string
    {
        try {
            // Get public key without '04' prefix
            $pubKey = substr($this->getPublicKey(), 2);

            // Ensure pubKey is valid hex
            if (! ctype_xdigit($pubKey)) {
                throw new \InvalidArgumentException('Invalid public key format');
            }

            // Keccak-256 hash of public key
            $hash = Keccak::hash(hex2bin($pubKey), 256);

            // Take last 20 bytes
            $address = substr($hash, -40);

            // Checksum address according to EIP-55
            return $this->toChecksumAddress($address);
        } catch (\Throwable $e) {
            throw new \InvalidArgumentException('Failed to generate address: ' . $e->getMessage());
        }
    }

    /**
     * {@inheritdoc}
     */
    public function deriveChild(int $index, bool $hardened = false): self
    {
        if ($index < 0) {
            throw new \InvalidArgumentException('Child index cannot be negative');
        }

        try {
            if ($hardened) {
                $index += 0x80000000;
            }

            // Prepare data for derivation
            if ($hardened) {
                // Hardened: data = 0x00 || ser256(privateKey) || ser32(index)
                $privateKey = str_pad($this->getPrivateKey(), 64, '0', STR_PAD_LEFT);
                if (! ctype_xdigit($privateKey)) {
                    throw new \InvalidArgumentException('Invalid private key format');
                }
                $data = "\x00" . hex2bin($privateKey);
            } else {
                // Normal: data = serP(publicKey) || ser32(index)
                $publicKey = $this->getCompressedPublicKey();
                if (! ctype_xdigit($publicKey)) {
                    throw new \InvalidArgumentException('Invalid public key format');
                }
                $data = hex2bin($publicKey);
            }
            $data .= $this->intToBytes($index, 4);

            // Derive key and chain code
            [$derivedKey, $chainCode] = $this->deriveHmac($data);

            // Convert derived key to integer (mod n)
            $curve = new EC('secp256k1');
            $n = $curve->n;

            $factor = $this->parseIntFromBytes($derivedKey);
            $privateKey = $this->getPrivateKey();

            // ki = (parse256(IL) + kpar) mod n
            $childPrivateKey = gmp_strval(
                gmp_mod(
                    gmp_add(
                        gmp_init($factor, 10),
                        gmp_init($privateKey, 16)
                    ),
                    gmp_init($n->toString(), 10)
                ),
                16
            );

            // Ensure private key is 64 characters (32 bytes) long
            $childPrivateKey = str_pad($childPrivateKey, 64, '0', STR_PAD_LEFT);

            return new self($childPrivateKey, bin2hex($chainCode));
        } catch (\Throwable $e) {
            throw new \InvalidArgumentException('Failed to derive child key: ' . $e->getMessage());
        }
    }

    /**
     * {@inheritdoc}
     */
    /**
     * {@inheritdoc}
     */
    public function derivePath(string $path): self
    {
        // Check for valid BIP44 path format for Ethereum
        // Accepts both m/44'/60'/0'/account/index and m/44'/60'/account'/0/index
        if (! preg_match('/^m\/44\'\/60\'\/(?:0\'\/[0-9]+|[0-9]+\'\/0)\/[0-9]+$/', $path)) {
            throw new \InvalidArgumentException('Invalid derivation path format. Must follow BIP44 for Ethereum');
        }

        return parent::derivePath($path);
    }

    public function sign(string $message): string
    {
        try {
            // Convert message to hex if it's not already
            if (! $this->isValidHex($message)) {
                $message = bin2hex($message);
            }

            // Normalize hex format
            $message = $this->normalizeHex($message);

            // Hash the message if it's not already a hash
            if (strlen($message) !== 64) {
                $message = Keccak::hash(hex2bin($message), 256);
            }

            $signature = $this->keyPair->sign($message, ['canonical' => true]);

            // Convert signature to Ethereum format
            $r = str_pad($signature->r->toString(16), 64, '0', STR_PAD_LEFT);
            $s = str_pad($signature->s->toString(16), 64, '0', STR_PAD_LEFT);
            $v = str_pad(dechex($signature->recoveryParam + 27), 2, '0', STR_PAD_LEFT);

            return '0x' . $r . $s . $v;
        } catch (\Throwable $e) {
            throw new \InvalidArgumentException('Failed to sign message: ' . $e->getMessage());
        }
    }

    /**
     * {@inheritdoc}
     */
    public function verify(string $message, string $signature): bool
    {
        try {
            // Normalize and validate signature
            $signature = $this->normalizeHex($signature);
            if (strlen($signature) !== 130 || ! $this->isValidHex($signature)) {
                return false;
            }

            // Split signature into r, s, v
            $r = substr($signature, 0, 64);
            $s = substr($signature, 64, 64);
            $v = hexdec(substr($signature, 128, 2));

            if (! $this->isValidHex($r) || ! $this->isValidHex($s)) {
                return false;
            }

            // Convert message to hex if it's not already
            if (! $this->isValidHex($message)) {
                $message = bin2hex($message);
            }

            // Normalize message format
            $message = $this->normalizeHex($message);

            // Hash the message if it's not already a hash
            if (strlen($message) !== 64) {
                $message = Keccak::hash(hex2bin($message), 256);
            }

            return $this->keyPair->verify($message, [
                'r' => $r,
                's' => $s,
                'v' => $v - 27,
            ]);
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * Convert an address to checksum format according to EIP-55
     *
     * @param string $address Hex address without 0x prefix
     * @return string Checksummed address with 0x prefix
     * @throws \InvalidArgumentException If address format is invalid
     */
    private function toChecksumAddress(string $address): string
    {
        if (! $this->isValidHex($address) || strlen($address) !== 40) {
            throw new \InvalidArgumentException('Invalid address format');
        }

        $address = strtolower($address);
        $hash = Keccak::hash($address, 256);

        $ret = '0x';
        for ($i = 0; $i < 40; $i++) {
            // If ith character is 9-f and ith hash character >= 8, uppercase it
            $ret .= hexdec($hash[$i]) >= 8 ? strtoupper($address[$i]) : $address[$i];
        }

        return $ret;
    }

    /**
     * Normalize a hex string by removing '0x' prefix and ensuring even length
     *
     * @param string $hex The hex string to normalize
     * @return string Normalized hex string
     */
    private function normalizeHex(string $hex): string
    {
        // Remove '0x' prefix if present
        $hex = preg_replace('/^0x/', '', $hex);

        // Ensure even length
        if (strlen($hex) % 2 !== 0) {
            $hex = '0' . $hex;
        }

        return $hex;
    }

    /**
     * Validate if a string is a valid hex string
     *
     * @param string $hex The hex string to validate
     * @return bool True if valid hex string
     */
    private function isValidHex(string $hex): bool
    {
        return ctype_xdigit($this->normalizeHex($hex));
    }
}
