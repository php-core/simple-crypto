<?php

declare(strict_types=1);

namespace PHPCore\SimpleCrypto\Wallet\KeyPair;

use Elliptic\EC;
use StephenHill\Base58;

final class BTCKeyPair extends AbstractKeyPair
{
    private const ADDRESS_TYPE_LEGACY = 'legacy';
    private const ADDRESS_TYPE_SEGWIT = 'segwit';
    private const ADDRESS_TYPE_NATIVE_SEGWIT = 'native_segwit';
    private const ADDRESS_TYPE_TAPROOT = 'taproot';

    /**
     * Get the Bitcoin address for this key pair
     *
     * @param string $type Address type: 'legacy', 'segwit', 'native_segwit', or 'taproot'
     * @return string The Bitcoin address
     * @throws \InvalidArgumentException If address type is invalid
     */
    public function getAddress(string $type = self::ADDRESS_TYPE_NATIVE_SEGWIT): string
    {
        try {
            // Always use compressed public key format
            $pubKey = $this->keyPair->getPublic(true, 'hex');
            if (strlen($pubKey) !== 66) {
                throw new \InvalidArgumentException('Invalid public key format');
            }

            // Hash the public key: RIPEMD160(SHA256(pubkey))
            $sha256 = hash('sha256', hex2bin($pubKey), true);
            $ripemd160 = hash('ripemd160', $sha256, true);

            switch ($type) {
                case self::ADDRESS_TYPE_LEGACY:
                    // Legacy address (P2PKH)
                    $version = "\x00"; // Mainnet
                    $hash = $version . $ripemd160;
                    $checksum = substr(hash('sha256', hash('sha256', $hash, true), true), 0, 4);

                    return (new Base58())->encode($hash . $checksum);

                case self::ADDRESS_TYPE_SEGWIT:
                    // P2SH-wrapped SegWit
                    $version = "\x05"; // Mainnet P2SH
                    $redeemScript = "\x00\x14" . $ripemd160;
                    $scriptHash = hash('ripemd160', hash('sha256', $redeemScript, true), true);
                    $hash = $version . $scriptHash;
                    $checksum = substr(hash('sha256', hash('sha256', $hash, true), true), 0, 4);

                    return (new Base58())->encode($hash . $checksum);

                case self::ADDRESS_TYPE_NATIVE_SEGWIT:
                    // Native SegWit (bech32)
                    $program = array_values(unpack('C*', $ripemd160));

                    return $this->encodeBech32('bc', 0, $program);

                case self::ADDRESS_TYPE_TAPROOT:
                    throw new \InvalidArgumentException('Taproot addresses not yet implemented');

                default:
                    throw new \InvalidArgumentException('Invalid address type');
            }
        } catch (\Throwable $e) {
            throw new \InvalidArgumentException('Failed to generate address: ' . $e->getMessage());
        }
    }

    /**
     * Encode a bech32 address
     */
    private function encodeBech32(string $hrp, int $version, array $program): string
    {
        $values = array_merge([$version], $this->convertBits($program, 8, 5, true));

        return $this->bech32Encode($hrp, $values);
    }

    /**
     * Convert bits from one base to another
     */
    private function convertBits(array $data, int $fromBits, int $toBits, bool $pad = true): array
    {
        $acc = 0;
        $bits = 0;
        $ret = [];
        $maxv = (1 << $toBits) - 1;

        foreach ($data as $value) {
            $acc = ($acc << $fromBits) | $value;
            $bits += $fromBits;
            while ($bits >= $toBits) {
                $bits -= $toBits;
                $ret[] = ($acc >> $bits) & $maxv;
            }
        }

        if ($pad && $bits > 0) {
            $ret[] = ($acc << ($toBits - $bits)) & $maxv;
        }

        return $ret;
    }

    /**
     * Encode a bech32 string
     */
    private function bech32Encode(string $hrp, array $values): string
    {
        $CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
        $chk = 1;
        $data = [];

        // Convert human-readable part
        for ($i = 0; $i < strlen($hrp); $i++) {
            $c = ord($hrp[$i]);
            if ($c < 33 || $c > 126) {
                throw new \InvalidArgumentException('Invalid character in hrp');
            }
            $chk = $this->bech32Polymod($chk) ^ ($c >> 5);
            $data[] = $c & 0x1f;
        }

        $chk = $this->bech32Polymod($chk);
        for ($i = 0; $i < strlen($hrp); $i++) {
            $chk = $this->bech32Polymod($chk) ^ (ord($hrp[$i]) & 0x1f);
        }

        // Convert data values to bech32 characters
        foreach ($values as $v) {
            $chk = $this->bech32Polymod($chk) ^ $v;
            $data[] = $v;
        }

        // Compute checksum
        for ($i = 0; $i < 6; $i++) {
            $chk = $this->bech32Polymod($chk);
        }
        $chk ^= 1;

        // Convert checksum to characters
        for ($i = 0; $i < 6; $i++) {
            $data[] = ($chk >> ((5 - $i) * 5)) & 0x1f;
        }

        // Convert data to characters
        $ret = $hrp . '1';
        foreach ($data as $d) {
            $ret .= $CHARSET[$d];
        }

        return $ret;
    }

    /**
     * Calculate bech32 checksum
     */
    private function bech32Polymod(int $x): int
    {
        return (($x & 0x1ffffff) << 5)
            ^ (($x >> 25) & 0x1f ? 0x3b6a57b2 : 0)
            ^ (($x >> 26) & 0x1f ? 0x26508e6d : 0)
            ^ (($x >> 27) & 0x1f ? 0x1ea119fa : 0)
            ^ (($x >> 28) & 0x1f ? 0x3d4233dd : 0)
            ^ (($x >> 29) & 0x1f ? 0x2a1462b3 : 0);
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

            // Get parent key data
            $parentPrivateKey = $this->getPrivateKey();
            $parentPublicKey = $this->keyPair->getPublic(true, 'hex');

            // Prepare data for derivation
            if ($hardened) {
                // Hardened: data = 0x00 || ser256(parentKey) || ser32(i)
                $data = "\x00" . hex2bin(str_pad($parentPrivateKey, 64, '0', STR_PAD_LEFT));
            } else {
                // Normal: data = serP(parentPubKey) || ser32(i)
                $data = hex2bin($parentPublicKey);
            }
            $data .= $this->intToBytes($index, 4);

            // Derive child key
            [$derivedKey, $chainCode] = $this->deriveHmac($data);

            // Convert to scalar and add to parent private key
            $curve = new EC('secp256k1');
            $n = $curve->n;

            $factor = $this->parseIntFromBytes($derivedKey);
            $childKey = gmp_strval(
                gmp_mod(
                    gmp_add(
                        gmp_init($factor, 10),
                        gmp_init($parentPrivateKey, 16)
                    ),
                    gmp_init($n->toString(), 10)
                ),
                16
            );

            return new self($childKey, bin2hex($chainCode));
        } catch (\Throwable $e) {
            throw new \InvalidArgumentException('Failed to derive child key: ' . $e->getMessage());
        }
    }

    /**
     * {@inheritdoc}
     */
    public function derivePath(string $path): self
    {
        // Check for valid BIP44 path format for Bitcoin
        // m/44'/0'/0'/0/index or m/84'/0'/0'/0/index for native segwit
        if (! preg_match('/^m\/(?:44|84)\'\/0\'\/[0-9]+\'\/[0-9]+\/[0-9]+$/', $path)) {
            throw new \InvalidArgumentException('Invalid derivation path format. Must follow BIP44/84 for Bitcoin');
        }

        return parent::derivePath($path);
    }

    /**
     * Sign a message with the private key
     *
     * @param string $message The message to sign
     * @return string The signature
     * @throws \InvalidArgumentException If signing fails
     */
    /**
     * Sign a message using ECDSA
     *
     * @param string $message The message to sign
     * @return string The signature in hex format
     * @throws \InvalidArgumentException If signing fails
     */
    public function sign(string $message): string
    {
        try {
            // Hash the message with double SHA256
            $hash = hash('sha256', hash('sha256', $message, true), true);

            // Sign using the elliptic curve key pair
            $hashHex = bin2hex($hash);
            $sig = $this->keyPair->sign($hashHex);

            // Get signature values
            $signature = '';
            $signature .= "\x30"; // Sequence

            // Build r and s
            $r = $sig->r->toString(16);
            $s = $sig->s->toString(16);

            // Ensure even length
            if (strlen($r) % 2) {
                $r = '0' . $r;
            }
            if (strlen($s) % 2) {
                $s = '0' . $s;
            }

            // Convert to binary
            $r = hex2bin($r);
            $s = hex2bin($s);

            // Add length markers
            $signature .= chr(4 + strlen($r) + strlen($s)); // Total length
            $signature .= "\x02"; // Integer marker
            $signature .= chr(strlen($r)); // r length
            $signature .= $r;
            $signature .= "\x02"; // Integer marker
            $signature .= chr(strlen($s)); // s length
            $signature .= $s;

            return bin2hex($signature);
        } catch (\Throwable $e) {
            throw new \InvalidArgumentException('Failed to sign message: ' . $e->getMessage());
        }
    }

    /**
     * Verify a signature
     *
     * @param string $message The original message
     * @param string $signature The signature in DER format (hex)
     * @return bool True if signature is valid
     */
    public function verify(string $message, string $signature): bool
    {
        try {
            // Hash the message with double SHA256
            $hash = hash('sha256', hash('sha256', $message, true), true);
            $hashHex = bin2hex($hash);

            // Validate and decode DER signature
            if (! ctype_xdigit($signature)) {
                return false;
            }
            $der = @hex2bin($signature);
            if ($der === false) {
                return false;
            }

            $pos = 0;
            if (strlen($der) < 2) {
                return false;
            }

            // Check sequence
            if (ord($der[$pos++]) !== 0x30) {
                return false;
            }

            // Get total length
            $len = ord($der[$pos++]);
            if ($len + 2 !== strlen($der)) {
                return false;
            }

            // Get r
            if (ord($der[$pos++]) !== 0x02) {
                return false;
            }
            $rLen = ord($der[$pos++]);
            $r = bin2hex(substr($der, $pos, $rLen));
            $pos += $rLen;

            // Get s
            if (ord($der[$pos++]) !== 0x02) {
                return false;
            }
            $sLen = ord($der[$pos++]);
            $s = bin2hex(substr($der, $pos, $sLen));

            // Verify
            return $this->keyPair->verify($hashHex, ['r' => $r, 's' => $s]);
        } catch (\Throwable $e) {
            return false;
        }
    }
}
