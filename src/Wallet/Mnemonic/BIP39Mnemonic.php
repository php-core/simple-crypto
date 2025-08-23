<?php

declare(strict_types=1);

namespace PHPCore\SimpleCrypto\Wallet\Mnemonic;

final class BIP39Mnemonic extends AbstractMnemonic
{
    /**
     * {@inheritdoc}
     */
    public function generate(int $wordCount = 12, string $language = 'english'): string
    {
        if (! in_array($wordCount, self::VALID_WORD_COUNTS, true)) {
            throw new \InvalidArgumentException(
                "Invalid word count. Must be one of: " . implode(', ', self::VALID_WORD_COUNTS)
            );
        }

        // Calculate required entropy bytes (ENT) based on word count (MS)
        // MS = ENT + (ENT/32)
        // For 12 words: MS = 132 bits, ENT = 128 bits = 16 bytes
        $entropyBytes = ($wordCount * 11 - $wordCount * 11 / 33) / 8;

        // Generate random entropy
        $entropy = random_bytes((int) $entropyBytes);

        return $this->entropyToMnemonic(bin2hex($entropy), $language);
    }

    /**
     * {@inheritdoc}
     */
    public function entropyToMnemonic(string $entropy, string $language = 'english'): string
    {
        if (! ctype_xdigit($entropy) || ! $this->isValidEntropyLength($entropy)) {
            throw new \InvalidArgumentException('Invalid entropy - must be valid hex with appropriate length');
        }

        // Calculate checksum and append to entropy
        $checksumBits = $this->calculateChecksum($entropy);

        // Convert entropy to binary
        $entropyBits = implode('', array_map(
            fn ($byte) => str_pad(decbin(hexdec($byte)), 8, '0', STR_PAD_LEFT),
            str_split($entropy, 2)
        ));

        // Combine entropy bits with checksum bits
        $bits = $entropyBits . $checksumBits;

        // Convert bits to words
        return $this->bitsToWords($bits, $language);
    }

    /**
     * {@inheritdoc}
     */
    public function mnemonicToEntropy(string $mnemonic, string $language = 'english'): string
    {
        $words = explode(' ', $mnemonic);
        $wordCount = count($words);

        if (! in_array($wordCount, self::VALID_WORD_COUNTS, true)) {
            throw new \InvalidArgumentException(
                "Invalid word count. Must be one of: " . implode(', ', self::VALID_WORD_COUNTS)
            );
        }

        // Convert words to bits
        $bits = $this->wordsToBits($mnemonic, $language);

        // Split bits into entropy and checksum
        $checksumLength = $wordCount / 3; // One checksum bit for every 32 bits of entropy
        $entropyLength = strlen($bits) - $checksumLength;
        $entropyBits = substr($bits, 0, $entropyLength);
        $checksumBits = substr($bits, $entropyLength);

        // Convert entropy bits to hex
        $entropy = '';
        for ($i = 0; $i < strlen($entropyBits); $i += 8) {
            $entropy .= str_pad(
                dechex(bindec(substr($entropyBits, $i, 8))),
                2,
                '0',
                STR_PAD_LEFT
            );
        }

        // Verify checksum
        if ($checksumBits !== $this->calculateChecksum($entropy)) {
            throw new \InvalidArgumentException('Invalid mnemonic - checksum verification failed');
        }

        return $entropy;
    }
}
