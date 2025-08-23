<?php

declare(strict_types=1);

namespace PHPCore\SimpleCrypto\Wallet\Mnemonic;

abstract class AbstractMnemonic implements MnemonicInterface
{
    /**
     * @var array<int> Valid word counts for mnemonic phrases
     */
    protected const VALID_WORD_COUNTS = [12, 15, 18, 21, 24];

    /**
     * @var array<string> Valid languages for wordlists
     */
    protected const VALID_LANGUAGES = ['english']; // We'll add more languages later

    /**
     * @var array<string, array<string>> Wordlists cache
     */
    protected array $wordlists = [];

    /**
     * Get the wordlist for a specific language
     *
     * @param string $language Language of the wordlist
     * @return array<string> Array of words
     * @throws \InvalidArgumentException If language is not supported
     */
    protected function getWordlist(string $language): array
    {
        if (! in_array($language, self::VALID_LANGUAGES, true)) {
            throw new \InvalidArgumentException("Language '{$language}' is not supported");
        }

        if (! isset($this->wordlists[$language])) {
            $wordlistPath = __DIR__ . "/wordlists/{$language}.txt";
            if (! file_exists($wordlistPath)) {
                throw new \RuntimeException("Wordlist file for language '{$language}' not found");
            }
            $this->wordlists[$language] = array_filter(explode("\n", file_get_contents($wordlistPath)));
        }

        return $this->wordlists[$language];
    }

    /**
     * Validate entropy length
     *
     * @param string $entropy Hex encoded entropy
     * @return bool True if valid, false otherwise
     */
    protected function isValidEntropyLength(string $entropy): bool
    {
        $length = strlen($entropy) * 4; // Convert hex length to bit length

        return $length >= 128 && $length <= 256 && $length % 32 === 0;
    }

    /**
     * Calculate checksum bits
     *
     * @param string $entropy Hex encoded entropy
     * @return string Binary checksum
     */
    protected function calculateChecksum(string $entropy): string
    {
        $checksumLength = strlen($entropy) * 4 / 32; // Get number of checksum bits
        $hash = hash('sha256', hex2bin($entropy), true);
        $hashBits = str_pad(implode('', array_map(function ($byte) {
            return str_pad(decbin(ord($byte)), 8, '0', STR_PAD_LEFT);
        }, str_split($hash))), 256, '0', STR_PAD_LEFT);

        return substr($hashBits, 0, $checksumLength);
    }

    /**
     * Convert bits to words
     *
     * @param string $bits Binary string
     * @param string $language Language for the wordlist
     * @return string Space-separated mnemonic words
     */
    protected function bitsToWords(string $bits, string $language): string
    {
        $wordlist = $this->getWordlist($language);
        $words = [];

        // Split bits into 11-bit chunks and convert to words
        for ($i = 0; $i < strlen($bits); $i += 11) {
            $index = bindec(substr($bits, $i, 11));
            $words[] = $wordlist[$index];
        }

        return implode(' ', $words);
    }

    /**
     * Convert words to bits
     *
     * @param string $mnemonic Space-separated mnemonic words
     * @param string $language Language of the wordlist
     * @return string Binary string
     * @throws \InvalidArgumentException If word is not in wordlist
     */
    protected function wordsToBits(string $mnemonic, string $language): string
    {
        $wordlist = $this->getWordlist($language);
        $words = explode(' ', $mnemonic);
        $bits = '';

        foreach ($words as $word) {
            $index = array_search($word, $wordlist, true);
            if ($index === false) {
                throw new \InvalidArgumentException("Word '{$word}' is not in the wordlist");
            }
            $bits .= str_pad(decbin($index), 11, '0', STR_PAD_LEFT);
        }

        return $bits;
    }

    /**
     * {@inheritdoc}
     */
    public function validate(string $mnemonic, string $language = 'english'): bool
    {
        try {
            $entropy = $this->mnemonicToEntropy($mnemonic, $language);

            return $this->entropyToMnemonic($entropy, $language) === $mnemonic;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function toSeed(string $mnemonic, string $passphrase = ''): string
    {
        if (! $this->validate($mnemonic)) {
            throw new \InvalidArgumentException('Invalid mnemonic phrase');
        }

        $salt = 'mnemonic' . $passphrase;

        return bin2hex(hash_pbkdf2(
            'sha512',
            $mnemonic,
            $salt,
            2048,
            64,
            true
        ));
    }
}
