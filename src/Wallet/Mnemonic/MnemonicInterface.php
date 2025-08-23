<?php

declare(strict_types=1);

namespace PHPCore\SimpleCrypto\Wallet\Mnemonic;

interface MnemonicInterface
{
    /**
     * Generate a new mnemonic phrase with the specified word count
     *
     * @param int $wordCount Number of words (12, 15, 18, 21, or 24)
     * @param string $language Language for the wordlist (default: 'english')
     * @return string The generated mnemonic phrase
     * @throws \InvalidArgumentException If word count is invalid
     */
    public function generate(int $wordCount = 12, string $language = 'english'): string;

    /**
     * Validate a mnemonic phrase
     *
     * @param string $mnemonic The mnemonic phrase to validate
     * @param string $language Language of the wordlist (default: 'english')
     * @return bool True if valid, false otherwise
     */
    public function validate(string $mnemonic, string $language = 'english'): bool;

    /**
     * Convert mnemonic to seed
     *
     * @param string $mnemonic The mnemonic phrase
     * @param string $passphrase Optional passphrase (default: '')
     * @return string The generated seed (hex encoded)
     * @throws \InvalidArgumentException If mnemonic is invalid
     */
    public function toSeed(string $mnemonic, string $passphrase = ''): string;

    /**
     * Convert entropy to mnemonic
     *
     * @param string $entropy Hex encoded entropy
     * @param string $language Language for the wordlist (default: 'english')
     * @return string The generated mnemonic phrase
     * @throws \InvalidArgumentException If entropy is invalid
     */
    public function entropyToMnemonic(string $entropy, string $language = 'english'): string;

    /**
     * Convert mnemonic to entropy
     *
     * @param string $mnemonic The mnemonic phrase
     * @param string $language Language of the wordlist (default: 'english')
     * @return string Hex encoded entropy
     * @throws \InvalidArgumentException If mnemonic is invalid
     */
    public function mnemonicToEntropy(string $mnemonic, string $language = 'english'): string;
}
