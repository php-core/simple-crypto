# BIP39 Wordlists

This directory contains the wordlists used for BIP39 mnemonic phrase generation. Each wordlist follows the official BIP39 specification.

## File Format Requirements

1. File naming:
   - Lowercase language name: `english.txt`, `spanish.txt`, etc.
   - UTF-8 encoded text files
   - Unix line endings (LF, not CRLF)

2. Content requirements:
   - Exactly 2048 words
   - One word per line
   - No empty lines
   - No leading/trailing whitespace
   - Words must be in alphabetical order
   - No duplicate words
   - All words must be unique in the first 4 characters (for early unique identification)

3. Word requirements:
   - Lowercase letters only
   - No special characters
   - No numbers
   - No spaces within words
   - No accents or diacritical marks

## Verification

To verify a wordlist:
1. Must contain exactly 2048 lines
2. Each line must be unique
3. Lines must be in alphabetical order
4. First 4 characters of each word must be unique within the list
5. No empty lines or whitespace-only lines
6. No leading/trailing whitespace on any line

## Official Wordlists

The following languages are officially supported:
- English (english.txt) - The reference wordlist
- Japanese (japanese.txt)
- Korean (korean.txt)
- Spanish (spanish.txt)
- Chinese Simplified (chinese_simplified.txt)
- Chinese Traditional (chinese_traditional.txt)
- French (french.txt)
- Italian (italian.txt)
- Czech (czech.txt)
- Portuguese (portuguese.txt)

## Usage

These wordlists are used by the BIP39Mnemonic class to generate and validate mnemonic phrases. The English wordlist is required, while other language files are optional.

## Example Usage

```php
// Generate a 12-word mnemonic in English
$mnemonic = new BIP39Mnemonic();
$phrase = $mnemonic->generate(12, 'english');

// Generate a 24-word mnemonic in Spanish
$phrase = $mnemonic->generate(24, 'spanish');
```

## Adding New Languages

To add a new language:
1. Create a new file named `{language}.txt`
2. Add exactly 2048 words following the format requirements
3. Update the VALID_LANGUAGES constant in AbstractMnemonic class
4. Add appropriate tests for the new language

## Source

The original wordlists are sourced from the official BIP39 specification and implementations:
https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md