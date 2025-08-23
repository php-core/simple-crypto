<?php

declare(strict_types=1);

namespace PHPCore\SimpleCrypto\Tests\Wallet\Mnemonic;

use PHPCore\SimpleCrypto\Tests\TestCase;
use PHPCore\SimpleCrypto\Wallet\Mnemonic\AbstractMnemonic;
use PHPCore\SimpleCrypto\Wallet\Mnemonic\BIP39Mnemonic;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(BIP39Mnemonic::class)]
#[CoversClass(AbstractMnemonic::class)]
final class BIP39MnemonicTest extends TestCase
{
    private BIP39Mnemonic $mnemonic;

    protected function setUp(): void
    {
        parent::setUp();
        $this->mnemonic = new BIP39Mnemonic();
    }

    /**
     * @return array<string, array{entropy: string, mnemonic: string, seed: string}>
     */
    public static function bip39TestVectorProvider(): array
    {
        return [
            'test_vector_1' => [
                'entropy' => '00000000000000000000000000000000',
                'mnemonic' => 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
                'seed' => '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4',
            ],
            'test_vector_2' => [
                'entropy' => '7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f',
                'mnemonic' => 'legal winner thank year wave sausage worth useful legal winner thank yellow',
                'seed' => '878386efb78845b3355bd15ea4d39ef97d179cb712b77d5c12b6be415fffeffe5f377ba02bf3f8544ab800b955e51fbff09828f682052a20faa6addbbddfb096',
            ],
        ];
    }

    #[Test]
    public function generateCreatesValidMnemonic(): void
    {
        $phrase = $this->mnemonic->generate();

        $this->assertIsString($phrase);
        $this->assertCount(12, explode(' ', $phrase));
        $this->assertTrue($this->mnemonic->validate($phrase));
    }

    #[Test]
    public function generateWithCustomWordCount(): void
    {
        $wordCounts = [12, 15, 18, 21, 24];

        foreach ($wordCounts as $count) {
            $phrase = $this->mnemonic->generate($count);
            $this->assertCount($count, explode(' ', $phrase));
            $this->assertTrue($this->mnemonic->validate($phrase));
        }
    }

    #[Test]
    public function invalidWordCountThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->mnemonic->generate(13);
    }

    #[Test]
    #[DataProvider('bip39TestVectorProvider')]
    public function entropyToMnemonic(string $entropy, string $mnemonic, string $_): void
    {
        $generated = $this->mnemonic->entropyToMnemonic($entropy);
        $this->assertSame($mnemonic, $generated);
    }

    #[Test]
    public function invalidEntropyLengthThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->mnemonic->entropyToMnemonic('0000');
    }

    #[Test]
    public function invalidEntropyHexThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->mnemonic->entropyToMnemonic('Invalid hex string here...');
    }

    #[Test]
    #[DataProvider('bip39TestVectorProvider')]
    public function mnemonicToEntropy(string $entropy, string $mnemonic, string $_): void
    {
        $generated = $this->mnemonic->mnemonicToEntropy($mnemonic);
        $this->assertSame($entropy, $generated);
    }

    #[Test]
    public function invalidMnemonicToEntropyThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->mnemonic->mnemonicToEntropy('invalid mnemonic phrase here');
    }

    #[Test]
    #[DataProvider('bip39TestVectorProvider')]
    public function toSeed(string $_, string $mnemonic, string $expectedSeed): void
    {
        $seed = $this->mnemonic->toSeed($mnemonic);
        $this->assertSame($expectedSeed, $seed);
    }

    #[Test]
    public function toSeedWithPassphrase(): void
    {
        $mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
        $passphrase = 'TREZOR';
        $expectedSeed = 'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04';

        $seed = $this->mnemonic->toSeed($mnemonic, $passphrase);
        $this->assertSame($expectedSeed, $seed);
    }

    #[Test]
    public function validateReturnsTrueForValidMnemonic(): void
    {
        $mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
        $this->assertTrue($this->mnemonic->validate($mnemonic));
    }

    #[Test]
    public function validateReturnsFalseForInvalidMnemonic(): void
    {
        $invalidMnemonics = [
            'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon',
            'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invalid',
            'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon',
            'not a valid mnemonic phrase at all',
            '',
        ];

        foreach ($invalidMnemonics as $mnemonic) {
            $this->assertFalse($this->mnemonic->validate($mnemonic));
        }
    }

    #[Test]
    public function unsupportedLanguageThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->mnemonic->generate(12, 'unsupported');
    }

    #[Test]
    public function testWordlistLoading(): void
    {
        $phrase = $this->mnemonic->generate();
        $this->assertTrue($this->mnemonic->validate($phrase));

        // Test wordlist caching by generating another phrase
        $phrase2 = $this->mnemonic->generate();
        $this->assertTrue($this->mnemonic->validate($phrase2));
    }

    #[Test]
    public function testAllValidWordCounts(): void
    {
        foreach ([128, 160, 192, 224, 256] as $entropyBits) {
            $wordCount = ($entropyBits + ($entropyBits / 32)) / 11;
            $entropy = str_repeat('00', $entropyBits / 8);
            $mnemonic = $this->mnemonic->entropyToMnemonic($entropy);
            $this->assertCount($wordCount, explode(' ', $mnemonic));
        }
    }

    #[Test]
    public function testEntropyGeneration(): void
    {
        // Generate multiple phrases and verify they're different
        $phrases = [];
        for ($i = 0; $i < 5; $i++) {
            $phrase = $this->mnemonic->generate();
            $this->assertNotContains($phrase, $phrases, 'Generated duplicate mnemonic');
            $phrases[] = $phrase;
        }
    }
}
