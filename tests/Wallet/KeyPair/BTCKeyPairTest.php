<?php

declare(strict_types=1);

namespace PHPCore\SimpleCrypto\Tests\Wallet\KeyPair;

use PHPCore\SimpleCrypto\Tests\TestCase;
use PHPCore\SimpleCrypto\Wallet\KeyPair\BTCKeyPair;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(BTCKeyPair::class)]
final class BTCKeyPairTest extends TestCase
{
    /**
     * @return array<string, array{privateKey: string, chainCode: string, legacy: string, segwit: string, nativeSegwit: string}>
     */
    public static function keyTestVectorProvider(): array
    {
        return [
            'test_vector_1' => [
                'privateKey' => 'e77c3c21dd798c48e632be06fd946521e5844ba6804f872fbe12d2c0faf653c2',
                'chainCode' => '7923408dadd3c7b56eed15567707ae5e5dca089de972e07f3b860450e2a3b70e',
                'legacy' => '1DQ2SrMPXfTz9VvqMNXe4khri3hM9TVJ8z',
                'segwit' => '3GZ1GUcRWqf3cP7GaD4WXfCkQRgVZQ8VUF',
                'nativeSegwit' => 'bc1zrqsl7y3z8uzwzw24p4p6lnpn9el6lrkzr04knrj2',
            ],
        ];
    }

    /**
     * @return array<string, array{seed: string, path: string, address: string}>
     */
    public static function derivationTestVectorProvider(): array
    {
        return [
            'test_vector_1' => [
                'seed' => '000102030405060708090a0b0c0d0e0f',
                'path' => "m/44'/0'/0'/0/0", // Using BIP44 path for consistency
                'address' => 'bc1zrqatd6clekcdlrjds3dzm64m3ukf9z2vfdndmtp2',
            ],
        ];
    }

    #[Test]
    #[DataProvider('keyTestVectorProvider')]
    public function addressGeneration(
        string $privateKey,
        string $chainCode,
        string $expectedLegacy,
        string $expectedSegwit,
        string $expectedNativeSegwit
    ): void {
        $keyPair = new BTCKeyPair($privateKey, $chainCode);

        $this->assertSame($expectedLegacy, $keyPair->getAddress('legacy'));
        $this->assertSame($expectedSegwit, $keyPair->getAddress('segwit'));
        $this->assertSame($expectedNativeSegwit, $keyPair->getAddress('native_segwit'));
    }

    #[Test]
    public function invalidPrivateKeyFormat(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new BTCKeyPair('invalid hex', '7923408dadd3c7b56eed15567707ae5e5dca089de972e07f3b860450e2a3b70e');
    }

    #[Test]
    public function fromSeed(): void
    {
        $seed = '000102030405060708090a0b0c0d0e0f';
        $keyPair = BTCKeyPair::fromSeed($seed);

        $this->assertInstanceOf(BTCKeyPair::class, $keyPair);
        $this->assertNotEmpty($keyPair->getPrivateKey());
        $this->assertNotEmpty($keyPair->getPublicKey());

        // Test all address types
        $this->assertMatchesRegularExpression('/^1[1-9A-HJ-NP-Za-km-z]{25,34}$/', $keyPair->getAddress('legacy'));
        $this->assertMatchesRegularExpression('/^3[1-9A-HJ-NP-Za-km-z]{25,34}$/', $keyPair->getAddress('segwit'));
        $this->assertMatchesRegularExpression('/^bc1[a-zA-Z0-9]{8,87}$/', $keyPair->getAddress('native_segwit'));
    }

    #[Test]
    public function invalidSeedFormat(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        BTCKeyPair::fromSeed('invalid seed');
    }

    #[Test]
    #[DataProvider('derivationTestVectorProvider')]
    public function derivePath(string $seed, string $path, string $expectedAddress): void
    {
        $master = BTCKeyPair::fromSeed($seed);
        $derived = $master->derivePath($path);

        $this->assertSame($expectedAddress, $derived->getAddress('native_segwit'));
    }

    #[Test]
    public function signAndVerifyMessage(): void
    {
        $keyPair = new BTCKeyPair(
            'e77c3c21dd798c48e632be06fd946521e5844ba6804f872fbe12d2c0faf653c2',
            '7923408dadd3c7b56eed15567707ae5e5dca089de972e07f3b860450e2a3b70e'
        );

        $message = 'Hello, Bitcoin!';
        $signature = $keyPair->sign($message);

        $this->assertTrue($keyPair->verify($message, $signature));
    }

    #[Test]
    public function invalidSignature(): void
    {
        $keyPair = new BTCKeyPair(
            'e77c3c21dd798c48e632be06fd946521e5844ba6804f872fbe12d2c0faf653c2',
            '7923408dadd3c7b56eed15567707ae5e5dca089de972e07f3b860450e2a3b70e'
        );

        $message = 'Hello, Bitcoin!';

        $this->assertFalse($keyPair->verify($message, 'invalid signature'));
        $this->assertFalse($keyPair->verify('Different message', $keyPair->sign($message)));
    }

    #[Test]
    public function multipleDerivationsProduceDifferentAddresses(): void
    {
        $master = BTCKeyPair::fromSeed('000102030405060708090a0b0c0d0e0f');
        $addresses = [];

        // Generate multiple addresses and verify they're all different
        for ($i = 0; $i < 5; $i++) {
            $path = "m/84'/0'/0'/0/{$i}";
            $child = $master->derivePath($path);
            $address = $child->getAddress('native_segwit');

            $this->assertNotContains($address, $addresses);
            $addresses[] = $address;
        }
    }
}
