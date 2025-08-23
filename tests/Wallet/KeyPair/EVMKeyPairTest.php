<?php

declare(strict_types=1);

namespace PHPCore\SimpleCrypto\Tests\Wallet\KeyPair;

use PHPCore\SimpleCrypto\Tests\TestCase;
use PHPCore\SimpleCrypto\Wallet\KeyPair\EVMKeyPair;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(EVMKeyPair::class)]
final class EVMKeyPairTest extends TestCase
{
    /**
     * @return array<string, array{privateKey: string, chainCode: string, address: string}>
     */
    public static function keyTestVectorProvider(): array
    {
        return [
            'test_vector_1' => [
                'privateKey' => '0c1f67465719b8b644879372014792e573122fa21193f88095aec21df2e9b778',
                'chainCode' => '873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508',
                'address' => '0xcC5B3716e306Ac36087FE3d3e4db8B16cA1919F7',
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
                'path' => "m/44'/60'/0'/0/0",
                'address' => '0x022b971dFF0C43305e691DEd7a14367AF19D6407',
            ],
        ];
    }

    #[Test]
    #[DataProvider('keyTestVectorProvider')]
    public function addressGeneration(string $privateKey, string $chainCode, string $expectedAddress): void
    {
        $keyPair = new EVMKeyPair($privateKey, $chainCode);
        $this->assertSame($expectedAddress, $keyPair->getAddress());
    }

    #[Test]
    public function invalidPrivateKeyFormat(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new EVMKeyPair('invalid hex', '873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508');
    }

    #[Test]
    public function fromSeed(): void
    {
        $seed = '000102030405060708090a0b0c0d0e0f';
        $keyPair = EVMKeyPair::fromSeed($seed);

        $this->assertInstanceOf(EVMKeyPair::class, $keyPair);
        $this->assertNotEmpty($keyPair->getPrivateKey());
        $this->assertNotEmpty($keyPair->getPublicKey());
        $this->assertMatchesRegularExpression('/^0x[0-9a-fA-F]{40}$/', $keyPair->getAddress());
    }

    #[Test]
    public function invalidSeedFormat(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        EVMKeyPair::fromSeed('invalid seed');
    }

    #[Test]
    #[DataProvider('derivationTestVectorProvider')]
    public function derivePath(string $seed, string $path, string $expectedAddress): void
    {
        $master = EVMKeyPair::fromSeed($seed);
        $derived = $master->derivePath($path);

        $this->assertSame($expectedAddress, $derived->getAddress());
    }

    #[Test]
    public function signAndVerifyWithHexMessage(): void
    {
        $keyPair = new EVMKeyPair(
            '0c1f67465719b8b644879372014792e573122fa21193f88095aec21df2e9b778',
            '873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508'
        );

        $message = '0x68656c6c6f20776f726c64'; // "hello world" in hex
        $signature = $keyPair->sign($message);

        $this->assertTrue($keyPair->verify($message, $signature));
    }

    #[Test]
    public function signAndVerifyWithStringMessage(): void
    {
        $keyPair = new EVMKeyPair(
            '0c1f67465719b8b644879372014792e573122fa21193f88095aec21df2e9b778',
            '873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508'
        );

        $message = 'Hello, World!';
        $signature = $keyPair->sign($message);

        $this->assertTrue($keyPair->verify($message, $signature));
    }

    #[Test]
    public function verifyInvalidSignature(): void
    {
        $keyPair = new EVMKeyPair(
            '0c1f67465719b8b644879372014792e573122fa21193f88095aec21df2e9b778',
            '873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508'
        );

        $message = 'Hello, World!';

        // Test various invalid signatures
        $this->assertFalse($keyPair->verify($message, '0x' . str_repeat('00', 65)));
        $this->assertFalse($keyPair->verify($message, 'invalid signature'));
        $this->assertFalse($keyPair->verify($message, '0x123')); // Too short

        // Valid signature but wrong message
        $signature = $keyPair->sign($message);
        $this->assertFalse($keyPair->verify('Different message', $signature));
    }

    #[Test]
    public function deriveChild(): void
    {
        $master = EVMKeyPair::fromSeed('000102030405060708090a0b0c0d0e0f');

        // Test normal derivation
        $child1 = $master->deriveChild(0, false);
        $this->assertInstanceOf(EVMKeyPair::class, $child1);
        $this->assertNotSame($master->getPrivateKey(), $child1->getPrivateKey());

        // Test hardened derivation
        $child2 = $master->deriveChild(0, true);
        $this->assertInstanceOf(EVMKeyPair::class, $child2);
        $this->assertNotSame($child1->getPrivateKey(), $child2->getPrivateKey());

        // Test different indices
        $child3 = $master->deriveChild(1, false);
        $this->assertNotSame($child1->getPrivateKey(), $child3->getPrivateKey());
    }

    #[Test]
    public function invalidDerivationPath(): void
    {
        $master = EVMKeyPair::fromSeed('000102030405060708090a0b0c0d0e0f');

        $invalidPaths = [
            'invalid/path',
            'm/',
            'm/0/1/2',
            "m/44'/60'/0'/0/0/extra",
        ];

        foreach ($invalidPaths as $path) {
            try {
                $master->derivePath($path);
                $this->fail('Expected InvalidArgumentException for path: ' . $path);
            } catch (\InvalidArgumentException $e) {
                $this->addToAssertionCount(1);
            }
        }
    }

    #[Test]
    public function negativeIndexThrowsException(): void
    {
        $master = EVMKeyPair::fromSeed('000102030405060708090a0b0c0d0e0f');

        $this->expectException(\InvalidArgumentException::class);
        $master->deriveChild(-1);
    }

    #[Test]
    public function compressedPublicKey(): void
    {
        $keyPair = new EVMKeyPair(
            '0c1f67465719b8b644879372014792e573122fa21193f88095aec21df2e9b778',
            '873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508'
        );

        $compressed = $keyPair->getCompressedPublicKey();
        $this->assertIsString($compressed);
        $this->assertSame(66, strlen($compressed), 'Compressed public key should be 33 bytes (66 hex chars)');
        $prefix = substr($compressed, 0, 2);
        $this->assertTrue(in_array($prefix, ['02', '03']), 'Compressed public key should start with 02 or 03');
    }

    #[Test]
    public function multipleDerivationsProduceDifferentAddresses(): void
    {
        $master = EVMKeyPair::fromSeed('000102030405060708090a0b0c0d0e0f');
        $addresses = [];

        // Generate multiple addresses and verify they're all different
        for ($i = 0; $i < 5; $i++) {
            $child = $master->derivePath("m/44'/60'/0'/0/{$i}");
            $address = $child->getAddress();
            $this->assertNotContains($address, $addresses, 'Generated duplicate address');
            $addresses[] = $address;
        }
    }

    #[Test]
    public function longMessages(): void
    {
        $keyPair = new EVMKeyPair(
            '0c1f67465719b8b644879372014792e573122fa21193f88095aec21df2e9b778',
            '873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508'
        );

        $message = str_repeat('Long message content ', 100);
        $signature = $keyPair->sign($message);

        $this->assertTrue($keyPair->verify($message, $signature));
    }
}
