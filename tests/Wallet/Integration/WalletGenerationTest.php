<?php

declare(strict_types=1);

namespace PHPCore\SimpleCrypto\Tests\Wallet\Integration;

use PHPCore\SimpleCrypto\Tests\TestCase;
use PHPCore\SimpleCrypto\Wallet\KeyPair\EVMKeyPair;
use PHPCore\SimpleCrypto\Wallet\Mnemonic\BIP39Mnemonic;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Medium;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(BIP39Mnemonic::class)]
#[CoversClass(EVMKeyPair::class)]
#[Medium]
final class WalletGenerationTest extends TestCase
{
    private BIP39Mnemonic $mnemonic;

    protected function setUp(): void
    {
        parent::setUp();
        $this->mnemonic = new BIP39Mnemonic();
    }

    #[Test]
    public function completeWalletGenerationFlow(): void
    {
        // Generate mnemonic
        $phrase = $this->mnemonic->generate(12);
        $this->assertTrue($this->mnemonic->validate($phrase));

        // Convert to seed
        $seed = $this->mnemonic->toSeed($phrase);
        $this->assertNotEmpty($seed);

        // Create master key pair
        $master = EVMKeyPair::fromSeed($seed);
        $this->assertInstanceOf(EVMKeyPair::class, $master);

        // Derive multiple accounts
        for ($i = 0; $i < 5; $i++) {
            $path = "m/44'/60'/0'/0/{$i}";
            $account = $master->derivePath($path);

            $this->assertInstanceOf(EVMKeyPair::class, $account);
            $this->assertMatchesRegularExpression('/^0x[0-9a-fA-F]{40}$/', $account->getAddress());

            // Test signing and verification
            $message = "Test message for account {$i}";
            $signature = $account->sign($message);
            $this->assertTrue($account->verify($message, $signature));
        }
    }

    #[Test]
    public function walletRecoveryFromMnemonic(): void
    {
        // Known test vector
        $mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
        $expectedAddress = '0x9858EfFD232B4033E47d90003D41EC34EcaEda94';

        // Validate and convert to seed
        $this->assertTrue($this->mnemonic->validate($mnemonic));
        $seed = $this->mnemonic->toSeed($mnemonic);

        // Create wallet and derive first account
        $master = EVMKeyPair::fromSeed($seed);
        $account = $master->derivePath("m/44'/60'/0'/0/0");

        $this->assertSame($expectedAddress, $account->getAddress());
    }

    #[Test]
    public function multipleAccountsHaveUniqueAddresses(): void
    {
        $phrase = $this->mnemonic->generate(12);
        $seed = $this->mnemonic->toSeed($phrase);
        $master = EVMKeyPair::fromSeed($seed);

        $addresses = [];
        for ($i = 0; $i < 10; $i++) {
            $account = $master->derivePath("m/44'/60'/0'/0/{$i}");
            $address = $account->getAddress();

            $this->assertArrayNotHasKey($address, $addresses, 'Generated duplicate address');
            $addresses[$address] = true;
        }
    }

    #[Test]
    public function differentMnemonicsGenerateDifferentAddresses(): void
    {
        // Generate two different mnemonics
        $phrase1 = $this->mnemonic->generate(12);
        $phrase2 = $this->mnemonic->generate(12);
        $this->assertNotEquals($phrase1, $phrase2);

        // Create wallets
        $seed1 = $this->mnemonic->toSeed($phrase1);
        $seed2 = $this->mnemonic->toSeed($phrase2);

        $wallet1 = EVMKeyPair::fromSeed($seed1);
        $wallet2 = EVMKeyPair::fromSeed($seed2);

        // Compare addresses from same derivation path
        $path = "m/44'/60'/0'/0/0";
        $address1 = $wallet1->derivePath($path)->getAddress();
        $address2 = $wallet2->derivePath($path)->getAddress();

        $this->assertNotEquals($address1, $address2);
    }

    #[Test]
    public function passphraseAffectsGeneratedAddresses(): void
    {
        $mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

        // Generate seeds with different passphrases
        $seed1 = $this->mnemonic->toSeed($mnemonic, '');
        $seed2 = $this->mnemonic->toSeed($mnemonic, 'different passphrase');

        $wallet1 = EVMKeyPair::fromSeed($seed1);
        $wallet2 = EVMKeyPair::fromSeed($seed2);

        $path = "m/44'/60'/0'/0/0";
        $address1 = $wallet1->derivePath($path)->getAddress();
        $address2 = $wallet2->derivePath($path)->getAddress();

        $this->assertNotEquals($address1, $address2);
    }

    #[Test]
    public function largeBatchOfUniqueAddresses(): void
    {
        $phrase = $this->mnemonic->generate(24); // Use 24 words for more entropy
        $seed = $this->mnemonic->toSeed($phrase);
        $master = EVMKeyPair::fromSeed($seed);

        $addresses = [];
        // Test multiple accounts and indexes
        for ($account = 0; $account < 5; $account++) {
            for ($index = 0; $index < 20; $index++) {
                $path = "m/44'/60'/{$account}'/0/{$index}";
                $wallet = $master->derivePath($path);
                $address = $wallet->getAddress();

                $this->assertArrayNotHasKey(
                    $address,
                    $addresses,
                    "Generated duplicate address for path: {$path}"
                );
                $addresses[$address] = $path;
            }
        }

        $this->assertCount(100, $addresses, 'Failed to generate 100 unique addresses');
    }
}
