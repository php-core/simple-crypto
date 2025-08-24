<?php

namespace PHPCore\SimpleCrypto\Tests\NFT;

use PHPCore\SimpleCrypto\NFT\NFTMetadata;
use PHPCore\SimpleCrypto\Tests\TestCase;
use InvalidArgumentException;

class NFTMetadataTest extends TestCase
{
    private NFTMetadata $metadata;
    private string $name = 'Test NFT';
    private string $description = 'Test Description';
    private string $image = 'ipfs://QmTest123/image.png';
    private string $externalUrl = 'https://example.com';
    private string $animationUrl = 'ipfs://QmTest123/animation.mp4';

    protected function setUp(): void
    {
        parent::setUp();
        $this->metadata = new NFTMetadata(
            $this->name,
            $this->description,
            $this->image,
            [],
            $this->externalUrl,
            $this->animationUrl
        );
    }

    public function testConstructorAndGetters(): void
    {
        $this->assertEquals($this->name, $this->metadata->getName());
        $this->assertEquals($this->description, $this->metadata->getDescription());
        $this->assertEquals($this->image, $this->metadata->getImage());
        $this->assertEquals([], $this->metadata->getAttributes());
        $this->assertEquals($this->externalUrl, $this->metadata->getExternalUrl());
        $this->assertEquals($this->animationUrl, $this->metadata->getAnimationUrl());
    }

    public function testAddAttribute(): void
    {
        $this->metadata->addAttribute('Background', 'Blue');
        $this->metadata->addAttribute('Power Level', 95, 100);

        $attributes = $this->metadata->getAttributes();
        $this->assertCount(2, $attributes);

        $this->assertEquals([
            'trait_type' => 'Background',
            'value' => 'Blue'
        ], $attributes[0]);

        $this->assertEquals([
            'trait_type' => 'Power Level',
            'value' => 95,
            'max_value' => 100
        ], $attributes[1]);
    }

    public function testToArray(): void
    {
        $this->metadata->addAttribute('Test Trait', 'Test Value');

        $array = $this->metadata->toArray();

        $this->assertIsArray($array);
        $this->assertEquals($this->name, $array['name']);
        $this->assertEquals($this->description, $array['description']);
        $this->assertEquals($this->image, $array['image']);
        $this->assertEquals($this->externalUrl, $array['external_url']);
        $this->assertEquals($this->animationUrl, $array['animation_url']);
        $this->assertCount(1, $array['attributes']);
        $this->assertEquals('Test Trait', $array['attributes'][0]['trait_type']);
        $this->assertEquals('Test Value', $array['attributes'][0]['value']);
    }

    public function testToJson(): void
    {
        $this->metadata->addAttribute('Test Trait', 'Test Value');

        $json = $this->metadata->toJson();
        $decodedJson = json_decode($json, true);

        $this->assertJson($json);
        $this->assertEquals($this->name, $decodedJson['name']);
        $this->assertEquals($this->description, $decodedJson['description']);
        $this->assertEquals($this->image, $decodedJson['image']);
        $this->assertEquals($this->externalUrl, $decodedJson['external_url']);
        $this->assertEquals($this->animationUrl, $decodedJson['animation_url']);
    }

    public function testFromArray(): void
    {
        $data = [
            'name' => 'Test NFT',
            'description' => 'Test Description',
            'image' => 'ipfs://test.png',
            'attributes' => [
                [
                    'trait_type' => 'Test Trait',
                    'value' => 'Test Value'
                ]
            ],
            'external_url' => 'https://test.com',
            'animation_url' => 'ipfs://test.mp4'
        ];

        $metadata = NFTMetadata::fromArray($data);

        $this->assertEquals($data['name'], $metadata->getName());
        $this->assertEquals($data['description'], $metadata->getDescription());
        $this->assertEquals($data['image'], $metadata->getImage());
        $this->assertEquals($data['external_url'], $metadata->getExternalUrl());
        $this->assertEquals($data['animation_url'], $metadata->getAnimationUrl());
        $this->assertEquals($data['attributes'], $metadata->getAttributes());
    }

    public function testFromJson(): void
    {
        $data = [
            'name' => 'Test NFT',
            'description' => 'Test Description',
            'image' => 'ipfs://test.png',
            'attributes' => [
                [
                    'trait_type' => 'Test Trait',
                    'value' => 'Test Value'
                ]
            ],
            'external_url' => 'https://test.com',
            'animation_url' => 'ipfs://test.mp4'
        ];

        $json = json_encode($data);
        $metadata = NFTMetadata::fromJson($json);

        $this->assertEquals($data['name'], $metadata->getName());
        $this->assertEquals($data['description'], $metadata->getDescription());
        $this->assertEquals($data['image'], $metadata->getImage());
        $this->assertEquals($data['external_url'], $metadata->getExternalUrl());
        $this->assertEquals($data['animation_url'], $metadata->getAnimationUrl());
        $this->assertEquals($data['attributes'], $metadata->getAttributes());
    }

    public function testFromJsonWithInvalidJson(): void
    {
        $this->expectException(InvalidArgumentException::class);
        NFTMetadata::fromJson('invalid json');
    }

    public function testOptionalFields(): void
    {
        $metadata = new NFTMetadata(
            'Test NFT',
            'Test Description',
            'ipfs://test.png'
        );

        $array = $metadata->toArray();
        
        $this->assertArrayNotHasKey('external_url', $array);
        $this->assertArrayNotHasKey('animation_url', $array);
        $this->assertNull($metadata->getExternalUrl());
        $this->assertNull($metadata->getAnimationUrl());
    }

    public function testAttributeWithMaxValue(): void
    {
        $this->metadata->addAttribute('Power', 80, 100);
        $attributes = $this->metadata->getAttributes();

        $this->assertCount(1, $attributes);
        $this->assertEquals([
            'trait_type' => 'Power',
            'value' => 80,
            'max_value' => 100
        ], $attributes[0]);
    }

    public function testFluentInterface(): void
    {
        $result = $this->metadata
            ->addAttribute('Trait1', 'Value1')
            ->addAttribute('Trait2', 'Value2');

        $this->assertInstanceOf(NFTMetadata::class, $result);
        $this->assertCount(2, $this->metadata->getAttributes());
    }
}