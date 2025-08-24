<?php

namespace PHPCore\SimpleCrypto\NFT;

class NFTMetadata
{
    private string $name;
    private string $description;
    private string $image;
    private array $attributes;
    private ?string $externalUrl;
    private ?string $animationUrl;

    public function __construct(
        string $name,
        string $description,
        string $image,
        array $attributes = [],
        ?string $externalUrl = null,
        ?string $animationUrl = null
    ) {
        $this->name = $name;
        $this->description = $description;
        $this->image = $image;
        $this->attributes = $attributes;
        $this->externalUrl = $externalUrl;
        $this->animationUrl = $animationUrl;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getDescription(): string
    {
        return $this->description;
    }

    public function getImage(): string
    {
        return $this->image;
    }

    public function getAttributes(): array
    {
        return $this->attributes;
    }

    public function getExternalUrl(): ?string
    {
        return $this->externalUrl;
    }

    public function getAnimationUrl(): ?string
    {
        return $this->animationUrl;
    }

    public function addAttribute(string $traitType, string|int|float $value, ?float $maxValue = null): self
    {
        $attribute = [
            'trait_type' => $traitType,
            'value' => $value
        ];

        if ($maxValue !== null) {
            $attribute['max_value'] = $maxValue;
        }

        $this->attributes[] = $attribute;
        return $this;
    }

    public function toArray(): array
    {
        $metadata = [
            'name' => $this->name,
            'description' => $this->description,
            'image' => $this->image,
            'attributes' => $this->attributes,
        ];

        if ($this->externalUrl !== null) {
            $metadata['external_url'] = $this->externalUrl;
        }

        if ($this->animationUrl !== null) {
            $metadata['animation_url'] = $this->animationUrl;
        }

        return $metadata;
    }

    public function toJson(): string
    {
        return json_encode($this->toArray(), JSON_PRETTY_PRINT);
    }

    public static function fromArray(array $data): self
    {
        return new self(
            $data['name'],
            $data['description'],
            $data['image'],
            $data['attributes'] ?? [],
            $data['external_url'] ?? null,
            $data['animation_url'] ?? null
        );
    }

    public static function fromJson(string $json): self
    {
        $data = json_decode($json, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \InvalidArgumentException('Invalid JSON string provided');
        }
        return self::fromArray($data);
    }
}