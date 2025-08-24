<?php

require_once __DIR__ . '/../vendor/autoload.php';

use PHPCore\SimpleCrypto\NFT\NFTMetadata;

// Create a new NFT metadata instance
$metadata = new NFTMetadata(
    'Cool NFT #1',
    'This is a really cool NFT with amazing attributes!',
    'ipfs://QmYourImageCIDHere/1.png'
);

// Add some attributes
$metadata->addAttribute('Background', 'Blue')
    ->addAttribute('Skin', 'Gold')
    ->addAttribute('Eyes', 'Diamond')
    ->addAttribute('Power Level', 95, 100)
    ->addAttribute('Speed', 80, 100);

// Convert to JSON and print
echo $metadata->toJson() . "\n";

// Example of creating from JSON
$jsonString = '{
    "name": "Cool NFT #2",
    "description": "Another awesome NFT!",
    "image": "ipfs://QmAnotherImageCIDHere/2.png",
    "attributes": [
        {
            "trait_type": "Background",
            "value": "Red"
        },
        {
            "trait_type": "Power Level",
            "value": 85,
            "max_value": 100
        }
    ]
}';

$newMetadata = NFTMetadata::fromJson($jsonString);
echo "\nCreated from JSON:\n" . $newMetadata->toJson() . "\n";