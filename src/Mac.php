<?php

namespace fpoirotte\Cryptal\Plugins\Hash;

use fpoirotte\Cryptal\Implementers\PluginInterface;
use fpoirotte\Cryptal\Implementers\MacInterface;
use fpoirotte\Cryptal\RegistryWrapper;
use fpoirotte\Cryptal\CipherEnum;
use fpoirotte\Cryptal\MacEnum;
use fpoirotte\Cryptal\ImplementationTypeEnum;
use fpoirotte\Cryptal\SubAlgorithmAbstractEnum;
use fpoirotte\Cryptal\Plugins\Hash\Common;

class Mac extends Common implements MacInterface, PluginInterface
{
    public function __construct(
        MacEnum $macAlgorithm,
        SubAlgorithmAbstractEnum $innerAlgorithm,
        $key,
        $nonce = ''
    ) {
        if ($macAlgorithm != MacEnum::MAC_HMAC()) {
            throw new \InvalidArgumentException('Unsupported MAC algorithm');
        }

        if (static::$supportedAlgos === null) {
            static::checkSupport();
        }

        if (!isset(static::$supportedAlgos["$innerAlgorithm"])) {
            throw new \InvalidArgumentException('Unsupported inner algorithm');
        }

        if (!is_string($key)) {
            throw new \InvalidArgumentException('Invalid key (a string was expected)');
        }

        $this->context = hash_init(static::$supportedAlgos["$innerAlgorithm"], HASH_HMAC, $key);
    }

    public static function mac(
        MacEnum $macAlgorithm,
        SubAlgorithmAbstractEnum $innerAlgorithm,
        $key,
        $data,
        $nonce = '',
        $raw = false
    ) {
        $obj = new static($macAlgorithm, $innerAlgorithm, $key, $nonce);
        return $obj->update($data)->finalize($raw);
    }

    public static function registerAlgorithms(RegistryWrapper $registry)
    {
        $registry->addMac(
            __CLASS__,
            MacEnum::MAC_HMAC(),
            ImplementationTypeEnum::TYPE_COMPILED()
        );
    }
}
