<?php

namespace fpoirotte\Cryptal\Plugins\Hash;

use fpoirotte\Cryptal\Implementers\PluginInterface;
use fpoirotte\Cryptal\Implementers\HashInterface;
use fpoirotte\Cryptal\RegistryWrapper;
use fpoirotte\Cryptal\HashEnum;
use fpoirotte\Cryptal\ImplementationTypeEnum;
use fpoirotte\Cryptal\Plugins\Hash\Common;

class Hash extends Common implements HashInterface, PluginInterface
{
    public function __construct(HashEnum $algorithm)
    {
        if (static::$supportedAlgos === null) {
            static::checkSupport();
        }

        if (!isset(static::$supportedAlgos["$algorithm"])) {
            throw new \InvalidArgumentException('Unsupported algorithm');
        }

        $this->context = hash_init(static::$supportedAlgos["$algorithm"]);
    }

    public static function hash(HashEnum $algorithm, $data, $raw = false)
    {
        $obj = new static($algorithm);
        return $obj->update($data)->finalize($raw);
    }

    public static function registerAlgorithms(RegistryWrapper $registry)
    {
        static::checkSupport();
        foreach (static::$supportedAlgos as $algo => $algoConst) {
            $registry->addHash(
                __CLASS__,
                HashEnum::$algo(),
                ImplementationTypeEnum::TYPE_COMPILED()
            );
        }
    }
}
