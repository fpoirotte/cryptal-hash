<?php

namespace fpoirotte\Cryptal\Plugins\Hash;

use fpoirotte\Cryptal\Implementers\PluginInterface;
use fpoirotte\Cryptal\Implementers\HashInterface;
use fpoirotte\Cryptal\RegistryWrapper;
use fpoirotte\Cryptal\HashEnum;
use fpoirotte\Cryptal\ImplementationTypeEnum;

class Hash extends HashInterface implements PluginInterface
{
    protected $context;
    protected static $supportedAlgos = null;

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

    public function __clone()
    {
        // Create a copy of the original hashing context,
        // so that both the original object and the clone
        // can work without interfering with each other.
        $this->context = hash_copy($this->context);
    }

    protected static function checkSupport()
    {
        $mapping  = array(
            (string) HashEnum::HASH_CRC32()     => 'crc32',
            (string) HashEnum::HASH_MD2()       => 'md2',
            (string) HashEnum::HASH_MD4()       => 'md4',
            (string) HashEnum::HASH_MD5()       => 'md5',
            (string) HashEnum::HASH_RIPEMD160() => 'ripemd160',
            (string) HashEnum::HASH_SHA1()      => 'sha1',
            (string) HashEnum::HASH_SHA224()    => 'sha224',
            (string) HashEnum::HASH_SHA256()    => 'sha256',
            (string) HashEnum::HASH_SHA384()    => 'sha384',
            (string) HashEnum::HASH_SHA512()    => 'sha512',
        );

        static::$supportedAlgos = array_intersect($mapping, hash_algos());
    }

    protected function internalUpdate($data)
    {
        hash_update($this->context, $data);
    }

    protected function internalFinish()
    {
        return hash_final($this->context, true);
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
