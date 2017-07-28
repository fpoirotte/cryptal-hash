<?php

namespace fpoirotte\Cryptal\Plugins\Hash;

use fpoirotte\Cryptal\Implementers\PluginInterface;
use fpoirotte\Cryptal\Implementers\MacInterface;
use fpoirotte\Cryptal\RegistryWrapper;
use fpoirotte\Cryptal\CipherEnum;
use fpoirotte\Cryptal\HashEnum;
use fpoirotte\Cryptal\MacEnum;
use fpoirotte\Cryptal\ImplementationTypeEnum;
use fpoirotte\Cryptal\SubAlgorithmAbstractEnum;

class Mac extends MacInterface implements PluginInterface
{
    protected $context;
    protected static $supportedAlgos = null;

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
        $registry->addMac(
            __CLASS__,
            MacEnum::MAC_HMAC(),
            ImplementationTypeEnum::TYPE_COMPILED()
        );
    }
}
