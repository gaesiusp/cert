<?php 

namespace Gaesi\Cert\IcpBrasil;

use Gaesi\Cert\IcpBrasil\IcpBrasilParser;
use phpseclib\File\X509;


class IcpBrasilCertificate extends IcpBrasilParser
{
    /**
     * @var X509 Object representando o Certificado 
     */
    public $x509 = null;

    /**
     * @var array Array com todos OIDs existentes no Subject Alternative Name do Certificado
     */
    public $oids = null;

    /**
     * @var string CommonName completo do Certificado
     */
    public ?string $commonName = null;
    
    /**
     * @var string Nome presente no
     */
    public ?string $name = null;

    /**
     * @var string Identificador do certificado ICPBrasil presente no CommonName <Nome>:<CNPJ>
     */
    public ?string $cnIdentifier = null;
    
    /**
     * @var string cpf presente no OID "2.16.76.1.3.1", caso não exista é preenchido com o CPF presente no CommonName
     */
    public ?string $cpf = null;
    
    /**
     * @var string cnpj presente no OID "2.16.76.1.3.3", caso não exista é preenchido com o CNPJ presente no CommonName
     */
    public ?string $cnpj = null;

    public function parseSSL(): ?IcpBrasilCertificate
    {
        parent::setInstance($this);
        return  parent::parseSSL();
    }

    public function parseX509(string $x509 = null): ?IcpBrasilCertificate
    {
        parent::setInstance($this);
        return  parent::parseX509($x509);
    }


    public function setX509($x509): void
    {
        $this->x509 = $x509;
    }

    public function setSanOids($oids): void
    {
        $this->oids = $oids;
    }

    /**
     * Método Verifica a existência de um OID especifico no Certificado.
     * Somente os OIDs presentes no Subject Alternative Name
     * 
     * @param string OID procurado. Ex.: 2.16.76.1.3.3
     * 
     * @return mixed Retorna um array com o conteúdo do OID encontrado (oid => value), ou null caso não exista
     */
    public function hasOid(string $oid)
    {
        if (isset($this->oids) && isset($this->oids[$oid])) {
            return $this->oids[$oid];
        }
        return null;
    }
}