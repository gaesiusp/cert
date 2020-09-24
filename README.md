# Gaesi/cert

A PHP library for working with Certificates.

 - ICP-Brasil Support
 - SSL Certificate Parser
 - Verify Cert Chain
 - Verify ICP-Brasil Cert Chain
 
 ## Usage


 For load the SSL Certificate ICPBrasil: 
 ```` php
 use Gaesi\Cert\IcpBrasil\IcpBrasilCertificate;

 $icp = new IcpBrasilCertificate();
 $icp->parseSSL();

 echo $icp->cnpj;   // print the cnpj
 echo $icp->name;   // print the name of the CommonName
 echo $icp->oidExists('2.16.76.1.3.3'); // true

 ````

 For load the Certificate ICPBrasil from the text or file:
 ```` php
 use Gaesi\Cert\IcpBrasil\IcpBrasilCertificate;

 string $cert = "-----BEGIN CERTIFICATE-----MIIG4...XLFw==-----END CERTIFICATE-----";
 $icp = new IcpBrasilCertificate();
 $icp->parseX509($cert);
 echo $icp->cnpj;   // print the cnpj

 ````

 ### Verify CertChain

 For load and verify the Chain of Certificate :
 ```` php
 use Gaesi\Cert\IcpBrasil\IcpBrasilCertificate;

 $ca = new CALoader();
 $ca->addRepositoryPath('path/to/CAs/repository');
 
 $icp = new IcpBrasilCertificate();
 $icp->parseSSL();
 $icp->setChain($ca->getCAs());
 echo 'Valid? :'. ($icp->validateChain())? 'true' : 'false';
````

 For verify if the Chain of Certificate is a ICP-Basil Chain :
 ```` php
 use Gaesi\Cert\IcpBrasil\IcpBrasilCertificate;


 $icp = new IcpBrasilCertificate();
 $icp->parseSSL();

 // Include the Intermediates Certs to the Chain
 $ca = new CALoader();
 $ca->addCerts( $intermediatesCert ); 
 
 $icp->setChain($ca->getCAs());
 echo 'Is IcpBrasil? :'. ($icp->validateICPBrasilChain())? 'true' : 'false';

 ````

 ## ICP-Brasil CAs Root 
 The library store only the default ICP-Brasil CA Root on the directory ``src/Resources/icpBrasil/Roots``, for verify the Chain is necessary load all the Chain of Certificate.  

 ## References

 https://www.gov.br/iti/pt-br/centrais-de-conteudo/doc-icp-04-01-versao-3-3-atribuicao-de-oid-na-icp-brasil-pdf

 https://www.gov.br/iti/pt-br/assuntos/repositorio/repositorio-ac-raiz
  