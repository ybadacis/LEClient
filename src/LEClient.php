<?php

namespace LEClient;

use LEClient\Exceptions\LEClientException;

/**
 * Main LetsEncrypt Client class, works as a framework for the LEConnector, LEAccount, LEOrder and LEAuthorization classes.
 *
 * PHP version 5.2.0
 *
 * MIT License
 *
 * Copyright (c) 2018 Youri van Weegberg
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * @author     Youri van Weegberg <youri@yourivw.nl>
 * @copyright  2018 Youri van Weegberg
 * @license    https://opensource.org/licenses/mit-license.php  MIT License
 * @link       https://github.com/yourivw/LEClient
 * @since      Class available since Release 1.0.0
 */
class LEClient
{
	const LE_PRODUCTION = 'https://acme-v02.api.letsencrypt.org';
	const LE_STAGING = 'https://acme-staging-v02.api.letsencrypt.org';

	private $certificateKeys;
	private $accountKeys;

	private $connector;
	private $account;

	private $sourceIp = false;

	private $log;
    private $baseUrl;

	const LOG_OFF = 0;		// Logs no messages or faults, except Runtime Exceptions.
	const LOG_STATUS = 1;	// Logs only messages and faults.
	const LOG_DEBUG = 2;	// Logs messages, faults and raw responses from HTTP requests.

    /**
     * Initiates the LetsEncrypt main client.
     *
     * @param array		$email	 			The array of strings containing e-mail addresses. Only used in this function when creating a new account.
     * @param boolean	$acmeURL			ACME URL, can be string or one of predefined values: LE_STAGING or LE_PRODUCTION. Defaults to LE_STAGING.
     * @param int 		$log				The level of logging. Defaults to no logging. LOG_OFF, LOG_STATUS, LOG_DEBUG accepted. Defaults to LOG_OFF. (optional)
     * @param string 	$certificateKeys 	The main directory in which all keys (and certificates), including account keys, are stored. Defaults to 'keys/'. (optional)
     * @param array 	$certificateKeys 	Optional array containing location of all certificate files. Required paths are public_key, private_key, order and certificate/fullchain_certificate (you can use both or only one of them)
     * @param string 	$accountKeys 		The directory in which the account keys are stored. Is a subdir inside $certificateKeys. Defaults to '__account/'.(optional)
     * @param array 	$accountKeys 		Optional array containing location of account private and public keys. Required paths are private_key, public_key.
	 * @param string    $sourceIp           Optional source IP address.
     */
	public function __construct($email, $acmeURL = LEClient::LE_PRODUCTION, $log = LEClient::LOG_OFF, $certificateKeys = 'keys/', $accountKeys = '__account/', $sourceIp = false, $eabParams = array())
	{
		$this->log = $log;
		$this->sourceIp = $sourceIp;
		if (is_bool($acmeURL))
		{
			if ($acmeURL === true) $this->baseURL = LEClient::LE_STAGING;
			elseif ($acmeURL === false) $this->baseURL = LEClient::LE_PRODUCTION;
		}
		elseif (is_string($acmeURL))
		{
			$this->baseURL = $acmeURL;
		}
		else throw LEClientException::InvalidArgumentException('acmeURL must be set to string or bool (legacy).');

		if (is_array($certificateKeys) && is_string($accountKeys)) throw LEClientException::InvalidArgumentException('When certificateKeys is array, accountKeys must be array too.');
		elseif (is_array($accountKeys) && is_string($certificateKeys)) throw LEClientException::InvalidArgumentException('When accountKeys is array, certificateKeys must be array too.');

		if (is_string($certificateKeys))
		{
			$certificateKeysDir = $certificateKeys;

			if(!file_exists($certificateKeys))
			{
				mkdir($certificateKeys, 0755, true);
				LEFunctions::createhtaccess($certificateKeys);
			}

			$this->certificateKeys = array(
				"public_key" => $certificateKeys.'/public.pem',
				"private_key" => $certificateKeys.'/private.pem',
				"certificate" => $certificateKeys.'/certificate.crt',
				"fullchain_certificate" => $certificateKeys.'/fullchain.crt',
				"order" => $certificateKeys.'/order'
			);
		}
		elseif (is_array($certificateKeys))
		{
			if (!isset($certificateKeys['certificate']) && !isset($certificateKeys['fullchain_certificate'])) throw LEClientException::InvalidArgumentException('certificateKeys[certificate] or certificateKeys[fullchain_certificate] file path must be set.');
			if (!isset($certificateKeys['private_key'])) throw LEClientException::InvalidArgumentException('certificateKeys[private_key] file path must be set.');
			if (!isset($certificateKeys['order'])) $certificateKeys['order'] = dirname($certificateKeys['private_key']).'/order';
			if (!isset($certificateKeys['public_key'])) $certificateKeys['public_key'] = dirname($certificateKeys['private_key']).'/public.pem';

			foreach ($certificateKeys as $param => $file) {
				$parentDir = dirname($file);
				if (!is_dir($parentDir)) throw LEClientException::InvalidDirectoryException($parentDir);
			}

			$this->certificateKeys = $certificateKeys;
		}
		else
		{
			throw LEClientException::InvalidArgumentException('certificateKeys must be string or array.');
		}

		if (is_string($accountKeys))
		{
			$accountKeys = $certificateKeysDir.'/'.$accountKeys;

			if(!file_exists($accountKeys))
			{
				mkdir($accountKeys, 0755, true);
				LEFunctions::createhtaccess($accountKeys);
			}

			$this->accountKeys = array(
				"private_key" => $accountKeys.'/private.pem',
				"public_key" => $accountKeys.'/public.pem'
			);
		}
		elseif (is_array($accountKeys))
		{
			if (!isset($accountKeys['private_key'])) throw LEClientException::InvalidArgumentException('accountKeys[private_key] file path must be set.');
			if (!isset($accountKeys['public_key'])) throw LEClientException::InvalidArgumentException('accountKeys[public_key] file path must be set.');

			foreach ($accountKeys as $param => $file) {
				$parentDir = dirname($file);
				if (!is_dir($parentDir)) throw LEClientException::InvalidDirectoryException($parentDir);
			}

			$this->accountKeys = $accountKeys;
		}
		else
		{
			throw LEClientException::InvalidArgumentException('accountKeys must be string or array.');
		}

		$this->connector = new LEConnector($this->log, $this->baseURL, $this->accountKeys, $this->sourceIp);
		if ($this->connector->externalAccountRequired) {
			if($this->log instanceof \Psr\Log\LoggerInterface)
			{
				$this->log->info('LEClient : ACME provider requires External Account Binding');
			}
			elseif($this->log >= LEClient::LOG_STATUS) LEFunctions::log('LEClient : ACME provider requires External Account Binding', 'function LEClient __construct');

			if (!isset($eabParams['kid'])) throw LEClientException::InvalidArgumentException('eabParams[kid] must be set for External Account Binding.');
			if (!isset($eabParams['hmac'])) throw LEClientException::InvalidArgumentException('eabParams[hmac] must be set for External Account Binding.');
		}
		$this->account = new LEAccount($this->connector, $this->log, $email, $this->accountKeys, $eabParams);

		if($this->log instanceof \Psr\Log\LoggerInterface)
		{
			$this->log->info('LEClient finished constructing');
		}
		elseif($this->log >= LEClient::LOG_STATUS) LEFunctions::log('LEClient finished constructing', 'function LEClient __construct');
	}


    /**
     * Returns the LetsEncrypt account used in the current client.
	 *
	 * @return LEAccount	The LetsEncrypt Account instance used by the client.
     */
	public function getAccount()
	{
		return $this->account;
	}

    /**
     * Returns a LetsEncrypt order. If an order exists, this one is returned. If not, a new order is created and returned.
     *
     * @param string	$basename	The base name for the order. Preferable the top domain (example.org). Will be the directory in which the keys are stored. Used for the CommonName in the certificate as well.
     * @param array 	$domains 	The array of strings containing the domain names on the certificate.
     * @param string 	$keyType 	Type of the key we want to use for certificate. Can be provided in ALGO-SIZE format (ex. rsa-4096 or ec-256) or simple "rsa" and "ec" (using default sizes)
     * @param string 	$notBefore	A date string formatted like 0000-00-00T00:00:00Z (yyyy-mm-dd hh:mm:ss) at which the certificate becomes valid. Defaults to the moment the order is finalized. (optional)
     * @param string 	$notAfter	A date string formatted like 0000-00-00T00:00:00Z (yyyy-mm-dd hh:mm:ss) until which the certificate is valid. Defaults to 90 days past the moment the order is finalized. (optional)
	 * @param boolean 	$skipOrderValidation  A boolean indicating whether to skip order status validation after creation/retrieval. Defaults to false. (optional)
     *
     * @return LEOrder	The LetsEncrypt Order instance which is either retrieved or created.
     */
	public function getOrCreateOrder($basename, $domains, $keyType = 'rsa-4096', $notBefore = '', $notAfter = '', bool $skipOrderValidation = false, ?string $ariCertId = null)
	{
		return new LEOrder($this->connector, $this->log, $this->certificateKeys, $basename, $domains, $keyType, $notBefore, $notAfter, $skipOrderValidation, $ariCertId);
	}

    /**
     * Revoke a certificate bypassing LEOrder.
     *
     * @param string 	$basename	The CN of the certificate to revoke.
     * @param int 	    $reason		The reason for revocation. Must be one of the valid revocation reasons.
     * @throws LEClientException    If the certificate is not found or the revocation reason is invalid.
     * 
     * @return boolean	Returns true if the certificate was successfully revoked, false if not.
     */
    public function revokeCertificateWithoutOrder($basename, int $reason = 0)
    {
        if (!in_array($reason, LEOrder::VALID_REVOCATION_REASONS, true)) {
            throw LEClientException::InvalidArgumentException('Invalid revocation reason: ' . $reason);
        }

        $certFile = '';
        if (isset($this->certificateKeys['certificate'])) {
            $certFile = $this->certificateKeys['certificate'];
        } elseif (isset($this->certificateKeys['fullchain_certificate'])) {
            $certFile = $this->certificateKeys['fullchain_certificate'];
        } else {
            throw new \Exception('certificateKeys[certificate] or certificateKeys[fullchain_certificate] required');
        }

        if (file_exists($certFile) && file_exists($this->certificateKeys['private_key'])) {
            $certificate = file_get_contents($this->certificateKeys['certificate']);
            preg_match('~-----BEGIN\sCERTIFICATE-----(.*)-----END\sCERTIFICATE-----~s', $certificate, $matches);
            $certificate = trim(LEFunctions::Base64UrlSafeEncode(base64_decode(trim($matches[1]))));

            $sign = $this->connector->signRequestJWK(array('certificate' => $certificate, 'reason' => $reason), $this->connector->revokeCert, $this->certificateKeys['private_key']);
            $post = $this->connector->post($this->connector->revokeCert, $sign);
            if ($post['status'] === 200) {
                if ($this->log instanceof \Psr\Log\LoggerInterface) {
                    $this->log->info('Certificate for order \'' . $basename . '\' revoked.');
                } elseif ($this->log >= LEClient::LOG_STATUS) {
                    LEFunctions::log('Certificate for order \'' . $basename . '\' revoked.', 'function revokeCertificateWithoutOrder');
                }

                return true;
            } else {
                if ($this->log instanceof \Psr\Log\LoggerInterface) {
                    $this->log->info('Certificate for order \'' . $basename . '\' cannot be revoked.');
                } elseif ($this->log >= LEClient::LOG_STATUS) {
                    LEFunctions::log('Certificate for order \'' . $basename . '\' cannot be revoked.', 'function revokeCertificateWithoutOrder');
                }
            }
        } else {
            if ($this->log instanceof \Psr\Log\LoggerInterface) {
                $this->log->info('Certificate for order \'' . $basename . '\' not found. Cannot revoke certificate.');
            } elseif ($this->log >= LEClient::LOG_STATUS) {
                LEFunctions::log('Certificate for order \'' . $basename . '\' not found. Cannot revoke certificate.', 'function revokeCertificateWithoutOrder');
            }
        }

        return false;
    }

    /**
     * Get ACME Renewal Information (ARI, RFC 9773) for a given certificate.
     * Does not require an order, and is not signed (per protocol).
     *
     * @param string $certPem PEM encoded leaf certificate
     *
     * @return array{
     *      'suggestedWindow': array{
     *          'start': int,
     *          'end': int,
     *      },
     *      'retryAfter': ?int,
     *      'ariCertId': string
     * }
     */
    public function getARI(): array
    {
        if (!$this->connector->supportsAri()) {
            throw new \RuntimeException('This ACME server does not support ARI.');
        }

        $certFile = '';

        if (isset($this->certificateKeys['certificate']) && file_exists($this->certificateKeys['certificate'])) {
            $certFile = $this->certificateKeys['certificate'];
        } else {
            throw new \Exception('ARI certificateKeys[certificate] required');
        }

        $certificate = file_get_contents($this->certificateKeys['certificate']);
        
        $certId = LEFunctions::getARICertId($certificate);

        $result = $this->connector->get($this->connector->renewalInfo . '/' . $certId);

        $data = $result['body'];
        if (!is_array($data) || !isset($data['suggestedWindow'])) {
            throw new \Exception('Cartificate invalid ARI response: ' . $result['body']);
        }

        $suggestedWindow = $data['suggestedWindow'];
        if (!isset($suggestedWindow['start'])) {
            throw new Exception('Certificate ARI suggestedWindow start not present');
        }
		if (!isset($suggestedWindow['end'])) {
            throw new Exception('ARI suggestedWindow end not present');
        }

        $data['suggestedWindow']['start'] = strtotime($suggestedWindow['start']);
        $data['suggestedWindow']['end'] = strtotime($suggestedWindow['end']);
        $data['retryAfter'] = LEFunctions::getRetryAfterHeader($result['parsedHeader']);
        $data['ariCertId'] = $certId;

        return $data;
    }
}
