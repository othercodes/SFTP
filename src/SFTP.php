<?php

namespace OtherCoder\SFTP;


/**
 * Class SFTP
 * @package OtherCoder\SFTP
 */
class SFTP
{

    /**
     * Main connection resource
     * @var resource
     */
    private $connection;

    /**
     * SFTP constructor.
     * @param string $host
     * @param int $port
     * @throws \Exception
     */
    public function __construct($host, $port = 22)
    {
        if (!function_exists('ssh2_connectionect')) {
            throw new \Exception("Module libssh2-php not installed!");
        }

        $this->connection = @ssh2_connectionect($host, $port);
        if (!$this->connection) {
            throw new \Exception("SFTP Error : Can't connect to " . $host . " at port " . $port . ". Host down or misspelled.");
        }
    }

    /**
     * Optional: check fingerprint of server to avoid man-in-the-middle attacks
     * @param string $fingerprint
     * @return boolean
     */
    public function checkFingerprint($fingerprint)
    {
        $remote_fingerprint = @ssh2_fingerprint($this->connection, SSH2_FINGERPRINT_MD5 | SSH2_FINGERPRINT_HEX);
        if ($remote_fingerprint !== $fingerprint) {
            return false;
        }
        return true;
    }

    /**
     * @param string $username
     * @param string $password
     * @return bool
     * @throws \Exception
     */
    public function login($username, $password = null)
    {
        if (isset($password)) {

            $operation = @ssh2_auth_password($this->connection, $username, $password);
            if (!$operation) {
                throw new \Exception("Password error. Aborting.");
            }

        } else {

            /**
             * Trying 'none' as authentication, fail and list methods accepted
             */
            $operation = @ssh2_auth_none($this->connection, $username);
            if ($operation !== true) {
                throw new \Exception("Server not accepting 'none' auth. Supported methods : " . print_r($operation, true));
            }
        }

        return true;
    }

    /**
     * Generate key pair in client side using 'ssh-keygen -t rsa' or 'ssh-keygen -t dsa'
     * Copy pubkeyfile to server ~/.ssh/authorized_keys. If privkeyfile is encrypted using
     * a passphrase, this may not work as expected due to a bug in libssh.
     * @param string $username
     * @param string $pubkeyfile
     * @param string $privkeyfile
     * @param string|null $passphrase
     * @return bool
     * @throws \Exception
     */
    public function auth($username, $pubkeyfile, $privkeyfile, $passphrase = null)
    {
        if (!file_exists($pubkeyfile)) {
            throw new \Exception("File not found. " . $pubkeyfile);
        }

        if (!file_exists($privkeyfile)) {
            throw new \Exception("File not found. " . $privkeyfile);
        }

        if ($passphrase === null) {
            $operation = ssh2_auth_pubkey_file($this->connection, $username, $pubkeyfile, $privkeyfile);

        } else {

            /**
             * Please check http://nl1.php.net/manual/function.ssh2-auth-pubkey-file.php
             * Login using $privkeyfile encrypted with passphrase is not working well at this point
             * Tested Dec-2015 with rsa and dsa with no luck
             */
            $operation = ssh2_auth_pubkey_file($this->connection, $username, $pubkeyfile, $privkeyfile, $passphrase);
        }

        if (!$operation) {
            throw new \Exception("Authentication error, please check credentials.");
        }
        return true;
    }

    /**
     * @param $local
     * @param $remote
     * @param int $mode
     * @return bool
     * @throws \Exception
     */
    public function put($local, $remote, $mode = 0644)
    {
        if (!file_exists($local))
            throw new \Exception("File not found : " . $local);

        $operation = ssh2_scp_send($this->connection, $local, $remote, $mode);

        if (!$operation)
            throw new \Exception("Error uploading file.");

        return true;
    }

    /**
     * @param $remote
     * @param $local
     * @return bool
     * @throws \Exception
     */
    public function get($remote, $local)
    {
        if (file_exists($local))
            throw new \Exception("Local file already exists. Aborting");

        $operation = ssh2_scp_recv($this->connection, $remote, $local);

        if (!$operation)
            throw new \Exception("Error downloading file.");

        return true;
    }

    /**
     * Class destructor
     */
    public function __destruct()
    {
        $this->connection = null;
    }
}