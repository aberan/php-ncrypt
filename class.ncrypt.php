<?php
namespace nxnw;

/* inspired and borrows very heavily from this implementation http://www.itnewb.com/tutorial/PHP-Encryption-Decryption-Using-the-MCrypt-Library-libmcrypt/ */
/* uses PBKDF2 implementation at https://defuse.ca/php-pbkdf2.htm */
class ncrypt {
	static private $pw = 'lo7uj3$chUYFgkjds*&%ga'; //change this per implementation : TODO: set this on a session basis somehow?
	static private $iterations = 1000;
	static private $key_len = 32;
	static private $algorithm = 'sha256';

	
	static function ec($msg, $key, $urlencode=false, $base64=false){
		try {
			 if(!$td = mcrypt_module_open('rijndael-256', '', 'ctr', '')){
			 	return false;
			 }
			$msg = serialize($msg);
      		
      		//create iv
			$iv = self::gen_iv();
			if(mcrypt_generic_init($td, $key, $iv) !== 0){
          		return false;
          	}
          	$msg = mcrypt_generic($td, $msg);
          	
      		$msg = $iv.$msg;
      		$mac = self::pbkdf2(true);
      		$msg .= $mac; 
      		
      		// clear buffers and close module
      		mcrypt_generic_deinit($td);
      		mcrypt_module_close($td);
      
      		//encode as needed..
      		if($base64){
      			$msg = base64_encode($msg);
      		}
      		
      		if($urlencode){
      			$msg = rawurlencode($msg);
      		}
      
      		return $msg;
		} 
		catch (Exception $e) {
			return false;
		}
	} /* \ec */
	
	static function dc($msg, $key, $urlencode=false, $base64=false){
		try{
			if($urlencode){
      			$msg = rawurldecode($msg);
      		}
      		
			if($base64){
				$msg = base64_decode($msg);
			}

			if (!$td = mcrypt_module_open('rijndael-256', '', 'ctr', '')){
				return false;
			}
	 		
	 		$iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC);
			$iv = substr($msg, 0, self::$key_len);                    
			$mac_offset = strlen($msg) - self::$key_len;                      
			$extracted_mac = substr($msg, $mac_offset);                         
			$msg = substr($msg, self::$key_len, strlen($msg)-self::$key_len*2);        
	 		$mac = self::pbkdf2(true);
	 		
			if($extracted_mac !== $mac){                               # authenticate mac
				return false;
			}
	 
			if(mcrypt_generic_init($td, $key, $iv) !== 0){      # initialize buffers
				return false;
			}
	 
			$msg = mdecrypt_generic($td, $msg);                 # decrypt
			$msg = unserialize($msg);                           # unserialize
			mcrypt_generic_deinit($td);                         # clear buffers
			mcrypt_module_close($td);                           # close cipher module
	 
			return $msg;
		}
		catch(Exception $e){
			return false;
		}
	} /* \dc */
	
	static function gen_iv(){
		try{
			return is_readable('/dev/urandom') ? mcrypt_create_iv(self::$key_len, MCRYPT_DEV_URANDOM) : mcrypt_create_iv(self::$key_len, MCRYPT_RAND);
		}
		catch(Exception $e){
			return false;
		}	
	} /* \gen_iv */

	static function gen_pw() {
		if(@is_readable('/dev/urandom')) {
			$fp = fopen('/dev/urandom', 'r'); 
			$csrf = md5(fread($fp, 128));
			fclose($fp);
		}
		else{
			$csrf = md5(mt_rand() . mt_rand() . mt_rand() . mt_rand());
		}
		return $csrf;
	} /* \gen_pw */
	
	static function pbkdf2() {
		$salt = self::gen_iv();
		$hl = strlen(hash(self::$algorithm, null, true)); # Hash length
		$kb = ceil(self::$key_len / $hl);              # Key blocks to compute
		$dk = '';                           # Derived key
		$pw = self::gen_pw();
 
		# Create key
		for ( $block = 1; $block <= $kb; $block ++ ) {
 
			# Initial hash for this block
			$ib = $b = hash_hmac(self::$algorithm, $salt . pack('N', $block), $pw, true);
 
			# Perform block iterations
			for ( $i = 1; $i < self::$iterations; $i ++ )
 
				# XOR each iterate
				$ib ^= ($b = hash_hmac(self::$algorithm, $b, $pw, true));
 
			$dk .= $ib; # Append iterated block
		}
 
		# Return derived key of correct length
		//return $mac ? substr($dk, 0, self::$key_len): $base_64 ? base64_encode($dk) : $dk;
		return substr($dk, 0, self::$key_len);
	} /* \pbkdf2 */
	
}
?>