<?php

class SQL{
    public static $host = 'localhost';
    public static $stmt;
	public static $db_type = 'mysql';
    public static $dbh;
    public static $error;
 
	public static function Connect($sqlusername, $sqlpassword, $sqlhost){
		if(posix_getpwuid(fileowner('encryption.inc'))['name'] !== 'www-data' || substr(sprintf('%o', fileperms('encryption.inc')), -4) !== '0400'){die("Please Change encryption.inc Premissions");} /// encryption.inc Needs to be www-data owner only and 0400 premissions for Security Purposes 
		$B69AB4B1CC47C = array("_c+8oe8k|umgt9vFPEz@1E_6qGnIbm" => $sqlusername, "R|zMpGcwN2>AZ[f5_cN7c^cm852Bg3" => $sqlpassword);
        // Set DSN
        $dsn = SQL::$db_type . ':host=' . $sqlhost  . ";";
        // Set options
        $options = array(
            PDO::ATTR_PERSISTENT    => true,
            PDO::ATTR_ERRMODE       => PDO::ERRMODE_EXCEPTION
        );
        // Create a new PDO instanace
        try{
            SQL::$dbh = new PDO($dsn, $B69AB4B1CC47C['_c+8oe8k|umgt9vFPEz@1E_6qGnIbm'], $B69AB4B1CC47C['R|zMpGcwN2>AZ[f5_cN7c^cm852Bg3'], $options);
			return true;
        }
        // Catch any errors
        catch(PDOException $e){
			die($e->getMessage());
        }
    }
    
    public static function Query($query){
        SQL::$stmt = SQL::$dbh->prepare($query);
    }
    
    public static function Bind($param, $value, $encrypt = 0, $type = null){
    if (is_null($type)) {
        switch (true) {
            case is_int($value):
                $type = PDO::PARAM_INT;
                break;
            case is_bool($value):
                $type = PDO::PARAM_BOOL;
                break;
            case is_null($value):
                $type = PDO::PARAM_NULL;
                break;
            case is_float($value):
                $type = PDO::PARAM_STR;
            default:
                $type = PDO::PARAM_STR;
        }
    }
		if($encrypt !== 0){
			$value = SQL::Encrypt($value);
		}
        SQL::$stmt->bindValue($param, $value, $type);
    }
	
	public static function Run($sql){
		SQL::Query($sql);
		SQL::Execute();
	}

    public static function Execute(){
        return SQL::$stmt->execute();
    }
    
    public static function Results(){
        SQL::execute();
        if(SQL::RowCount() > 0){
			return SQL::DecryptArray(SQL::$stmt->fetchAll(PDO::FETCH_ASSOC));
		} else {
			return SQL::$stmt->fetchAll(PDO::FETCH_ASSOC);
		}
    }
	
	public static function ResultsQuery($sql){
		SQL::Query($sql);
        SQL::execute();
	    if(SQL::RowCount() > 0){
			return SQL::DecryptArray(SQL::$stmt->fetchAll(PDO::FETCH_ASSOC));
		} else {
        	return SQL::$stmt->fetchAll(PDO::FETCH_ASSOC);
		}
    }
    
    public static function Single(){
        SQL::execute();
		if(SQL::RowCount() > 0){
        	return SQL::DecryptSingleArray(SQL::$stmt->fetch(PDO::FETCH_ASSOC));
		} else {
			return SQL::$stmt->fetch(PDO::FETCH_ASSOC);
		}
    }
	
	public static function SingleQuery($sql){
		SQL::Query($sql);
        SQL::execute();
        if(SQL::RowCount() > 0){
        	return SQL::DecryptSingleArray(SQL::$stmt->fetch(PDO::FETCH_ASSOC));
		} else {
			return SQL::$stmt->fetch(PDO::FETCH_ASSOC);
		}
    }

    public static function RowCount(){
        return SQL::$stmt->rowCount();
    }
    
    public static function LastID(){
        return SQL::$dbh->lastInsertId();
    }

    public static function Start(){
        return SQL::$dbh->beginTransaction();
    }
    
    public static function End(){
        return SQL::$dbh->commit();
		SQL::$dbh = null;
    }
    
    public static function Cancel(){
        return SQL::$dbh->rollBack();
		SQL::$dbh = null;
    }
    
    public static function debugDumpParams(){
        return SQL::$stmt->debugDumpParams();
    }
	
	public static function Encrypt($encrypt, $key = 0){
		if($key !== 0){$key = file_get_contents("encryption.inc");}
		$encrypt = serialize($encrypt);
		$iv = mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC), MCRYPT_DEV_URANDOM);
		$mac = hash_hmac('sha256', $encrypt, substr(bin2hex($key), -32));
		$passcrypt = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $key, $encrypt.$mac, MCRYPT_MODE_CBC, $iv);
		$encoded = base64_encode($passcrypt).'|'.base64_encode($iv);
		return $encoded;
	}

	public static function Decrypt($decrypt, $key = 0){
		if($key !== 0){$key = file_get_contents("encryption.inc");}
		$decrypt = explode('|', $decrypt.'|');
		$decoded = base64_decode($decrypt[0]);
		$iv = base64_decode($decrypt[1]);
		if(strlen($iv)!==mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC)){ return false; }
		$decrypted = trim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $key, $decoded, MCRYPT_MODE_CBC, $iv));
		$mac = substr($decrypted, -64);
		$decrypted = substr($decrypted, 0, -64);
		$calcmac = hash_hmac('sha256', $decrypted, substr(bin2hex($key), -32));
		if($calcmac!==$mac){ return false; }
		$decrypted = unserialize($decrypted);
		return $decrypted;
	}
	
	public static function DecryptArray($results){
		$gen_result_array = array();
		foreach($results as $key => $value){
			$gen_result_array[$key] = $value;
			foreach($value as $k=>$v){
				if (!SQL::decrypt($v)){
					$gen_result_array[$key][$k] = $v;
				} else {
					$gen_result_array[$key][$k] = SQL::decrypt($v);
				}
			}
		};
		return $gen_result_array;
	}
	
	public static function DecryptSingleArray($results){
		
			foreach($results as $k=>$v){
				if (!SQL::decrypt($v)){
					$gen_result_array[$k] = $v;
				} else {
					$gen_result_array[$k] = SQL::decrypt($v);
				}
			}
				return $gen_result_array;

	}
    
}
