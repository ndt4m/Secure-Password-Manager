
/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Arguments:
   *  You may design the constructor with any parameters you would like. 
   * Return Type: void
   */
  constructor(kvs, masterSalt, hmacSalt, aesSalt, masterKey, hmacKey, aesKey, magic) {
    this.data = {
        masterSalt: masterSalt,
        hmacSalt: hmacSalt,
        aesSalt: aesSalt,
        magic: magic,
        kvs: kvs
    }; 
    // Store member variables that you intend to be public here
    this.secrets = { 
        masterKey: masterKey,
        hmacKey: hmacKey,
        aesKey: aesKey  
    };
    // Store member variables that you intend to be private here
  
  };

  /** 
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: Keychain
    */
  static async init(password) {
    // Generate salts
    const masterSalt = getRandomBytes(16);
    

    // Derive master key from password
    const rawKey  = await subtle.importKey("raw", stringToBuffer(password), "PBKDF2", false, ["deriveKey"]);
    const masterKey = await subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: masterSalt,
      iterations: PBKDF2_ITERATIONS
    }, 
    rawKey,
    {
        name: "HMAC",
        hash: "SHA-256",
        length: 256
    }, 
    false,
    ["sign"]);

    // Derive hmac key and aes key from master key
    const hmacSalt = getRandomBytes(16);
    const hmacSaltDigest = await subtle.sign("HMAC", masterKey, hmacSalt);
    const hmacKey = await subtle.importKey("raw", stringToBuffer(hmacSaltDigest), {name: "HMAC", hash: "SHA-256", length: 256}, false, ["sign", "verify"]);

    const aesSalt = getRandomBytes(16);
    const aesSaltDigest = await subtle.sign("HMAC", masterKey, aesSalt);
    const aesKey = await subtle.importKey("raw", stringToBuffer(aesSaltDigest), {name: "AES-GCM"}, false, ["encrypt", "decrypt"]);

    const iv = getRandomBytes(16);

    let encrypt = await subtle.encrypt({name: "AES-GCM", iv: iv}, aesKey, stringToBuffer("realPassword"));
 
    
    let magic = encodeBuffer(iv) + encodeBuffer(encrypt);
    
  
   
    
    // Return initialized keychain
    return new Keychain({}, encodeBuffer(stringToBuffer(masterSalt)), encodeBuffer(stringToBuffer(hmacSalt)), encodeBuffer(stringToBuffer(aesSalt)), masterKey, hmacKey, aesKey, magic);
  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr. 
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {

    let storeDigest = await subtle.digest("SHA-256", stringToBuffer(repr));

    if (trustedDataCheck !== undefined && encodeBuffer(storeDigest) != trustedDataCheck)
    {   
        throw new Error("Integrity check failed!");
    }
    let new_keychain = JSON.parse(repr);

    const rawKey  = await subtle.importKey("raw", stringToBuffer(password), "PBKDF2", false, ["deriveKey"]);
    const masterKey = await subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: decodeBuffer(new_keychain.masterSalt),
      iterations: PBKDF2_ITERATIONS
    }, 
    rawKey,
    {
        name: "HMAC",
        hash: "SHA-256",
        length: 256
    }, 
    false,
    ["sign"]);
    const hmacSaltDigest = await subtle.sign("HMAC", masterKey, decodeBuffer(new_keychain.hmacSalt));
    const hmacKey = await subtle.importKey("raw", stringToBuffer(hmacSaltDigest), {name: "HMAC", hash: "SHA-256", length: 256}, false, ["sign", "verify"]);

    const aesSaltDigest = await subtle.sign("HMAC", masterKey, decodeBuffer(new_keychain.aesSalt));
    const aesKey = await subtle.importKey("raw", stringToBuffer(aesSaltDigest), {name: "AES-GCM"}, false, ["encrypt", "decrypt"]);
    
   
    let iv = decodeBuffer(new_keychain.magic.slice(0, 24));
    let encryptedMagic = decodeBuffer(new_keychain.magic.slice(24));

    let decryptMagic = await subtle.decrypt({name: "AES-GCM", iv: iv}, aesKey, encryptedMagic);
  
    if (bufferToString(decryptMagic) === "realPassword")
    {
      return new Keychain(new_keychain.kvs, new_keychain.masterSalt, new_keychain.hmacSalt, new_keychain.aesSalt, masterKey, hmacKey, aesKey, new_keychain.magic, true);
    }
    return false;
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */ 
  async dump() {
    let encoded_store = JSON.stringify(this.data);
    let checksum = await subtle.digest("SHA-256", stringToBuffer(encoded_store));
    let base64Checksum = encodeBuffer(checksum);

    return [encoded_store, base64Checksum];
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    let hmacDomain = await subtle.sign("HMAC", this.secrets.hmacKey, stringToBuffer(name));
    let base64DomainKey = encodeBuffer(stringToBuffer(hmacDomain));

    if (!this.data.kvs[base64DomainKey]) {
      return null;
    }

    let value = this.data.kvs[base64DomainKey];
    let base64_iv = value.iv;
    let base64_pwd = value.pwd;
    let tag = decodeBuffer(value.tag);

    let key_val = base64DomainKey + base64_iv + base64_pwd;
    
    let isValid = await subtle.verify("HMAC", this.secrets.hmacKey, tag, stringToBuffer(key_val));
    if (!isValid)
    {
        throw "Swap attack????? Not so easyyy!!";
    }

    let padding_pwd = await subtle.decrypt({name: "AES-GCM", iv: decodeBuffer(base64_iv)}, this.secrets.aesKey, decodeBuffer(base64_pwd));
    let str_padding_pwd = bufferToString(padding_pwd);
    let paddingNumber = str_padding_pwd.charCodeAt(str_padding_pwd.length - 1);
    
    if (paddingNumber < 1 || paddingNumber > MAX_PASSWORD_LENGTH) 
    {
        paddingNumber = 0;
    }

    for (let i = str_padding_pwd.length - paddingNumber; i < str_padding_pwd.length; i++) 
    {
        if (str_padding_pwd.charCodeAt(i) !== paddingNumber) 
        {
            paddingNumber = 0;
            break;
        }
    }

    let pwd = str_padding_pwd.slice(0, str_padding_pwd.length - paddingNumber);
    
    return pwd;
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
    let hmacDomain = await subtle.sign("HMAC", this.secrets.hmacKey, stringToBuffer(name));
    let base64DomainKey = encodeBuffer(stringToBuffer(hmacDomain));
    
    let paddedValue = value.padEnd(MAX_PASSWORD_LENGTH, String.fromCharCode(MAX_PASSWORD_LENGTH - value.length));
    let iv = getRandomBytes(16);
    let base64_iv = encodeBuffer(stringToBuffer(iv));
    let encryptedValue = await subtle.encrypt({name: "AES-GCM", iv: iv}, this.secrets.aesKey, stringToBuffer(paddedValue));
    let base64EncryptedValue = encodeBuffer(stringToBuffer(encryptedValue));

    let key_val = base64DomainKey + base64_iv + base64EncryptedValue;
    let tag = await subtle.sign("HMAC", this.secrets.hmacKey, stringToBuffer(key_val));
    let base64Tag = encodeBuffer(stringToBuffer(tag));

    this.data.kvs[base64DomainKey] = {iv: base64_iv, pwd: base64EncryptedValue, tag: base64Tag};
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    let hmacDomain = await subtle.sign("HMAC", this.secrets.hmacKey, stringToBuffer(name));
    let base64DomainKey = encodeBuffer(stringToBuffer(hmacDomain));

    if (!this.data.kvs[base64DomainKey]) 
    {
      return false;
    }

    delete this.data.kvs[base64DomainKey];
    return true;
  };
};

module.exports = { Keychain }
