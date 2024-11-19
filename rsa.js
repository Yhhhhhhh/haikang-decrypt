const crypto = require('crypto');
const { URL } = require('url');

/**
 * RSA工具类
 */
class RSAUtils {
  constructor() {
    throw new Error('This class cannot be instantiated.');
  }

  static RSA_ALGORITHM = 'RSA';
  static CHARSET = 'utf-8';
  static MAX_ENCRYPT_BLOCK = 117;
  static MAX_DECRYPT_BLOCK = 128;

  /**
   * 应用秘钥加密接口
   * @param {string} data - 需要加密的字符串
   * @param {string} privateKey - 应用的秘钥（私钥）
   * @return {string} - 加密后的字符串
   */
  static encryptByPrivateKey(data, privateKey) {
    const key = this._formatPrivateKey(privateKey);
    const buffer = Buffer.from(encodeURIComponent(data), this.CHARSET);
    const encrypted = [];

    for (let i = 0; i < buffer.length; i += this.MAX_ENCRYPT_BLOCK) {
      const chunk = buffer.slice(i, i + this.MAX_ENCRYPT_BLOCK);
      const encryptedChunk = crypto.privateEncrypt(
        { key, padding: crypto.constants.RSA_PKCS1_PADDING },
        chunk
      );
      encrypted.push(encryptedChunk);
    }

    return Buffer.concat(encrypted).toString('base64');
  }

  /**
   * 应用秘钥解密接口
   * @param {string} data - 需要解密的字符串
   * @param {string} privateKey - 应用的秘钥（私钥）
   * @return {string} - 解密后的字符串
   */
  static decryptByPrivateKey(data, privateKey) {
    const key = this._formatPrivateKey(privateKey);
    const buffer = Buffer.from(data, 'base64');
    const decrypted = [];
    let offset = 0;

    while (offset < buffer.length) {
      const chunk = buffer.slice(offset, offset + this.MAX_DECRYPT_BLOCK);
      const decryptedChunk = crypto.privateDecrypt(
        { key, padding: crypto.constants.RSA_PKCS1_PADDING },
        chunk
      );
      decrypted.push(decryptedChunk);
      offset += this.MAX_DECRYPT_BLOCK;
    }

    const decoded = Buffer.concat(decrypted).toString(this.CHARSET);
    return decodeURIComponent(decoded);
  }

  /**
   * 格式化私钥
   * @param {string} privateKey - PEM 格式私钥
   * @return {string} - 格式化后的私钥
   */
  static _formatPrivateKey(privateKey) {
    if (!privateKey.includes('BEGIN PRIVATE KEY')) {
      return `-----BEGIN PRIVATE KEY-----\n${privateKey}\n-----END PRIVATE KEY-----`;
    }
    return privateKey;
  }
}

module.exports = RSAUtils;
