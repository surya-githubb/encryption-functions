const crypto = require('crypto');

function encryptData(data, secretKey) {
    // crypto.randomBytes(16);
  const sameIv = 'a93080f6d06bfa54bf30035b8cf19380'
  const iv = Buffer.from(sameIv, 'hex');
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(secretKey, 'hex'), iv);
  let encrypted = cipher.update(data, 'utf-8', 'hex');
  encrypted += cipher.final('hex'); //adds padding to flush the data, output format: hex.
  return encrypted;
}

function decryptData(encryptedData, secretKey) {
  const sameIv = 'a93080f6d06bfa54bf30035b8cf19380'
  const iv = Buffer.from(sameIv, 'hex'); // Convert the IV back to a binary buffer from hex.
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(secretKey, 'hex'), iv);
  let decrypted = decipher.update(encryptedData, 'hex', 'utf-8');
  decrypted += decipher.final('utf-8');
  return decrypted;
}

// crypto.randomBytes(32);
// secretKey = 'b489bef6477f82e9166f74f79a1f86cd1808c80057f3ee4ad39f158b5728ec39'
// console.log(encryptData('password', secretKey))
// console.log(decryptData('db44bff322087d75c1f49da678a426af', secretKey))



module.exports = { encryptData, decryptData };
