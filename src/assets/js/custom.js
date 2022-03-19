export function signValidator() {
  var text = 'McAfee Endpoint Security\r\n8192\r\n1\r\n0\r\nClassic\r\n154938\r\n0\r\n0\r\nApplication\r\nDT011.mct.local\r\nS-1-5-18\r\nEventID=1120\n\nUpdate in Progress\r\n3/9/2022 8:50:03 PM\r\nMicrosoft Event Log\r\nMicrosoft Event Log System\r\n2022-03-09T20:52:14.0537022+03:00';
  console.log(JSON.stringify(text));
  const md5 = require('md5');
  const shajs = require('sha.js');
  const base64js = require('base64-js');
  const windows1254 = require('windows-1254');
  const saltBytes = [12, 34, 56, 53, 74, 233, 137, 18];
  const encodedPlainText = windows1254.encode(text);
  const plainTextWithSaltBytes = stringToByte(encodedPlainText).concat(saltBytes);
  console.log(plainTextWithSaltBytes);
  var md5Hex = md5(plainTextWithSaltBytes);
  console.log(md5Hex);
  var hashBytes = stringToByte(hex2a(md5Hex));
  var hashWithSaltBytes = hashBytes.concat(saltBytes);
  var resultSha256 = base64js.fromByteArray(hashWithSaltBytes);
  console.log(resultSha256);
  var sha256Hex = shajs('sha256').update(plainTextWithSaltBytes).digest('hex');
  console.log(sha256Hex);
  hashBytes = stringToByte(hex2a(sha256Hex));
  hashWithSaltBytes = hashBytes.concat(saltBytes);
  resultSha256 = base64js.fromByteArray(hashWithSaltBytes);
  console.log(resultSha256);
};

function hex2a(hex) {
  const hexStr = hex.toString();
  let str = '';
  for (let i = 0; i < hex.length; i += 2) {
    str += String.fromCharCode(parseInt(hexStr.substr(i, 2), 16));
  }
  return str;
}

function stringToByte(str) {
  let bytes = [];
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    bytes = bytes.concat([code]);
  }
  return bytes;
}
