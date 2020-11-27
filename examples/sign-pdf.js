var forge = require('..');
const moment = require('moment');
const fs = require('fs');
const buffer = require('buffer');
const Buffer = buffer.Buffer

function signFile(signer, pdf, signDate) {
  const p7 = forge.pkcs7.createSignedData();
  // p7.content = forge.util.createBuffer('Some content to be signed.', 'utf8');
  p7.content = forge.util.createBuffer(pdf.toString("binary"));
  p7.addCertificate(signer.certificate);
  p7.addSigner({
    key: signer.keys.privateKey,
    certificate: signer.certificate,
    digestAlgorithm: forge.pki.oids.dsaWithSHA1,
    // digestAlgorithm: forge.pki.oids.sha256,
    authenticatedAttributes: [
      // {
      //   type: forge.pki.oids.contentType,
      //   value: forge.pki.oids.data,
      // },
      // {
      //   type: forge.pki.oids.messageDigest,
      // },
      // {
      //   type: forge.pki.oids.signingTime,
      //   value: signDate,
      // },
    ],
  });

  // Sign in detached mode.
  p7.sign({ detached: true });
  p7.sign();

  var pem = forge.pkcs7.messageToPem(p7);
  console.log('Signed PKCS #7 message:\n' + pem);
  const raw = forge.asn1.toDer(p7.toAsn1()).getBytes();
  let signature = Buffer.from(raw, "binary").toString("hex");
  return { signature, raw };
}

function signPdf(pdf, signer = {}) {
  const byteRangePos = pdf.indexOf('/ByteRange [0');
  const byteRangeEND = pdf.indexOf(' ]');
  const byteRangeArray = pdf.slice(byteRangePos + 12, byteRangeEND + 1);

  let str = new TextDecoder("utf-8").decode(byteRangeArray);
  let arr = str.split(" ");
  const contentLenghtBeforeSign = parseInt(arr[1], 10); // L1 = Length 1 (Content length before signature)
  const signIndexEnd = parseInt(arr[2], 10); //  O2 = offset 2 (L1 + signature length)
  const contentLenghtAfterSign = parseInt(arr[3], 10); //  L2 = Length 2 (Content length after signature)

  /*
  O1 = offset 1 (zero)
  L1 = Length 1 (Content length before signature)
  O2 = offset 2 (L1 + signature length)
  L2 = Length 2 (Content length after signature)
 */
  const contentSign = pdf.slice(contentLenghtBeforeSign + 1, signIndexEnd - 1);
  if (byteRangePos === -1) {
    throw new Error(
      `Could not find ByteRange placeholder: ${byteRangePos}`,
    );
  }

  // const emptyPlaceholder = Buffer.from(
  //   String.fromCharCode(0).repeat(contentSign.length / 2)
  // ).toString("hex");

  const pdfTmp = Buffer.concat([
    pdf.slice(0, contentLenghtBeforeSign),
    // Buffer.from(`<${emptyPlaceholder}>`),
    pdf.slice(signIndexEnd),
  ]);

  const signDate = new Date('2020-11-25T14:55:03Z');
  // const signDateFormat = moment(signDate).format('YYYYMMDDHHmmss-03\'00\'');
  //
  // const datePosBegin = pdf.indexOf('/M(D:');
  // const datePosEnd = pdf.indexOf(')', datePosBegin);
  //
  // pdf = Buffer.concat([
  //   pdf.slice(0, datePosBegin),
  //   Buffer.from(`/M(D:${signDateFormat})`),
  //   pdf.slice(datePosEnd + 1),
  // ]);

  let { signature, raw } = signFile(
    signer,
    pdfTmp,
    signDate
  );
  const paddSize = contentSign.length / 2 - raw.length;
  if (paddSize < 0) {
    throw new Error('No room on original signature slot to store full signature contents');
  }
  signature += Buffer.from(
    String.fromCharCode(0).repeat(paddSize)
  ).toString("hex");
  pdf = Buffer.concat([
    pdf.slice(0, contentLenghtBeforeSign),
    Buffer.from(`<${signature}>`),
    pdf.slice(signIndexEnd),
  ]);
  return pdf;
}

async function test() {
  try {
    const pdfFile = await fs.readFileSync('../signedByJava.pdf')
    const signer = createSigner('gonzita');
    const p12Asn1 = forge.pkcs12.toPkcs12Asn1(
      signer.keys.privateKey,
      [signer.certificate],
      'password',
      {algorithm: '3des'},
    );
    const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
    // const p12Der = forge.asn1.toDer(p12Asn1);
    await fs.writeFileSync('../keysByNode.p12', p12Der, {encoding: 'binary'});
    const pdfSignedFile = await signPdf(pdfFile, signer, new Date('2050-01-01T00:00:00Z'));
    await fs.writeFileSync('../signedByNode.pdf', pdfSignedFile);
  } catch(ex) {
    if(ex.stack) {
      console.log(ex.stack);
    } else {
      console.log('Error', ex);
    }
  }
}

test();

function createSigner(name) {
  console.log('Creating signer "' + name + '"...');

  // generate a keypair
  console.log('Generating 1024-bit key-pair...');
  const keys = forge.pki.rsa.generateKeyPair(1024);
  console.log('Key-pair created:');
  console.log(forge.pki.privateKeyToPem(keys.privateKey));
  console.log(forge.pki.publicKeyToPem(keys.publicKey));

  // create a certificate
  var certificate = createCertificate(name, keys);
  console.log('Signer "' + name + '" created.');

  return {
    name,
    keys,
    certificate,
  };
}

function createCertificate(name, keys) {
  // create a certificate
  console.log('Creating self-signed certificate...');
  var cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date('2021-10-15');
  cert.validity.notAfter = new Date('2020-01-01');
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
  var attrs = [{
    name: 'commonName',
    value: name
  }, {
    name: 'countryName',
    value: 'US'
  }, {
    shortName: 'ST',
    value: 'Virginia'
  }, {
    name: 'localityName',
    value: 'Blacksburg'
  }, {
    name: 'organizationName',
    value: 'Test'
  }, {
    shortName: 'OU',
    value: 'Test'
  }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([{
    name: 'basicConstraints',
    cA: true
  }, {
    name: 'keyUsage',
    keyCertSign: true,
    digitalSignature: true,
    nonRepudiation: true,
    keyEncipherment: true,
    dataEncipherment: true
  }, {
    name: 'subjectAltName',
    altNames: [{
      type: 6, // URI
      value: 'http://example.org/webid#me'
    }]
  }]);

  // self-sign certificate
  cert.sign(keys.privateKey);
  console.log('Certificate created: \n' + forge.pki.certificateToPem(cert));

  return cert;
}
