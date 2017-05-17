'use strict';

const AWS = require('aws-sdk'),
  pem = require('pem'),
  promisify = require('es6-promisify');

const region = process.env['REGION'],
  prefix = process.env['STAGE'] + '/';

const readCertificateInfo = promisify(pem.readCertificateInfo);

module.exports.main = (event, context, callback) => {
  const s3 = new AWS.S3({region: region});
  const acm = new AWS.ACM({region: region});

  const existingCerts = acm.listCertificates({MaxItems: 1000}).promise().then(resp => resp.CertificateSummaryList);

  const existingCert = (cert) =>
    existingCerts.then(ec => readCertificateInfo(cert).then(certinfo => {
      const found = ec.find(c => c.DomainName === certinfo.commonName);
      return found ? found.CertificateArn : null;
    }));

  const handleCert = (bucket, key) => {
    return s3.getObject({Bucket: bucket, Key: key}).promise()
    .then(obj => JSON.parse(obj.Body))
    .then(cert => existingCert(cert.cert).then(arn => {
      return acm.importCertificate({
        CertificateArn: arn,
        Certificate: cert.cert,
        CertificateChain: cert.issuerCert,
        PrivateKey: cert.key.privateKeyPem
      }).promise();
    }));
  };

  console.log(JSON.stringify(event));
  const records = event.Records.map(r => JSON.parse(r.Sns.Message).Records);
  Promise.all([].concat(...records)
    .filter(r => r.s3.object.key.startsWith(prefix))
    .map(r => handleCert(r.s3.bucket.name, r.s3.object.key)))
  .then(success => callback(null, success), e => callback(e));
};
