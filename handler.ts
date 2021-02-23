import { S3 } from '@aws-sdk/client-s3';
import { ACM, CertificateSummary } from '@aws-sdk/client-acm';
import getStream from 'get-stream';
import * as pem from 'pem';
import { promisify } from 'util';

const region = process.env['REGION'];
const prefix = process.env['STAGE'] + '/';

const readCertificateInfo = promisify<string, pem.CertificateSubjectReadResult>(
  pem.readCertificateInfo
);

const s3 = new S3({ region });
const acm = new ACM({ region });

const existingCert = async (
  cert: string,
  existingCerts: CertificateSummary[]
): Promise<string | undefined> => {
  const certInfo = await readCertificateInfo(cert);
  return existingCerts.find((c) => c.DomainName === certInfo.commonName)
    ?.CertificateArn;
};

const handleCert = async (
  Bucket: string,
  Key: string,
  existingCerts: CertificateSummary[]
) => {
  const { Body } = await s3.getObject({ Bucket, Key });
  const certJson = await getStream(Body);
  const cert = JSON.parse(certJson);
  const arn = await existingCert(cert.cert, existingCerts);
  return acm.importCertificate({
    CertificateArn: arn,
    Certificate: cert.cert,
    CertificateChain: cert.issuerCert,
    PrivateKey: cert.key.privateKeyPem,
  });
};

export const main: AWSLambda.SNSHandler = async (event) => {
  const existingCerts = await acm
    .listCertificates({ MaxItems: 1000 })
    .then((resp) => resp.CertificateSummaryList);

  console.log(JSON.stringify(event));

  const records = event.Records.map(
    (r) => JSON.parse(r.Sns.Message).Records
  ).flat() as AWSLambda.S3EventRecord[];

  await Promise.all(
    records
      .filter((r) => r.s3.object.key.startsWith(prefix))
      .map((r) => handleCert(r.s3.bucket.name, r.s3.object.key, existingCerts ?? []))
  );
};
