import { GetObjectCommand, S3Client } from '@aws-sdk/client-s3';
import {
  ACMClient,
  CertificateSummary,
  ImportCertificateCommand,
  paginateListCertificates,
} from '@aws-sdk/client-acm';
import { Certificate } from '@fidm/x509';
import getStream from 'get-stream';

const region = process.env['REGION'];
const prefix = process.env['STAGE'] + '/';

const s3 = new S3Client({ region });
const acm = new ACMClient({ region });

interface Jwk {
  kty: string;
  n: string;
  e: string;
}

interface PrivateJwk extends Jwk {
  d: string;
  p: string;
  q: string;
  dp: string;
  dq: string;
  qi: string;
}

interface LECert {
  cert: string;
  issuerCert: string;
  key: {
    privateKeyPem: string;
    publicKeyPem: string;
    privateKeyJwk: PrivateJwk;
    publicKeyJwk: Jwk;
  };
}

const existingCert = (
  cert: Buffer,
  existingCerts: CertificateSummary[]
): string | undefined => {
  const certInfo = Certificate.fromPEM(cert);
  return existingCerts.find((c) => c.DomainName === certInfo.subject.commonName)
    ?.CertificateArn;
};

const handleCert = async (
  Bucket: string,
  Key: string,
  existingCerts: CertificateSummary[]
) => {
  const { Body } = await s3.send(new GetObjectCommand({ Bucket, Key }));
  const certJson = await getStream(Body);
  const leCert = JSON.parse(certJson) as LECert;
  const cert = Buffer.from(leCert.cert);
  const arn = existingCert(cert, existingCerts);
  return acm.send(
    new ImportCertificateCommand({
      CertificateArn: arn,
      Certificate: cert,
      CertificateChain: Buffer.from(leCert.issuerCert),
      PrivateKey: Buffer.from(leCert.key.privateKeyPem),
    })
  );
};

const getAllCerts = async (): Promise<CertificateSummary[]> => {
  const certs: CertificateSummary[][] = [];
  for await (const page of paginateListCertificates({ client: acm }, {})) {
    certs.push(page.CertificateSummaryList ?? []);
  }
  return certs.flat();
};

export const main: AWSLambda.SNSHandler = async (event) => {
  console.log(JSON.stringify(event));

  const existingCerts = await getAllCerts();

  const records = event.Records.map(
    (r) => JSON.parse(r.Sns.Message).Records
  ).flat() as AWSLambda.S3EventRecord[];

  await Promise.all(
    records
      .filter((r) => r.s3.object.key.startsWith(prefix))
      .map((r) => handleCert(r.s3.bucket.name, r.s3.object.key, existingCerts))
  );
};
