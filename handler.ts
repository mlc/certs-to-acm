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

const existingCert = (
  cert: string,
  existingCerts: CertificateSummary[]
): string | undefined => {
  const certInfo = Certificate.fromPEM(Buffer.from(cert));
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
  const cert = JSON.parse(certJson);
  const arn = existingCert(cert.cert, existingCerts);
  return acm.send(
    new ImportCertificateCommand({
      CertificateArn: arn,
      Certificate: cert.cert,
      CertificateChain: cert.issuerCert,
      PrivateKey: cert.key.privateKeyPem,
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
