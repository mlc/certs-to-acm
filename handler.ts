import { GetObjectCommand, S3Client } from '@aws-sdk/client-s3';
import {
  ACMClient,
  CertificateSummary,
  ImportCertificateCommand,
  paginateListCertificates,
} from '@aws-sdk/client-acm';
import getStream from 'get-stream';
import { readCertificateInfo, CertificateSubjectReadResult } from 'pem';
import { promisify } from 'util';

const region = process.env['REGION'];
const prefix = process.env['STAGE'] + '/';

const asyncReadCertificateInfo = promisify<
  string,
  CertificateSubjectReadResult
>(readCertificateInfo);

const s3 = new S3Client({ region });
const acm = new ACMClient({ region });

const existingCert = async (
  cert: string,
  existingCerts: CertificateSummary[]
): Promise<string | undefined> => {
  const certInfo = await asyncReadCertificateInfo(cert);
  return existingCerts.find((c) => c.DomainName === certInfo.commonName)
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
  const arn = await existingCert(cert.cert, existingCerts);
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
