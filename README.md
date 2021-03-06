certs-to-acm
============

This is a small AWS lambda for taking SSL certificates from [Let's Encrypt][] as
generated by [node-letsencrypt-lambda][] and storing them in the
[AWS Certificate Manager][].

When a certificate is generated or renewed, `certs-to-acm` will (if configured
appropriately) notice and store the new certificate in ACM for further use. If
a certificate with the same "common name" already exists in ACM, that
certificate will be replaced with the new one, for your ease in renewal
handling.

You could also consider [iam-server-cert-lambda][] to see if it meets your needs
better than this, but, among other disadvantages, that is written in scala and
this isn't.

Setup
-----

Install the [serverless framework][], and all dependencies of this lambda:
```
$ npm install -g serverless
$ npm install
```

Make sure you have an IAM role set up. Attach the `AWSCertificateManagerFullAccess`
managed policy to it, and also make sure it can write CloudWatch logs (as is
needed by lambdas by default) and that it can read the S3 bucket in which your
certificates are stored. I found it easiest to reuse the role created for
`node-letsencrypt-lambda` to run under, but it would be slightly more proper to
make a new role.

Then, make sure than S3 is configured such that `PUT` operation to your
certificate bucket are delivered to an SNS topic, as described in the
`node-letsencrypt-lambda` documentation.

Copy `serverless.yml.example` to `serverless.yml`, and fill in the IAM role
and SNS topic ARNs you generated above. Set the `stage` to be the same as the
`s3-folder` from `node-letsencrypt-lambda`.

(Probably you want to put this script and all related resources in the
`us-east-1` region, as required for ACM certificates which will be used with
Cloudfront. But if your needs differ, you can use the region of your choice.)

Deploy by doing:
```
sls deploy
```

Enjoy!

[Let's Encrypt]: https://letsencrypt.org/
[node-letsencrypt-lambda]: https://github.com/ocelotconsulting/node-letsencrypt-lambda
[AWS Certificate Manager]: https://aws.amazon.com/certificate-manager/
[iam-server-cert-lambda]: https://github.com/ocelotconsulting/iam-server-cert-lambda
[serverless framework]: https://serverless.com/framework/
