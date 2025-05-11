# veil

> **Verified Entity Identity Lock** (Expose hidden trust paths in your AWS IAM setup before they become security risks.)

> [!NOTE]
> This tool finds IAM principals in your AWS account that can assume a specific permission and returns them as a JSON
> list.
> Super handy for auditing trust relationships and spotting who has access to what.

```shell
$ veil -h
Usage veil:
  -region string
        AWS region used for IAM communication (default "eu-west-1")
  -verbose
        verbose log output
  -version
        show version
```

### Installation

#### From source

```shell
# via the Go toolchain
go install github.com/wakeful/veil
```

#### Using a binary release

You can download a pre-built binary from the [release page](https://github.com/wakeful/veil/releases/latest) and add it
to your user PATH.

### Example scenario

Let's run `veil` against the current AWS account.

```shell
$ veil | tee output
```

We should get back a similar response.

```json
{
  "apidestinations.events.amazonaws.com": [
    "arn:aws:iam::CurrentAccountID:role/aws-service-role/apidestinations.events.amazonaws.com/AWSServiceRoleForAmazonEventBridgeApiDestinations"
  ],
  "apprunner.amazonaws.com": [
    "arn:aws:iam::CurrentAccountID:role/aws-service-role/apprunner.amazonaws.com/AWSServiceRoleForAppRunner"
  ],
  "arn:aws:iam::OurOrgMasterAccountID:root": [
    "arn:aws:iam::CurrentAccountID:role/OrganizationAccountAccessRole"
  ],
  "arn:aws:iam::UnknownAccountID:root": [
    "arn:aws:iam::CurrentAccountID:role/OrganizationAccountAccessRole"
  ],
  "arn:aws:iam::CurrentAccountID:oidc-provider/token.actions.githubusercontent.com": [
    "arn:aws:iam::CurrentAccountID:role/github"
  ],
  "arn:aws:iam::CurrentAccountID:saml-provider/AWSSSO_bc4a1d0eeaf11feb_DO_NOT_DELETE": [
    "arn:aws:iam::CurrentAccountID:role/aws-reserved/sso.amazonaws.com/eu-west-1/AWSReservedSSO_ViewOnlyAccess_de8667700c107932",
    "arn:aws:iam::CurrentAccountID:role/aws-reserved/sso.amazonaws.com/eu-west-1/AWSReservedSSO_FullAdmin_7b2592782fd2ce48"
  ],
  "arn:aws:iam::ThirdPartyVendorAccountID:root": [
    "arn:aws:iam::CurrentAccountID:role/ViewOnlyRole",
    "arn:aws:iam::CurrentAccountID:role/aws-service-role/rds.amazonaws.com/AWSServiceRoleForRDS"
  ],
  "autoscaling.amazonaws.com": [
    "arn:aws:iam::CurrentAccountID:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
  ],
  "ecs.amazonaws.com": [
    "arn:aws:iam::CurrentAccountID:role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS"
  ],
  "elasticache.amazonaws.com": [
    "arn:aws:iam::CurrentAccountID:role/aws-service-role/elasticache.amazonaws.com/AWSServiceRoleForElastiCache"
  ],
  "grafana.amazonaws.com": [
    "arn:aws:iam::CurrentAccountID:role/aws-service-role/grafana.amazonaws.com/AWSServiceRoleForAmazonGrafana"
  ],
  "ops.apigateway.amazonaws.com": [
    "arn:aws:iam::CurrentAccountID:role/aws-service-role/ops.apigateway.amazonaws.com/AWSServiceRoleForAPIGateway"
  ],
  "organizations.amazonaws.com": [
    "arn:aws:iam::CurrentAccountID:role/aws-service-role/organizations.amazonaws.com/AWSServiceRoleForOrganizations"
  ],
  "rds.amazonaws.com": [
    "arn:aws:iam::CurrentAccountID:role/aws-service-role/rds.amazonaws.com/AWSServiceRoleForRDS"
  ],
  "schemas.amazonaws.com": [
    "arn:aws:iam::CurrentAccountID:role/aws-service-role/schemas.amazonaws.com/AWSServiceRoleForSchemas"
  ],
  "sso.amazonaws.com": [
    "arn:aws:iam::CurrentAccountID:role/aws-service-role/sso.amazonaws.com/AWSServiceRoleForSSO"
  ],
  "support.amazonaws.com": [
    "arn:aws:iam::CurrentAccountID:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport"
  ],
  "trustedadvisor.amazonaws.com": [
    "arn:aws:iam::CurrentAccountID:role/aws-service-role/trustedadvisor.amazonaws.com/AWSServiceRoleForTrustedAdvisor"
  ]
}
```

> [!TIP]
> We can now audit the principals that have access to our account. We can also leverage `jq` to quickly extract the AWS
> account IDs, which we can later compare against our trusted list.

```shell
$ cat output | jq -r 'keys.[]' | grep "^arn:" | cut -d ":" -f 5 | sort | uniq
CurrentAccountID
OurOrgMasterAccountID
ThirdPartyVendorAccountID
UnknownAccountID
```
