# kms-controller chart

* terrafrom example:

```terraform
resource "kubernetes_namespace" "kms-issuer-system" {
  metadata {
      name = "kms-issuer-system"
    }
  }

resource "aws_kms_key" "kms_key" {
  description               = "KMS key for eks cluster internal use"
  deletion_window_in_days   = 10
  key_usage                 = "SIGN_VERIFY"
  customer_master_key_spec  = "RSA_2048"

  tags = {
    "name" = "example_kms_key"
  }  
}

resource "aws_kms_alias" "aws_kms_alias" {
  name          = "alias/example_kms_key"
  target_key_id = aws_kms_key.kms_key.key_id
}

data "aws_iam_policy_document" "example_policy" {
  statement {
    sid = "Allow use of the key"
    actions   = [
        "kms:DescribeKey",
        "kms:GetPublicKey",
        "kms:Sign",
        "kms:Verify"
        ]
    resources = ["${aws_kms_key.kms_key.arn}"]
  }

  statement {
    sid = "Allow attachment of persistent resources"
    actions =  [
        "kms:CreateGrant",
        "kms:ListGrants",
        "kms:RevokeGrant"
      ]
      resources = ["${aws_kms_key.kms_key.arn}"]
      condition {
        test = "Bool"
        variable = "kms:GrantIsForAWSResource"
        values = ["true"]
        }
  }
}

module "iam_assumable_role_with_oidc" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role-with-oidc"
  version = "~> 3.0"

  create_role = true
  role_policy_arns = [aws_iam_policy.example_policy.arn]
  role_name = "example_role"
  provider_url = <YOUR_OIDC>
  tags = {
    "name" = "kms-issuer-role"
  }
}


resource "helm_release" "kms_controller" {
  name        = "kms-contoller"
  chart       = "./chart/kms-controller"
  namespace   = "kms-issuer-system"
  cleanup_on_fail = true

    set {
      name  = "serviceAccount.arnRole"
      value = "${module.iam_assumable_role_with_oidc.iam_role_arn}"
    }
  }

  resource "helm_release" "kms_issuer" {
  name        = "kms-issuer"
  chart       = "./chart/kms-issuer"
  namespace   = "<APP_NAMESPACE>"
  cleanup_on_fail = true
   # the value must be 'alias/<KSM_KEY_ALIAS>'
    set {
      name  = "keyID"
      value = "${aws_kms_alias.aws_kms_alias.name}"
    }

```


* install manuly:


    ```
    helm upgrade kms-issuer . -n kms-issuer-system --set "serviceAccount.arnRole=<ARN_ROLE>" --set "keyID=<KMS_KEY_ALIAS>"
    ```