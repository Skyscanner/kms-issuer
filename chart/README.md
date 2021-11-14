# kms-controller chart

* pre-requsites - 
    1. create kms-key from terraform or manualy
    2. create role with webidentity from terraform or manualy
    3. create namespace from terraform or manualy
    4. run crd files (make install) or from terrafrom

* terrafrom example:

```terraform
data "kubernetes_all_namespaces" "kms-issuer-system" {}
resource "kubernetes_namespace" "kms-issuer-system" {
  # Only create namespace if namespace does not exist
  count = contains([data.kubernetes_all_namespaces.kms-issuer-system.namespaces], "kms-issuer-system") ? 0 : 1
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

  }
}

resource "null_resource" "install_kms_controller_crd" {
  provisioner "local-exec" {
    command = "kubectl apply -k ./config/crd"
    interpreter = ["/bin/bash", "-c"]
  }
}

resource "helm_release" "kms_controller" {
  depends_on  = [ null_resource.install_kms_controller_crd ]
  name        = "kms-issuer"
  chart       = "./chart/kms-controller"
  namespace   = "kms-issuer-system"
  cleanup_on_fail = true

    set {
      name  = "serviceAccount.arnRole"
      value = "${module.oidc_kms_issuer.oidc_arn}"
    }
    
    # the value must be 'alias/<KSM_KEY_ALIAS>'
    set {
      name  = "kmskeyID"
      value = "${aws_kms_alias.aws_kms_alias.name}"
    }

  }


```


* install manuly:


    ```
    helm upgrade kms-issuer . -n kms-issuer-system --set "serviceAccount.arnRole=<ARN_ROLE>" --set "kmskeyID=<KMS_KEY_ALIAS>"
    ```