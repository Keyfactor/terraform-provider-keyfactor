terraform {
    required_providers {
        keyfactor = {
            version = "~> 1.0.1"
            source  = "keyfactor.com/keyfactordev/keyfactor"
        }
        aws = {
            source  = "hashicorp/aws"
            version = "~> 3.0"
        }
    }
}

provider "keyfactor" {
    alias = "command"
    hostname = "keyfactor.example.com"
    kf_username = "username"
    kf_password = "password"
    dev_mode = true
}

provider "aws" {
    region = "us-east-1"
    access_key = "key"
    secret_key = "key"
}

resource "keyfactor_certificate" "PFXCertificate" {
    provider                            = keyfactor.command
    certificate {
        revoke_on_destroy               = true
        subject {
            subject_common_name         = "example.com"
            subject_organization        = "example"
            subject_locality            = "Antarctica"
            subject_country             = "E"
            subject_organizational_unit = "IT"
            subject_state               = "NA"
        }
        sans {
            san_ip4                     = ["192.168.123.2", "172.51.2.4"]
            san_uri                     = ["example.com"]
            san_dns                     = ["0.0.0.0"]
            san_uri                     = ["*.example.com"]
        }
        metadata {
            name                       = "Department"
            value                      = "IT"
        }
        metadata {
            name                       = "Email-Contact"
            value                      = "example@example.com"
        }
        key_password                    = "#epicPassw0rd101!"
        certificate_authority           = "CA 1"
        cert_template                   = "WebServer1yr"
        certificate_format              = "PEM"
    }
}

resource "aws_iot_certificate" "cert" {
    active = true
    certificate_pem = keyfactor_certificate.PFXCertificate.certificate[0].certificates[0]
}