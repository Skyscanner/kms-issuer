package interfaces

import (
	"context"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
)

type KMSClient interface {
	AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
	GetCryptoKey(ctx context.Context, req *kmspb.GetCryptoKeyRequest, opts ...gax.CallOption) (*kmspb.CryptoKey, error)
	GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...gax.CallOption) (*kmspb.PublicKey, error)
	Close() error
}
