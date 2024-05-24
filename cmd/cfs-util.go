/*
	add by cfs
*/

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/confidential-filesystems/filesystem-toolchain/resource"
	"github.com/confidential-filesystems/filesystem-toolchain/wallet"
)

const (
	EnvCRPT              = "controllerCrpToken"
	EnvAttestationReport = "controllerAttestationReport"
	EnvCertChain         = "controllerCertChain"
	MetadataAttester     = "metadata"

	AudienceTypeS3 = "s3"

	EnvCfsAddr = "CFS_ADDR"
	EnvCfsName = "CFS_NAME"
)

func GetSeed(ctx context.Context, aski uint32) (string, error) {
	extra := &resource.ExtraCredential{
		ControllerCrpToken:          os.Getenv(EnvCRPT),
		ControllerAttestationReport: os.Getenv(EnvAttestationReport),
		ControllerCertChain:         os.Getenv(EnvCertChain),
		Attester:                    MetadataAttester,
	}
	//addr := "0x395b8caa3e77c5d0110a671bc8908c299b6872e7"
	addr := os.Getenv(EnvCfsAddr)
	if addr == "" {
		return "", fmt.Errorf("WebDAV: env CFS_ADDR empty")
	}
	kid := resource.KidPrefix + fmt.Sprintf(resource.ResAssk, addr, aski)
	return resource.GetResource(ctx, "http://127.0.0.1:8006", kid, extra)
}

func parseAccessSecret(asStr string) (*wallet.AccessSecretAK, error) {
	ak, err := wallet.ParseAk(asStr)
	if err != nil {
		return nil, err
	}
	return ak, nil
}

func CheckAccessSecret(ctx context.Context, akStr string) (*wallet.AccessSecretAK, string, error) {
	ak, err := parseAccessSecret(akStr)
	if err != nil {
		return nil, "", fmt.Errorf("s3-gateway: Access Secret ak parse error: %w", err)
	}
	asskStr, err := GetSeed(ctx, ak.Aski)
	if err != nil {
		return nil, "", fmt.Errorf("s3-gateway: GetSeed error: %w", err)
	}
	assk := []byte(asskStr)
	//verify ak
	if !ak.IsValid(assk) {
		return nil, "", fmt.Errorf("s3-gateway: Access Secret ak invalid")
	}
	//calc sk
	fsName := os.Getenv(EnvCfsName)
	if fsName == "" {
		return nil, "", fmt.Errorf("s3-gateway: env CFS_NAME empty")
	}
	calcSkStr, err := wallet.NewAccessSecretSk(assk, fsName, AudienceTypeS3)
	if err != nil {
		return nil, "", fmt.Errorf("s3-gateway: calc sk error: %w", err)
	}

	return ak, calcSkStr, nil
}
