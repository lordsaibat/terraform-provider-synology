package util

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kdomanski/iso9660"
)

const userDataFileName string = "user-data"
const metaDataFileName string = "meta-data"
const networkConfigFileName string = "network-config"

type CloudInit struct {
	Name          string
	PoolName      string
	MetaData      string `yaml:"meta_data"`
	UserData      string `yaml:"user_data"`
	NetworkConfig string `yaml:"network_config"`
}

func IsoFromFiles(ctx context.Context, isoName string, files map[string]string) ([]byte, error) {
	writer, err := iso9660.NewWriter()

	if err != nil {
		tflog.Error(ctx, fmt.Sprintf("failed to create writer: %v", err))
	}

	for path, content := range files {
		tflog.Info(ctx, fmt.Sprintf("writing iso file for %s", path))

		if len(path) > 0 {
			if err = writer.AddFile(strings.NewReader(path), content); err != nil {
				tflog.Error(ctx, fmt.Sprintf("failed to add metadata file: %v", err))
				return nil, err
			}
		}
	}

	var b bytes.Buffer
	err = writer.WriteTo(&b, fmt.Sprintf("vol%s", isoName))
	if err != nil {
		tflog.Error(ctx, fmt.Sprintf("failed to write ISO image: %s", err))
		return nil, err
	}

	defer func() {
		_ = writer.Cleanup()
	}()

	return b.Bytes(), nil
}

func IsoFromCloudInit(ctx context.Context, ci CloudInit) ([]byte, error) {
	return IsoFromFiles(ctx, ci.Name, map[string]string{
		metaDataFileName:      ci.MetaData,
		userDataFileName:      ci.UserData,
		networkConfigFileName: ci.NetworkConfig,
	})
}

func removeTmpIsoDirectory(ctx context.Context, iso string) {

	err := os.RemoveAll(filepath.Dir(iso))
	if err != nil {
		tflog.Error(ctx, fmt.Sprintf("error while removing tmp directory holding the ISO file: %s", err))
	}
}

// tflog.Print("Creating ISO tmp directory")
// 	tmpDir, err := os.MkdirTemp("", "cloudinit")
// 	if err != nil {
// 		tflog.Fatalf("failed to create tmp directory: %s", err)
// 		return nil, err
// 	}

// 	outputFile, err := os.OpenFile(filepath.Join(tmpDir, fmt.Sprintf("%s.iso", ci.Name)), os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
// 	if err != nil {
// 		tflog.Fatalf("failed to create file: %s", err)
// 		return nil, err
// 	}