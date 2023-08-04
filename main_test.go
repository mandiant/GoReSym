/*Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.*/
package main

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/pkg/profile"
)

var versions = []string{"117", "116", "115", "114", "113", "112", "111", "110", "19", "18", "17", "16", "15"}
var fileNames = []string{"testproject_lin", "testproject_lin_32", "testproject_lin_stripped", "testproject_lin_stripped_32", "testproject_mac", "testproject_mac_stripped", "testproject_win_32.exe", "testproject_win_stripped_32.exe", "testproject_win_stripped.exe", "testproject_win.exe"}

func TestAllVersions(t *testing.T) {
	defer profile.Start(profile.ProfilePath(".")).Stop()

	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Errorf("Failed to get working directory")
	}

	fmt.Println(workingDirectory)

	for _, v := range versions {
		for _, file := range fileNames {
			versionPath := fmt.Sprintf("%s/%s", v, file)
			filePath := fmt.Sprintf("%s/test/build/%s", workingDirectory, versionPath)
			if _, err := os.Stat(filePath); errors.Is(err, os.ErrNotExist) {
				fmt.Printf("Test file %s doesn't exist\n", filePath)
				continue
			}

			t.Run(versionPath, func(t *testing.T) {
				data, err := main_impl(filePath, true, true, true, 0, "")
				if err != nil {
					t.Errorf("Go %s failed on %s: %s", v, file, err)
				}

				if data.TabMeta.VA == 0 {
					t.Errorf("Go %s pclntab location failed on %s: %s", v, file, err)
				}

				if data.ModuleMeta.VA == 0 {
					t.Errorf("Go %s moduledata location failed on %s: %s", v, file, err)
				}

				if len(data.Types) == 0 {
					t.Errorf("Go %s type parsing failed on %s: %s", v, file, err)
				}

				// unsupported
				if v != "15" && v != "16" {
					if len(data.Interfaces) == 0 {
						t.Errorf("Go %s interface parsing failed on %s: %s", v, file, err)
					}
				}

				if len(data.StdFunctions) == 0 {
					t.Errorf("Go %s std functions failed on %s: %s", v, file, err)
				}

				if len(data.UserFunctions) == 0 {
					t.Errorf("Go %s user functions failed on %s: %s", v, file, err)
				}

				if len(data.Files) == 0 {
					t.Errorf("Go %s files failed on %s: %s", v, file, err)
				}

				if data.Version == "" {
					t.Errorf("Go %s version failed on %s: %s", v, file, err)
				}

				if data.OS == "" {
					t.Errorf("Go %s OS failed on %s: %s", v, file, err)
				}

				if data.Arch == "" {
					t.Errorf("Go %s Arch failed on %s: %s", v, file, err)
				}
			})
		}
	}
}
