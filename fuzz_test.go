package sdhash

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func FuzzParseSdbfFromString(f *testing.F) {
	// 1. Valid stream digest
	payload256 := base64.StdEncoding.EncodeToString(make([]byte, 256))
	f.Add(fmt.Sprintf("sdbf:03:1:-:1048576:sha1:256:5:7ff:160:1:100:%s\n", payload256))

	// 2. Valid DD digest
	f.Add(fmt.Sprintf("sdbf-dd:03:1:-:1048576:sha1:256:5:7ff:192:1:1048576:c0:%s\n", payload256))

	// 3. Empty string
	f.Add("")

	// 4. Truncated digest
	f.Add("sdbf:03:")

	// 5. Unsupported version
	f.Add("sdbf:99:1:-:1048576:sha1:256:5:7ff:160:1:100:\n")

	// 6. Oversized maxElem (the #19 attack)
	payload512 := base64.StdEncoding.EncodeToString(make([]byte, 512))
	f.Add(fmt.Sprintf("sdbf:03:1:-:1048576:sha1:256:5:7ff:2147483649:2:0:%s\n", payload512))

	// 7. Oversized bfCount
	f.Add("sdbf:03:1:-:1048576:sha1:256:5:7ff:160:999999999:100:\n")

	// 8. Zero bfSize
	f.Add("sdbf:03:1:-:1048576:sha1:0:5:7ff:160:1:100:\n")

	// 9. Wrong bfSize
	f.Add("sdbf:03:1:-:1048576:sha1:512:5:7ff:160:1:100:\n")

	// 10. Unrecognized magic
	f.Add("badmagic:03:1:-:1048576:sha1:256:5:7ff:160:1:100:\n")

	f.Fuzz(func(t *testing.T, input string) {
		sd, err := ParseSdbfFromString(input)
		if err != nil {
			return // parse errors are expected and fine — panics are not
		}
		// If parsing succeeded, exercise every method to ensure none panic.
		_ = sd.String()
		_ = sd.Size()
		_ = sd.InputSize()
		_ = sd.FilterCount()
		_ = sd.FeatureDensity()
		_ = sd.Compare(sd)
	})
}
