//go:build corpushash || corpuscompare

package sdhash

// generatecorpus_test.go — shared corpus generation, digest-row capture, and
// SHA-256 anchor accumulation for the corpushash and corpuscompare tests.
//
// This file is a faithful in-package port of three external tools that
// together define the reference pipeline:
//
//   1. bindatagenerator — deterministic PRNG corpus generator. The generator
//      functions below (genRandom … genJavaScriptEmbeddedHex, generateSizes,
//      and all their helpers) are copied verbatim from that tool so the bytes
//      produced here are identical to the bytes it writes to disk.
//
//   2. sdhashtest — walks a corpus, computes stream and DD digests, and emits
//      CSV rows. The row schemas and field formatting reproduced here
//      (buildStreamDigestRow, buildDDDigestRow, buildCompareRow) match that
//      tool's `-l` (corpushash) and `-f` (corpuscompare) output exactly.
//
//   3. csvhash — accumulates the CSV rows into a single order-independent
//      SHA-256 "anchor" using a three-tier construction (per-row canonical
//      record → per-bucket hash of sorted records → final hash of sorted
//      bucket hashes). computeCorpusAnchor reproduces that construction.
//
// Because every stage is deterministic, the CSV data itself never needs to be
// stored in the repository: regenerating the corpus and re-accumulating the
// anchor reproduces the same 32-byte value, and any regression in generation,
// digest computation, or scoring changes it.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// ===========================================================================
// Section 1 — Data generators (verbatim port of bindatagenerator)
//
// The code from here to the end of Section 1 is copied without modification
// from the bindatagenerator tool. Do not edit it by hand: it is the byte-for-
// byte source of truth for the corpus, and any divergence silently changes
// the generated data and therefore every anchor. The only omission is the
// tool's main()/config machinery and the unused humanSize helper.
// ===========================================================================

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

// ---------- generators ----------

// genRandom produces purely random bytes (high entropy, uniform distribution)
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

// genSubfloorEntropy produces near-zero entropy data by filling a buffer with
// one dominant byte value and scattering a second byte value at a very low
// frequency. The minority byte's presence is varied uniformly across
// 0.001%–0.5% of positions per file, spreading files across the 0–0.1 bit
// entropy range rather than collapsing them all to zero.
func genSubfloorEntropy(rng *rand.Rand, size int) []byte {
	buf := make([]byte, size)

	// Pick two distinct byte values
	dominant := byte(rng.Uint32())
	minority := byte(rng.Uint32())
	for minority == dominant {
		minority = byte(rng.Uint32())
	}

	// Fill entirely with the dominant byte
	for i := range buf {
		buf[i] = dominant
	}

	// Scatter the minority byte at a frequency in [0.0001%, 0.05%) — chosen
	// uniformly per file. This spreads files across the 0–0.006 bit entropy
	// range, filling the gap below the low_entropy floor.
	freq := 0.000001 + rng.Float64()*0.000499
	minorityCount := int(float64(size) * freq)
	for i := 0; i < minorityCount; i++ {
		pos := rng.IntN(size)
		buf[pos] = minority
	}

	return buf
}

// OLE2-style headers, directory entries, VBA streams with text and binary,
// and sector padding. This is closest to the file that triggered the original bug.
func genDocumentLike(rng *rand.Rand, size int) []byte {
	buf := make([]byte, size)

	// OLE2 header (first 512 bytes)
	ole2Header := []byte{
		0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, // magic
	}
	copy(buf, ole2Header)
	// Fill rest of header with structured-looking data
	for i := len(ole2Header); i < min(512, size); i++ {
		if i%4 == 0 && i+4 <= size {
			// Looks like uint32 fields
			binary.LittleEndian.PutUint32(buf[i:i+4], uint32(rng.Int32()))
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

// genOLE2VBADropper produces files that closely match the byte-level structure
// of real OLE2 Compound Document Format files containing malicious VBA macros.
//
// Modeled from a real malware sample (SHA256: 0d0b6b35...) with this profile:
//
//	9216 bytes (18 × 512-byte sectors), 41% zero, 24% 0xFF
//	Sector types: OLE2 header, FAT tables, UTF-16LE directory entries,
//	VBA p-code, ASCII text streams, zero/FF padding sectors
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
	// Magic signature + structured LE fields + 0xFF tail padding
	ole2Sector0(rng, buf[0:sectorSize])

	// Sector 1: FAT (File Allocation Table)
	// Mostly 0xFF with scattered LE uint32 sector indices
	fatSector(rng, buf[sectorSize:2*sectorSize])

	// Remaining sectors: assemble from weighted archetypes matching the
	// distribution observed in the malware sample analyzed above.
	//
	// Sector type distribution across 16 non-header sectors:
	//   ~25% directory (UTF-16LE names, 50-83% zero)
	//   ~19% ASCII text streams (VBA source, URLs - entropy 5.5-5.8)
	//   ~19% VBA p-code / compressed binary (entropy 3.9-5.7)
	//   ~19% sparse mixed (40-60% zero, some FF)
	//   ~12% padding-heavy (FF or zero dominated)
	//   ~6%  trailing zero pad
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
// Magic signature, minor/major version, byte order, sector size fields,
// FAT/directory pointers as LE uint32, then 0xFF padding to fill.
func ole2Sector0(rng *rand.Rand, sector []byte) {
	// Fill with 0xFF first (matches OLE2 headers where unused DIFAT entries are all-bits-set)
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
// sector chain entries (small integers) scattered in.
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
// Real profile: 50-83% zero bytes, rest is UTF-16LE encoded names and
// small structured fields.
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
// Real profile: entropy 5.5-5.8, mostly printable ASCII with \r\n line endings.
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
// Real profile: entropy 3.9-5.7, mix of small integers, opcode-like bytes,
// and occasional runs of zeros.
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
// Real profile: 40-60% zero, 2-40% FF, rest is scattered data.
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
// Real profile: >85% one value (0xFF or 0x00) with minor scattered noise.
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

// trailingZeroSector generates a mostly-zero sector with a small ASCII fragment,
// matching the trailing sector often seen in OLE2 files.
// Real profile: ~90% zero, small ASCII text fragment (module names, config).
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

// ---------- PE generator ----------

// genPE produces a synthetic Windows Portable Executable (PE/PE32+) file.
//
// Structure:
//   - DOS stub with realistic MZ header and e_lfanew pointer
//   - PE signature + COFF header (machine x86 or x64)
//   - Optional header (PE32 or PE32+ depending on machine)
//   - 2–6 section headers (.text, .data, .rdata, .rsrc, .reloc, .pdata)
//   - Section bodies: .text filled with x86/x64-like byte patterns,
//     .rdata/.rsrc with structured tables, .data with mixed data,
//     remaining space filled with realistic padding
func genPE(rng *rand.Rand, size int) []byte {
	const (
		dosHeaderSize  = 64
		dosStubSize    = 64 // small MS-DOS stub program
		peSignSize     = 4
		coffHeaderSize = 20
		sectionRecSize = 40
	)

	// Choose architecture: ~60% x64, ~40% x86
	is64 := rng.Float64() < 0.60
	var optHeaderSize int
	var machine uint16
	if is64 {
		optHeaderSize = 240 // PE32+
		machine = 0x8664    // IMAGE_FILE_MACHINE_AMD64
	} else {
		optHeaderSize = 224 // PE32
		machine = 0x014C    // IMAGE_FILE_MACHINE_I386
	}

	// Number of sections: 2–6
	numSections := 2 + rng.IntN(5)

	// File alignment and section alignment (standard values)
	fileAlign := 512
	sectAlign := 4096

	// Calculate header region size (rounded up to fileAlign)
	peHeaderOff := dosHeaderSize + dosStubSize
	rawHeaderSize := peHeaderOff + peSignSize + coffHeaderSize + optHeaderSize + numSections*sectionRecSize
	rawHeaderSize = (rawHeaderSize + fileAlign - 1) &^ (fileAlign - 1)

	// Divide remaining space among sections
	bodySpace := size - rawHeaderSize
	if bodySpace < numSections*fileAlign {
		// File is too small to be a real PE; just write a stub
		buf := make([]byte, size)
		buf[0] = 0x4D
		buf[1] = 0x5A
		return buf
	}

	buf := make([]byte, size)

	// ------------------------------------------------------------------
	// DOS header (64 bytes)
	// ------------------------------------------------------------------
	buf[0] = 0x4D // M
	buf[1] = 0x5A // Z
	// e_cblp, e_cp, e_crlc, e_cparhdr — typical stub values
	binary.LittleEndian.PutUint16(buf[2:], 0x0090)
	binary.LittleEndian.PutUint16(buf[4:], 0x0003)
	binary.LittleEndian.PutUint16(buf[6:], 0x0000)
	binary.LittleEndian.PutUint16(buf[8:], 0x0004)
	// e_minalloc, e_maxalloc
	binary.LittleEndian.PutUint16(buf[10:], 0x0000)
	binary.LittleEndian.PutUint16(buf[12:], 0xFFFF)
	// e_ss, e_sp
	binary.LittleEndian.PutUint16(buf[14:], 0x0000)
	binary.LittleEndian.PutUint16(buf[16:], 0x00B8)
	// e_lfanew: offset to PE header
	binary.LittleEndian.PutUint32(buf[60:], uint32(peHeaderOff))

	// ------------------------------------------------------------------
	// DOS stub (64 bytes of a realistic "This program cannot be run…" stub)
	// ------------------------------------------------------------------
	dosStub := []byte{
		0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD,
		0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
		0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72,
		0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
		0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E,
		0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,
		0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A,
		0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	copy(buf[dosHeaderSize:], dosStub)

	// ------------------------------------------------------------------
	// PE signature
	// ------------------------------------------------------------------
	off := peHeaderOff
	buf[off] = 'P'
	buf[off+1] = 'E'
	buf[off+2] = 0
	buf[off+3] = 0
	off += peSignSize

	// ------------------------------------------------------------------
	// COFF header
	// ------------------------------------------------------------------
	coffOff := off
	_ = coffOff
	binary.LittleEndian.PutUint16(buf[off:], machine)                  // Machine
	binary.LittleEndian.PutUint16(buf[off+2:], uint16(numSections))    // NumberOfSections
	binary.LittleEndian.PutUint32(buf[off+4:], rng.Uint32())           // TimeDateStamp
	binary.LittleEndian.PutUint32(buf[off+8:], 0)                      // PointerToSymbolTable
	binary.LittleEndian.PutUint32(buf[off+12:], 0)                     // NumberOfSymbols
	binary.LittleEndian.PutUint16(buf[off+16:], uint16(optHeaderSize)) // SizeOfOptionalHeader
	// Characteristics: executable | (large address aware if x64)
	var chars uint16 = 0x0002 // IMAGE_FILE_EXECUTABLE_IMAGE
	if is64 {
		chars |= 0x0020 // IMAGE_FILE_LARGE_ADDRESS_AWARE
	} else {
		chars |= 0x0100 // IMAGE_FILE_32BIT_MACHINE
	}
	binary.LittleEndian.PutUint16(buf[off+18:], chars)
	off += coffHeaderSize

	// ------------------------------------------------------------------
	// Optional header
	// ------------------------------------------------------------------
	optOff := off
	var magic uint16
	if is64 {
		magic = 0x020B // PE32+
	} else {
		magic = 0x010B // PE32
	}
	binary.LittleEndian.PutUint16(buf[optOff:], magic)
	buf[optOff+2] = 0x0E // MajorLinkerVersion
	buf[optOff+3] = 0x00 // MinorLinkerVersion

	// Realistic image base
	var imageBase uint64
	if is64 {
		imageBase = 0x0000000140000000
	} else {
		imageBase = 0x00400000
	}

	// SectionAlignment, FileAlignment
	binary.LittleEndian.PutUint32(buf[optOff+32:], uint32(sectAlign))
	binary.LittleEndian.PutUint32(buf[optOff+36:], uint32(fileAlign))

	// OS/Image/Subsystem version fields (typical values)
	binary.LittleEndian.PutUint16(buf[optOff+40:], 6) // MajorOSVersion
	binary.LittleEndian.PutUint16(buf[optOff+42:], 0)
	binary.LittleEndian.PutUint16(buf[optOff+48:], 6) // MajorSubsystemVersion
	binary.LittleEndian.PutUint16(buf[optOff+50:], 0)

	// SizeOfImage: rounded up to sectAlign
	sizeOfImage := ((size + sectAlign - 1) / sectAlign) * sectAlign
	binary.LittleEndian.PutUint32(buf[optOff+56:], uint32(sizeOfImage))
	// SizeOfHeaders
	binary.LittleEndian.PutUint32(buf[optOff+60:], uint32(rawHeaderSize))

	// Subsystem: GUI or CUI
	subsystems := []uint16{2, 3} // IMAGE_SUBSYSTEM_WINDOWS_GUI, _CUI
	binary.LittleEndian.PutUint16(buf[optOff+68:], subsystems[rng.IntN(2)])

	// DLLCharacteristics (ASLR, NX, etc.)
	binary.LittleEndian.PutUint16(buf[optOff+70:], 0x8160)

	if is64 {
		binary.LittleEndian.PutUint64(buf[optOff+24:], imageBase)
		// Stack/heap reserve+commit
		binary.LittleEndian.PutUint64(buf[optOff+72:], 0x0000000000100000)
		binary.LittleEndian.PutUint64(buf[optOff+80:], 0x0000000000001000)
		binary.LittleEndian.PutUint64(buf[optOff+88:], 0x0000000000100000)
		binary.LittleEndian.PutUint64(buf[optOff+96:], 0x0000000000001000)
		// NumberOfRvaAndSizes
		binary.LittleEndian.PutUint32(buf[optOff+108:], 16)
	} else {
		binary.LittleEndian.PutUint32(buf[optOff+28:], uint32(imageBase))
		// Stack/heap reserve+commit
		binary.LittleEndian.PutUint32(buf[optOff+72:], 0x00100000)
		binary.LittleEndian.PutUint32(buf[optOff+76:], 0x00001000)
		binary.LittleEndian.PutUint32(buf[optOff+80:], 0x00100000)
		binary.LittleEndian.PutUint32(buf[optOff+84:], 0x00001000)
		// NumberOfRvaAndSizes
		binary.LittleEndian.PutUint32(buf[optOff+92:], 16)
	}

	off = optOff + optHeaderSize

	// ------------------------------------------------------------------
	// Section table and bodies
	// ------------------------------------------------------------------
	sectionNames := []string{".text", ".data", ".rdata", ".rsrc", ".reloc", ".pdata"}
	// Shuffle to get variety in section ordering
	rng.Shuffle(len(sectionNames), func(i, j int) { sectionNames[i], sectionNames[j] = sectionNames[j], sectionNames[i] })
	sectionNames = sectionNames[:numSections]

	// Divide body space among sections with log-uniform-ish sizes
	type sectionLayout struct {
		name       string
		rawOffset  int
		rawSize    int
		virtOffset int
	}
	layouts := make([]sectionLayout, numSections)
	rawCursor := rawHeaderSize
	virtCursor := (rawHeaderSize + sectAlign - 1) &^ (sectAlign - 1)

	for i := range layouts {
		// Each section gets a share; last section gets the remainder
		var share int
		if i < numSections-1 {
			minShare := fileAlign
			maxShare := bodySpace / (numSections - i)
			if maxShare < minShare {
				maxShare = minShare
			}
			share = minShare + rng.IntN(maxShare-minShare+1)
			share = (share + fileAlign - 1) &^ (fileAlign - 1)
		} else {
			share = size - rawCursor
			if share < fileAlign {
				share = fileAlign
			}
			share = (share + fileAlign - 1) &^ (fileAlign - 1)
			if rawCursor+share > size {
				share = size - rawCursor
			}
		}
		if share < 0 {
			share = 0
		}
		layouts[i] = sectionLayout{
			name:       sectionNames[i],
			rawOffset:  rawCursor,
			rawSize:    share,
			virtOffset: virtCursor,
		}
		rawCursor += share
		virtCursor = (virtCursor + share + sectAlign - 1) &^ (sectAlign - 1)
	}

	// Write section headers
	sectHeaderOff := off
	_ = sectHeaderOff
	sectionCharMap := map[string]uint32{
		".text":  0x60000020, // code | execute | read
		".data":  0xC0000040, // initialized data | read | write
		".rdata": 0x40000040, // initialized data | read
		".rsrc":  0x40000040,
		".reloc": 0x42000040, // initialized data | read | discardable
		".pdata": 0x40000040,
	}
	for i, sl := range layouts {
		h := off + i*sectionRecSize
		// Name (8 bytes, null-padded)
		copy(buf[h:h+8], sl.name)
		// VirtualSize
		binary.LittleEndian.PutUint32(buf[h+8:], uint32(sl.rawSize))
		// VirtualAddress
		binary.LittleEndian.PutUint32(buf[h+12:], uint32(sl.virtOffset))
		// SizeOfRawData
		binary.LittleEndian.PutUint32(buf[h+16:], uint32(sl.rawSize))
		// PointerToRawData
		binary.LittleEndian.PutUint32(buf[h+20:], uint32(sl.rawOffset))
		// Characteristics
		chars32 := sectionCharMap[sl.name]
		if chars32 == 0 {
			chars32 = 0x40000040
		}
		binary.LittleEndian.PutUint32(buf[h+36:], chars32)
	}

	// Write section bodies
	for _, sl := range layouts {
		if sl.rawOffset+sl.rawSize > len(buf) {
			continue
		}
		body := buf[sl.rawOffset : sl.rawOffset+sl.rawSize]
		switch sl.name {
		case ".text":
			// x86/x64-like: mix of realistic opcode patterns and random bytes
			fillTextSection(rng, body, is64)
		case ".rdata", ".rsrc":
			// Read-only data: cstrings, import tables, resource tables
			fillRdataSection(rng, body)
		case ".reloc":
			// Relocation blocks: 4-byte page RVA + 4-byte block size + 16-bit entries
			fillRelocSection(rng, body)
		default:
			// .data, .pdata, others: mix of structured and random
			fillDataSection(rng, body)
		}
	}

	return buf
}

// fillTextSection writes x86/x64-like code patterns into a section body.
func fillTextSection(rng *rand.Rand, body []byte, is64 bool) {
	// Common function prologues / epilogues / instructions as byte patterns
	x86Patterns := [][]byte{
		{0x55, 0x48, 0x89, 0xE5},       // push rbp; mov rbp,rsp (x64 prologue)
		{0x48, 0x83, 0xEC, 0x28},       // sub rsp,0x28
		{0x48, 0x8B, 0x05},             // mov rax,[rip+...]
		{0x48, 0x89, 0x5C, 0x24, 0x08}, // mov [rsp+8],rbx
		{0xE8, 0x00, 0x00, 0x00, 0x00}, // call rel32
		{0x48, 0x83, 0xC4, 0x28},       // add rsp,0x28
		{0xC3},                         // ret
		{0x90},                         // nop
		{0x0F, 0x1F, 0x44, 0x00, 0x00}, // nop dword [rax+rax]
		{0x55, 0x89, 0xE5},             // push ebp; mov ebp,esp (x86 prologue)
		{0x83, 0xEC, 0x10},             // sub esp,0x10
		{0x8B, 0x45, 0x08},             // mov eax,[ebp+8]
		{0x5D, 0xC3},                   // pop ebp; ret
		{0x31, 0xC0},                   // xor eax,eax
		{0x85, 0xC0},                   // test eax,eax
		{0x74, 0x05},                   // jz +5
		{0x75, 0x05},                   // jnz +5
		{0xFF, 0x25},                   // jmp [mem] (IAT thunk)
		{0xCC},                         // int3 (debug break / padding)
	}
	_ = is64

	i := 0
	for i < len(body) {
		pat := x86Patterns[rng.IntN(len(x86Patterns))]
		// Occasionally emit a random byte run between patterns
		if rng.IntN(8) == 0 {
			runLen := 1 + rng.IntN(16)
			for j := 0; j < runLen && i < len(body); j++ {
				body[i] = byte(rng.Uint32())
				i++
			}
		}
		for _, b := range pat {
			if i >= len(body) {
				break
			}
			body[i] = b
			i++
		}
	}
}

// fillRdataSection writes import-table / string-table-like data.
func fillRdataSection(rng *rand.Rand, body []byte) {
	dllNames := []string{
		"KERNEL32.dll\x00", "USER32.dll\x00", "ADVAPI32.dll\x00",
		"ntdll.dll\x00", "msvcrt.dll\x00", "SHELL32.dll\x00",
		"ole32.dll\x00", "OLEAUT32.dll\x00", "WS2_32.dll\x00",
	}
	funcNames := []string{
		"CreateFileW\x00", "ReadFile\x00", "WriteFile\x00",
		"GetProcAddress\x00", "LoadLibraryA\x00", "VirtualAlloc\x00",
		"GetLastError\x00", "CloseHandle\x00", "HeapAlloc\x00",
		"MessageBoxW\x00", "RegOpenKeyExW\x00", "CryptEncrypt\x00",
		"WSAStartup\x00", "connect\x00", "send\x00", "recv\x00",
	}
	i := 0
	for i < len(body) {
		switch rng.IntN(4) {
		case 0: // DLL name string
			s := dllNames[rng.IntN(len(dllNames))]
			for _, b := range []byte(s) {
				if i >= len(body) {
					break
				}
				body[i] = b
				i++
			}
		case 1: // function name string
			s := funcNames[rng.IntN(len(funcNames))]
			for _, b := range []byte(s) {
				if i >= len(body) {
					break
				}
				body[i] = b
				i++
			}
		case 2: // zero padding (null separators between entries)
			padLen := 1 + rng.IntN(16)
			for j := 0; j < padLen && i < len(body); j++ {
				body[i] = 0x00
				i++
			}
		case 3: // RVA/ordinal as LE uint32
			if i+4 <= len(body) {
				binary.LittleEndian.PutUint32(body[i:], rng.Uint32())
				i += 4
			} else {
				i++
			}
		}
	}
}

// fillRelocSection writes IMAGE_BASE_RELOCATION blocks.
func fillRelocSection(rng *rand.Rand, body []byte) {
	i := 0
	for i+8 <= len(body) {
		// Page RVA (aligned to 4K)
		pageRVA := uint32((rng.IntN(0x1000) + 1) * 0x1000)
		// Number of 16-bit entries: 1–60
		numEntries := 1 + rng.IntN(60)
		blockSize := 8 + numEntries*2
		if i+blockSize > len(body) {
			break
		}
		binary.LittleEndian.PutUint32(body[i:], pageRVA)
		binary.LittleEndian.PutUint32(body[i+4:], uint32(blockSize))
		for j := 0; j < numEntries; j++ {
			// Type HIGHLOW (3) in high nibble, offset in low 12 bits
			entry := uint16(0x3000) | uint16(rng.IntN(0x1000))
			binary.LittleEndian.PutUint16(body[i+8+j*2:], entry)
		}
		i += blockSize
	}
	// Zero-pad remainder
	for ; i < len(body); i++ {
		body[i] = 0x00
	}
}

// fillDataSection writes a mix of structured records and random bytes.
func fillDataSection(rng *rand.Rand, body []byte) {
	i := 0
	for i < len(body) {
		switch rng.IntN(3) {
		case 0: // random bytes
			runLen := 4 + rng.IntN(64)
			for j := 0; j < runLen && i < len(body); j++ {
				body[i] = byte(rng.Uint32())
				i++
			}
		case 1: // zero run (BSS-like)
			runLen := 4 + rng.IntN(128)
			for j := 0; j < runLen && i < len(body); j++ {
				body[i] = 0x00
				i++
			}
		case 2: // LE uint32/uint64 field
			if i+8 <= len(body) {
				binary.LittleEndian.PutUint64(body[i:], rng.Uint64())
				i += 8
			} else if i+4 <= len(body) {
				binary.LittleEndian.PutUint32(body[i:], rng.Uint32())
				i += 4
			} else {
				body[i] = 0x00
				i++
			}
		}
	}
}

// ---------- ELF generator ----------

// genELF produces a synthetic ELF binary (32-bit or 64-bit, little- or
// big-endian, several machine types).
//
// Structure:
//   - ELF header (52 bytes for ELF32, 64 bytes for ELF64)
//   - Program headers (LOAD, DYNAMIC, NOTE segments)
//   - Section bodies: .text, .data, .rodata, .bss, .dynamic, .symtab,
//     .strtab, .shstrtab, .note
//   - Section header table at end of file
func genELF(rng *rand.Rand, size int) []byte {
	// Choose class, endianness, and machine
	is64 := rng.Float64() < 0.60
	isLE := rng.Float64() < 0.75 // most ELFs are little-endian

	type elfParams struct {
		machine uint16
		osabi   uint8
	}
	leParams := []elfParams{
		{0x0003, 0x00}, // EM_386
		{0x003E, 0x00}, // EM_X86_64
		{0x0028, 0x00}, // EM_ARM
		{0x00B7, 0x00}, // EM_AARCH64
		{0x0008, 0x00}, // EM_MIPS
	}
	beParams := []elfParams{
		{0x0002, 0x00}, // EM_SPARC
		{0x0008, 0x00}, // EM_MIPS (BE)
		{0x0015, 0x00}, // EM_PPC
		{0x0016, 0x00}, // EM_PPC64
	}
	var p elfParams
	if isLE {
		p = leParams[rng.IntN(len(leParams))]
	} else {
		p = beParams[rng.IntN(len(beParams))]
	}

	// Helper: write uint16/32/64 respecting endianness
	put16 := func(b []byte, v uint16) {
		if isLE {
			binary.LittleEndian.PutUint16(b, v)
		} else {
			binary.BigEndian.PutUint16(b, v)
		}
	}
	put32 := func(b []byte, v uint32) {
		if isLE {
			binary.LittleEndian.PutUint32(b, v)
		} else {
			binary.BigEndian.PutUint32(b, v)
		}
	}
	put64 := func(b []byte, v uint64) {
		if isLE {
			binary.LittleEndian.PutUint64(b, v)
		} else {
			binary.BigEndian.PutUint64(b, v)
		}
	}

	var elfHeaderSize, phEntSize, shEntSize int
	if is64 {
		elfHeaderSize = 64
		phEntSize = 56
		shEntSize = 64
	} else {
		elfHeaderSize = 52
		phEntSize = 32
		shEntSize = 40
	}

	// Sections we'll emit (plus SHN_UNDEF at index 0)
	sectionNames := []string{".text", ".rodata", ".data", ".bss", ".dynamic", ".symtab", ".strtab", ".shstrtab", ".note"}
	numSections := 3 + rng.IntN(len(sectionNames)-2) // 3–9 real sections
	sectionNames = sectionNames[:numSections]

	numPH := 2 + rng.IntN(3) // 2–4 program headers

	// Layout: ELF header | program headers | section bodies | section headers
	phTableSize := numPH * phEntSize
	shTableSize := (1 + numSections) * shEntSize // +1 for SHN_UNDEF
	headerRegion := elfHeaderSize + phTableSize
	bodySpace := size - headerRegion - shTableSize
	if bodySpace < numSections*16 {
		// File too small; write minimal valid stub
		buf := make([]byte, size)
		copy(buf, []byte{0x7f, 'E', 'L', 'F'})
		return buf
	}

	buf := make([]byte, size)

	// ------------------------------------------------------------------
	// ELF ident
	// ------------------------------------------------------------------
	copy(buf[0:4], []byte{0x7f, 'E', 'L', 'F'})
	if is64 {
		buf[4] = 2 // ELFCLASS64
	} else {
		buf[4] = 1 // ELFCLASS32
	}
	if isLE {
		buf[5] = 1 // ELFDATA2LSB
	} else {
		buf[5] = 2 // ELFDATA2MSB
	}
	buf[6] = 1       // EV_CURRENT
	buf[7] = p.osabi // OS/ABI
	// bytes 8–15: padding (zero)

	// e_type: ET_EXEC or ET_DYN
	etypes := []uint16{2, 3} // ET_EXEC, ET_DYN
	put16(buf[16:], etypes[rng.IntN(2)])
	put16(buf[18:], p.machine)

	// e_version = 1
	put32(buf[20:], 1)

	shOffset := uint64(size - shTableSize)

	if is64 {
		// e_entry, e_phoff, e_shoff
		put64(buf[24:], 0x400000+uint64(headerRegion)) // typical entry point
		put64(buf[32:], uint64(elfHeaderSize))         // phoff
		put64(buf[40:], shOffset)                      // shoff
		put32(buf[48:], 0)                             // e_flags
		put16(buf[52:], uint16(elfHeaderSize))         // e_ehsize
		put16(buf[54:], uint16(phEntSize))             // e_phentsize
		put16(buf[56:], uint16(numPH))                 // e_phnum
		put16(buf[58:], uint16(shEntSize))             // e_shentsize
		put16(buf[60:], uint16(1+numSections))         // e_shnum
		put16(buf[62:], uint16(numSections))           // e_shstrndx (last real section)
	} else {
		put32(buf[24:], 0x08048000+uint32(headerRegion)) // e_entry
		put32(buf[28:], uint32(elfHeaderSize))           // e_phoff
		put32(buf[32:], uint32(shOffset))                // e_shoff
		put32(buf[36:], 0)                               // e_flags
		put16(buf[40:], uint16(elfHeaderSize))           // e_ehsize
		put16(buf[42:], uint16(phEntSize))               // e_phentsize
		put16(buf[44:], uint16(numPH))                   // e_phnum
		put16(buf[46:], uint16(shEntSize))               // e_shentsize
		put16(buf[48:], uint16(1+numSections))           // e_shnum
		put16(buf[50:], uint16(numSections))             // e_shstrndx
	}

	// ------------------------------------------------------------------
	// Program headers (simple LOAD segments covering the body)
	// ------------------------------------------------------------------
	phOff := elfHeaderSize
	segSize := uint64(bodySpace / numPH)
	phTypes := []uint32{1, 2, 4, 6, 7} // PT_LOAD, PT_DYNAMIC, PT_NOTE, PT_PHDR, PT_TLS
	for i := 0; i < numPH; i++ {
		h := phOff + i*phEntSize
		pt := phTypes[rng.IntN(len(phTypes))]
		fileOff := uint64(headerRegion) + uint64(i)*segSize
		vaddr := uint64(0x400000) + fileOff
		//goland:noinspection DuplicatedCode
		if is64 {
			put32(buf[h:], pt)          // p_type
			put32(buf[h+4:], 5)         // p_flags R|X
			put64(buf[h+8:], fileOff)   // p_offset
			put64(buf[h+16:], vaddr)    // p_vaddr
			put64(buf[h+24:], vaddr)    // p_paddr
			put64(buf[h+32:], segSize)  // p_filesz
			put64(buf[h+40:], segSize)  // p_memsz
			put64(buf[h+48:], 0x200000) // p_align
		} else {
			put32(buf[h:], pt)
			put32(buf[h+4:], uint32(fileOff))
			put32(buf[h+8:], uint32(vaddr))
			put32(buf[h+12:], uint32(vaddr))
			put32(buf[h+16:], uint32(segSize))
			put32(buf[h+20:], uint32(segSize))
			put32(buf[h+24:], 5)
			put32(buf[h+28:], 0x1000)
		}
	}

	// ------------------------------------------------------------------
	// Section bodies
	// ------------------------------------------------------------------
	type sectLayout struct {
		name     string
		fileOff  int
		fileSize int
	}
	layouts := make([]sectLayout, numSections)
	cursor := headerRegion
	for i, name := range sectionNames {
		var share int
		if i < numSections-1 {
			maxShare := bodySpace / (numSections - i)
			if maxShare < 16 {
				maxShare = 16
			}
			share = 16 + rng.IntN(maxShare)
			share = (share + 15) &^ 15 // align to 16
		} else {
			share = size - shTableSize - cursor
			if share < 0 {
				share = 0
			}
		}
		layouts[i] = sectLayout{name: name, fileOff: cursor, fileSize: share}
		cursor += share
	}

	for _, sl := range layouts {
		if sl.fileSize <= 0 || sl.fileOff+sl.fileSize > len(buf) {
			continue
		}
		body := buf[sl.fileOff : sl.fileOff+sl.fileSize]
		switch sl.name {
		case ".text":
			fillTextSection(rng, body, is64)
		case ".rodata":
			fillRdataSection(rng, body)
		case ".note":
			fillELFNoteSection(rng, body, isLE)
		case ".symtab":
			fillELFSymtab(rng, body, is64, isLE)
		case ".strtab", ".shstrtab":
			fillELFStrtab(rng, body, sl.name == ".shstrtab", sectionNames)
		case ".dynamic":
			fillELFDynamic(rng, body, is64, isLE)
		case ".bss":
			// BSS is zero in the file
		default:
			fillDataSection(rng, body)
		}
	}

	// ------------------------------------------------------------------
	// Section header table (at end of file)
	// ------------------------------------------------------------------
	shBase := size - shTableSize

	// Build .shstrtab content to get name offsets
	shstrNames := make([]string, 1+numSections)
	shstrNames[0] = ""
	copy(shstrNames[1:], sectionNames)
	nameOffsets := make([]uint32, 1+numSections)
	strOff := uint32(1) // byte 0 is \0
	for i, n := range shstrNames {
		if i == 0 {
			nameOffsets[0] = 0
			continue
		}
		nameOffsets[i] = strOff
		strOff += uint32(len(n)) + 1
	}

	sectionTypes := map[string]uint32{
		".text":     1, // SHT_PROGBITS
		".rodata":   1,
		".data":     1,
		".bss":      8, // SHT_NOBITS
		".dynamic":  6, // SHT_DYNAMIC
		".symtab":   2, // SHT_SYMTAB
		".strtab":   3, // SHT_STRTAB
		".shstrtab": 3,
		".note":     7, // SHT_NOTE
	}
	sectionFlags := map[string]uint64{
		".text":     6, // SHF_ALLOC | SHF_EXECINSTR
		".rodata":   2, // SHF_ALLOC
		".data":     3, // SHF_ALLOC | SHF_WRITE
		".bss":      3,
		".dynamic":  3,
		".symtab":   0,
		".strtab":   0x30, // SHF_STRINGS | SHF_INFO_LINK
		".shstrtab": 0x30,
		".note":     2,
	}

	writeShdr := func(idx int, nameOff uint32, shType, flags uint64, addr, off, fsz, link, info, addralign, entsize uint64) {
		h := shBase + idx*shEntSize
		if h+shEntSize > len(buf) {
			return
		}
		//goland:noinspection DuplicatedCode
		if is64 {
			put32(buf[h:], nameOff)
			put32(buf[h+4:], uint32(shType))
			put64(buf[h+8:], flags)
			put64(buf[h+16:], addr)
			put64(buf[h+24:], off)
			put64(buf[h+32:], fsz)
			put32(buf[h+40:], uint32(link))
			put32(buf[h+44:], uint32(info))
			put64(buf[h+48:], addralign)
			put64(buf[h+56:], entsize)
		} else {
			put32(buf[h:], nameOff)
			put32(buf[h+4:], uint32(shType))
			put32(buf[h+8:], uint32(flags))
			put32(buf[h+12:], uint32(addr))
			put32(buf[h+16:], uint32(off))
			put32(buf[h+20:], uint32(fsz))
			put32(buf[h+24:], uint32(link))
			put32(buf[h+28:], uint32(info))
			put32(buf[h+32:], uint32(addralign))
			put32(buf[h+36:], uint32(entsize))
		}
	}

	// SHN_UNDEF (index 0)
	writeShdr(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

	for i, sl := range layouts {
		st := uint64(sectionTypes[sl.name])
		if st == 0 {
			st = 1
		}
		sf := sectionFlags[sl.name]
		vaddr := uint64(0x400000) + uint64(sl.fileOff)
		writeShdr(1+i, nameOffsets[1+i], st, sf, vaddr,
			uint64(sl.fileOff), uint64(sl.fileSize), 0, 0, 16, 0)
	}

	return buf
}

// fillELFNoteSection writes an ELF .note section (e.g. GNU build-id style).
func fillELFNoteSection(rng *rand.Rand, body []byte, isLE bool) {
	put32 := binary.LittleEndian.PutUint32
	if !isLE {
		put32 = binary.BigEndian.PutUint32
	}
	// One or two NOTE entries: namesz | descsz | type | name (padded) | desc
	noteNames := []string{"GNU\x00", "Linux\x00\x00\x00", "FreeBSD\x00"}
	i := 0
	for i+12 <= len(body) {
		name := noteNames[rng.IntN(len(noteNames))]
		nameSz := len(name)
		descSz := 4 + rng.IntN(20)
		entrySize := 12 + nameSz + descSz
		if i+entrySize > len(body) {
			break
		}
		put32(body[i:], uint32(nameSz))
		put32(body[i+4:], uint32(descSz))
		put32(body[i+8:], rng.Uint32()&0xF) // note type
		copy(body[i+12:], name)
		for j := 0; j < descSz; j++ {
			body[i+12+nameSz+j] = byte(rng.Uint32())
		}
		i += entrySize
	}
}

// fillELFSymtab writes synthetic ELF symbol table entries.
func fillELFSymtab(rng *rand.Rand, body []byte, is64, isLE bool) {
	put16 := binary.LittleEndian.PutUint16
	if !isLE {
		put16 = binary.BigEndian.PutUint16
	}
	put32 := binary.LittleEndian.PutUint32
	put64 := binary.LittleEndian.PutUint64
	if !isLE {
		put32 = binary.BigEndian.PutUint32
		put64 = binary.BigEndian.PutUint64
	}
	var entSize int
	if is64 {
		entSize = 24
	} else {
		entSize = 16
	}
	i := 0
	for i+entSize <= len(body) {
		if is64 {
			put32(body[i:], rng.Uint32())                 // st_name
			body[i+4] = byte(rng.IntN(5))                 // st_info
			body[i+5] = 0                                 // st_other
			put16(body[i+6:], uint16(rng.IntN(10)))       // st_shndx
			put64(body[i+8:], rng.Uint64())               // st_value
			put64(body[i+16:], uint64(rng.IntN(0x10000))) // st_size
		} else {
			put32(body[i:], rng.Uint32())   // st_name
			put32(body[i+4:], rng.Uint32()) // st_value
			put32(body[i+8:], rng.Uint32()) // st_size
			body[i+12] = byte(rng.IntN(5))  // st_info
			body[i+13] = 0                  // st_other
			put16(body[i+14:], uint16(rng.IntN(10)))
		}
		i += entSize
	}
}

// fillELFStrtab writes a null-separated string table. If shstrtab, it
// writes the actual section names; otherwise synthetic symbol names.
func fillELFStrtab(rng *rand.Rand, body []byte, isShstrtab bool, sectionNames []string) {
	symNames := []string{
		"main\x00", "_start\x00", "printf\x00", "malloc\x00", "free\x00",
		"strlen\x00", "memcpy\x00", "__libc_start_main\x00", "_init\x00",
		"_fini\x00", "puts\x00", "exit\x00", "__stack_chk_fail\x00",
	}
	body[0] = 0x00 // index 0 always null
	i := 1
	if isShstrtab {
		for _, n := range sectionNames {
			s := n + "\x00"
			for _, b := range []byte(s) {
				if i >= len(body) {
					return
				}
				body[i] = b
				i++
			}
		}
	} else {
		for i < len(body) {
			s := symNames[rng.IntN(len(symNames))]
			for _, b := range []byte(s) {
				if i >= len(body) {
					return
				}
				body[i] = b
				i++
			}
		}
	}
}

// fillELFDynamic writes DT_* tag/value pairs for a .dynamic section.
func fillELFDynamic(rng *rand.Rand, body []byte, is64, isLE bool) {
	put64 := binary.LittleEndian.PutUint64
	if !isLE {
		put64 = binary.BigEndian.PutUint64
	}
	put32 := binary.LittleEndian.PutUint32
	if !isLE {
		put32 = binary.BigEndian.PutUint32
	}
	// Common DT tags
	tags := []uint32{1, 5, 6, 10, 11, 12, 13, 20, 21, 25, 0}
	// DT_NEEDED=1, DT_STRTAB=5, DT_SYMTAB=6, DT_STRSZ=10, DT_SYMENT=11,
	// DT_INIT=12, DT_FINI=13, DT_REL=20, DT_RELSZ=21, DT_RELAENT=25, DT_NULL=0
	i := 0
	for _, tag := range tags {
		if is64 {
			if i+16 > len(body) {
				break
			}
			put64(body[i:], uint64(tag))
			put64(body[i+8:], rng.Uint64()&0xFFFFFF)
			i += 16
		} else {
			if i+8 > len(body) {
				break
			}
			put32(body[i:], tag)
			put32(body[i+4:], rng.Uint32()&0xFFFFFF)
			i += 8
		}
	}
}

// ---------- Mach-O generator ----------

// genMachO produces a synthetic Mach-O binary.
//
// Variants covered:
//   - 32-bit (mhMagic 0xFEEDFACE) and 64-bit (mhMagic64 0xFEEDFACF)
//   - Architectures: x86, x86_64, ARM, ARM64
//   - File types: mhExecute, mhDylib, mhBundle
//   - Load commands: lcSegment/lcSegment64, lcSymtab, lcDysymtab,
//     lcLoadDylib, lcUUID, lcMain
//   - Sections within segments: __text, __data, __const, __bss, __cstring
func genMachO(rng *rand.Rand, size int) []byte {
	const (
		mhMagic   = 0xFEEDFACE
		mhMagic64 = 0xFEEDFACF

		mhExecute = 0x2
		mhDylib   = 0x6
		mhBundle  = 0x8

		lcSegment   = 0x1
		lcSymtab    = 0x2
		lcDysymtab  = 0xB
		lcLoadDylib = 0xC
		lcUUID      = 0x1B
		lcSegment64 = 0x19
		lcMain      = 0x80000028

		cpuTypeX86   = 0x7
		cpuTypeX8664 = 0x01000007
		cpuTypeArm   = 0xC
		cpuTypeArm64 = 0x0100000C

		cpuSubtypeAll = 0x3
	)

	is64 := rng.Float64() < 0.65

	type archDef struct {
		cpuType    uint32
		cpuSubtype uint32
	}
	var arch archDef
	if is64 {
		archs64 := []archDef{
			{cpuTypeX8664, cpuSubtypeAll},
			{cpuTypeArm64, cpuSubtypeAll},
		}
		arch = archs64[rng.IntN(len(archs64))]
	} else {
		archs32 := []archDef{
			{cpuTypeX86, cpuSubtypeAll},
			{cpuTypeArm, cpuSubtypeAll},
		}
		arch = archs32[rng.IntN(len(archs32))]
	}

	fileTypes := []uint32{mhExecute, mhDylib, mhBundle}
	fileType := fileTypes[rng.IntN(len(fileTypes))]

	var mhSize int
	if is64 {
		mhSize = 32
	} else {
		mhSize = 28
	}

	type machoSection struct {
		sectName string
		segName  string
		flags    uint32
	}
	segDefs := []struct {
		segName  string
		sections []machoSection
		initProt uint32
		maxProt  uint32
	}{
		{
			segName: "__TEXT",
			sections: []machoSection{
				{"__text", "__TEXT", 0x80000400},
				{"__const", "__TEXT", 0x0},
				{"__cstring", "__TEXT", 0x2},
			},
			initProt: 5, maxProt: 5,
		},
		{
			segName: "__DATA",
			sections: []machoSection{
				{"__data", "__DATA", 0x0},
				{"__bss", "__DATA", 0x1},
				{"__const", "__DATA", 0x0},
			},
			initProt: 3, maxProt: 3,
		},
		{
			segName:  "__LINKEDIT",
			sections: []machoSection{},
			initProt: 1, maxProt: 1,
		},
	}

	numSegs := 2 + rng.IntN(2)
	if numSegs > len(segDefs) {
		numSegs = len(segDefs)
	}
	segs := segDefs[:numSegs]

	totalSects := 0
	for _, sg := range segs {
		n := len(sg.sections)
		if n > 0 {
			totalSects += 1 + rng.IntN(n)
		}
	}

	var lcSegSize, lcSectSize int
	if is64 {
		lcSegSize = 72
		lcSectSize = 80
	} else {
		lcSegSize = 56
		lcSectSize = 68
	}

	lcSymtabSize := 24
	lcDysymtabSize := 80
	lcUUIDSize := 24
	lcMainSize := 24
	lcLoadDylibSize := 56

	numDylibs := 1 + rng.IntN(3)
	totalLCSize := numSegs*lcSegSize + totalSects*lcSectSize +
		lcSymtabSize + lcDysymtabSize + lcUUIDSize +
		lcMainSize + numDylibs*lcLoadDylibSize

	headerRegion := mhSize + totalLCSize
	if headerRegion >= size {
		buf := make([]byte, size)
		if is64 {
			binary.LittleEndian.PutUint32(buf[0:], mhMagic64)
		} else {
			binary.LittleEndian.PutUint32(buf[0:], mhMagic)
		}
		return buf
	}

	buf := make([]byte, size)

	// ------------------------------------------------------------------
	// Mach-O header
	// ------------------------------------------------------------------
	if is64 {
		binary.LittleEndian.PutUint32(buf[0:], mhMagic64)
	} else {
		binary.LittleEndian.PutUint32(buf[0:], mhMagic)
	}
	binary.LittleEndian.PutUint32(buf[4:], arch.cpuType)
	binary.LittleEndian.PutUint32(buf[8:], arch.cpuSubtype)
	binary.LittleEndian.PutUint32(buf[12:], fileType)
	numLCs := uint32(numSegs + 4 + numDylibs)
	binary.LittleEndian.PutUint32(buf[16:], numLCs)
	binary.LittleEndian.PutUint32(buf[20:], uint32(totalLCSize))
	binary.LittleEndian.PutUint32(buf[24:], 0x00218085)

	// ------------------------------------------------------------------
	// Load commands
	// ------------------------------------------------------------------
	lc := mhSize

	bodySpace := size - headerRegion
	segBodySizes := make([]int, numSegs)
	remaining := bodySpace
	for i := range segs {
		if i < numSegs-1 {
			share := remaining / (numSegs - i)
			segBodySizes[i] = share
			remaining -= share
		} else {
			segBodySizes[i] = remaining
		}
	}

	fileOff := headerRegion
	vmAddr := uint64(0x100000000)

	type sectBody struct {
		name    string
		fileOff int
		size    int
	}
	var sectBodies []sectBody

	for si, sg := range segs {
		numSectHere := 0
		if len(sg.sections) > 0 {
			numSectHere = 1 + rng.IntN(len(sg.sections))
		}
		if numSectHere > len(sg.sections) {
			numSectHere = len(sg.sections)
		}
		sects := sg.sections[:numSectHere]

		lcCmd := uint32(lcSegment)
		if is64 {
			lcCmd = lcSegment64
		}

		lcStart := lc
		lcSize := lcSegSize + numSectHere*lcSectSize

		binary.LittleEndian.PutUint32(buf[lc:], lcCmd)
		binary.LittleEndian.PutUint32(buf[lc+4:], uint32(lcSize))
		copy(buf[lc+8:lc+24], sg.segName)

		segBodySize := segBodySizes[si]

		sectSizes := make([]int, numSectHere)
		rem := segBodySize
		for k := range sects {
			if k < numSectHere-1 {
				s := rem / (numSectHere - k)
				sectSizes[k] = s
				rem -= s
			} else {
				sectSizes[k] = rem
			}
		}

		if is64 {
			binary.LittleEndian.PutUint64(buf[lc+24:], vmAddr)
			binary.LittleEndian.PutUint64(buf[lc+32:], uint64(segBodySize))
			binary.LittleEndian.PutUint64(buf[lc+40:], uint64(fileOff))
			binary.LittleEndian.PutUint64(buf[lc+48:], uint64(segBodySize))
			binary.LittleEndian.PutUint32(buf[lc+56:], sg.maxProt)
			binary.LittleEndian.PutUint32(buf[lc+60:], sg.initProt)
			binary.LittleEndian.PutUint32(buf[lc+64:], uint32(numSectHere))
		} else {
			binary.LittleEndian.PutUint32(buf[lc+24:], uint32(vmAddr))
			binary.LittleEndian.PutUint32(buf[lc+28:], uint32(segBodySize))
			binary.LittleEndian.PutUint32(buf[lc+32:], uint32(fileOff))
			binary.LittleEndian.PutUint32(buf[lc+36:], uint32(segBodySize))
			binary.LittleEndian.PutUint32(buf[lc+40:], sg.maxProt)
			binary.LittleEndian.PutUint32(buf[lc+44:], sg.initProt)
			binary.LittleEndian.PutUint32(buf[lc+48:], uint32(numSectHere))
		}

		lc = lcStart + lcSegSize

		sectFileOff := fileOff
		sectVMAddr := vmAddr
		for k, sect := range sects {
			sh := lc
			copy(buf[sh:sh+16], sect.sectName)
			copy(buf[sh+16:sh+32], sect.segName)
			sz := sectSizes[k]
			if is64 {
				binary.LittleEndian.PutUint64(buf[sh+32:], sectVMAddr)
				binary.LittleEndian.PutUint64(buf[sh+40:], uint64(sz))
				binary.LittleEndian.PutUint32(buf[sh+48:], uint32(sectFileOff))
				binary.LittleEndian.PutUint32(buf[sh+52:], 4)
				binary.LittleEndian.PutUint32(buf[sh+72:], sect.flags)
			} else {
				binary.LittleEndian.PutUint32(buf[sh+32:], uint32(sectVMAddr))
				binary.LittleEndian.PutUint32(buf[sh+36:], uint32(sz))
				binary.LittleEndian.PutUint32(buf[sh+40:], uint32(sectFileOff))
				binary.LittleEndian.PutUint32(buf[sh+44:], 4)
				binary.LittleEndian.PutUint32(buf[sh+60:], sect.flags)
			}
			sectBodies = append(sectBodies, sectBody{
				name:    sect.sectName,
				fileOff: sectFileOff,
				size:    sz,
			})
			sectFileOff += sz
			sectVMAddr += uint64(sz)
			lc += lcSectSize
		}

		fileOff += segBodySize
		vmAddr += uint64(segBodySize)
	}

	// lcSymtab
	binary.LittleEndian.PutUint32(buf[lc:], lcSymtab)
	binary.LittleEndian.PutUint32(buf[lc+4:], uint32(lcSymtabSize))
	binary.LittleEndian.PutUint32(buf[lc+8:], uint32(fileOff))
	binary.LittleEndian.PutUint32(buf[lc+12:], uint32(rng.IntN(64)+4))
	binary.LittleEndian.PutUint32(buf[lc+16:], uint32(fileOff))
	binary.LittleEndian.PutUint32(buf[lc+20:], 128)
	lc += lcSymtabSize

	// lcDysymtab
	binary.LittleEndian.PutUint32(buf[lc:], lcDysymtab)
	binary.LittleEndian.PutUint32(buf[lc+4:], uint32(lcDysymtabSize))
	binary.LittleEndian.PutUint32(buf[lc+8:], 0)
	binary.LittleEndian.PutUint32(buf[lc+12:], rng.Uint32()&0x7)
	binary.LittleEndian.PutUint32(buf[lc+16:], rng.Uint32()&0x7)
	binary.LittleEndian.PutUint32(buf[lc+20:], rng.Uint32()&0x7)
	lc += lcDysymtabSize

	// lcUUID
	binary.LittleEndian.PutUint32(buf[lc:], lcUUID)
	binary.LittleEndian.PutUint32(buf[lc+4:], uint32(lcUUIDSize))
	for i := 0; i < 16; i++ {
		buf[lc+8+i] = byte(rng.Uint32())
	}
	lc += lcUUIDSize

	// lcMain
	binary.LittleEndian.PutUint32(buf[lc:], lcMain)
	binary.LittleEndian.PutUint32(buf[lc+4:], uint32(lcMainSize))
	binary.LittleEndian.PutUint64(buf[lc+8:], uint64(rng.IntN(0x1000)))
	binary.LittleEndian.PutUint64(buf[lc+16:], 0)
	lc += lcMainSize

	// lcLoadDylib entries
	dylibNames := []string{
		"/usr/lib/libSystem.B.dylib\x00",
		"/usr/lib/libc++.1.dylib\x00",
		"/usr/lib/libz.1.dylib\x00",
		"/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation\x00",
		"/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation\x00",
	}
	rng.Shuffle(len(dylibNames), func(i, j int) { dylibNames[i], dylibNames[j] = dylibNames[j], dylibNames[i] })
	for i := 0; i < numDylibs; i++ {
		binary.LittleEndian.PutUint32(buf[lc:], lcLoadDylib)
		binary.LittleEndian.PutUint32(buf[lc+4:], uint32(lcLoadDylibSize))
		binary.LittleEndian.PutUint32(buf[lc+8:], 24)
		binary.LittleEndian.PutUint32(buf[lc+12:], 0x00000002)
		binary.LittleEndian.PutUint32(buf[lc+16:], 0x00010000)
		binary.LittleEndian.PutUint32(buf[lc+20:], 0x00010000)
		nameBytes := []byte(dylibNames[i%len(dylibNames)])
		copyLen := min(len(nameBytes), lcLoadDylibSize-24)
		copy(buf[lc+24:lc+24+copyLen], nameBytes)
		lc += lcLoadDylibSize
	}

	// ------------------------------------------------------------------
	// Section bodies
	// ------------------------------------------------------------------
	for _, sb := range sectBodies {
		if sb.fileOff+sb.size > len(buf) || sb.size <= 0 {
			continue
		}
		body := buf[sb.fileOff : sb.fileOff+sb.size]
		switch sb.name {
		case "__text":
			fillTextSection(rng, body, is64)
		case "__cstring":
			fillMachOCstring(rng, body)
		case "__const", "__data":
			fillDataSection(rng, body)
		}
	}

	return buf
}

// fillMachOCstring writes a null-terminated C string table as found in __cstring.
func fillMachOCstring(rng *rand.Rand, body []byte) {
	cstrings := []string{
		"Hello, World!\x00",
		"dyld: Library not loaded\x00",
		"objc_retain\x00",
		"__ZN3fooC1Ev\x00",
		"NSApplicationMain\x00",
		"com.apple.security.app-sandbox\x00",
		"CFBundleIdentifier\x00",
		"NSPrincipalClass\x00",
		"/System/Library/CoreServices\x00",
		"malloc: *** error\x00",
	}
	i := 0
	for i < len(body) {
		s := []byte(cstrings[rng.IntN(len(cstrings))])
		if i+len(s) > len(body) {
			body[i] = 0x00
			break
		}
		copy(body[i:], s)
		i += len(s)
	}
}

// ---------- DEX generator ----------

// genDEX produces a synthetic Android Dalvik Executable (DEX) file.
//
// Structure follows the DEX file format specification:
//   - Header (112 bytes) with magic, checksum, SHA-1, counts and offsets
//   - String ID list → string data pool
//   - Type ID list (indices into string pool)
//   - Proto ID list (method prototypes)
//   - Field ID list
//   - Method ID list
//   - Class definition list
//   - Data section: code items, annotation data, debug info
//
// Checksums and SHA-1 are intentionally left as plausible-looking random
// bytes — the goal is structural realism for corpus purposes, not
// executability.
func genDEX(rng *rand.Rand, size int) []byte {
	// DEX header is exactly 112 bytes.
	// Magic: "dex\n{ver}\0" where ver is "035" or "039"
	const headerSize = 112

	if size < headerSize {
		buf := make([]byte, size)
		copy(buf, "dex\n035\x00")
		return buf
	}

	buf := make([]byte, size)

	// ------------------------------------------------------------------
	// Choose a DEX version
	// ------------------------------------------------------------------
	versions := []string{"035\x00", "036\x00", "038\x00", "039\x00"}
	ver := versions[rng.IntN(len(versions))]
	copy(buf[0:4], "dex\n")
	copy(buf[4:8], ver)

	// ------------------------------------------------------------------
	// Decide on counts — scale with file size so small files stay valid
	// ------------------------------------------------------------------
	bodySpace := size - headerSize
	unitBudget := bodySpace / 32 // rough bytes-per-unit estimate
	if unitBudget < 4 {
		unitBudget = 4
	}

	numStrings := 8 + rng.IntN(min(unitBudget, 128))
	numTypes := 2 + rng.IntN(min(numStrings/2+1, 32))
	numProtos := 1 + rng.IntN(min(numTypes+1, 16))
	numFields := 1 + rng.IntN(min(numTypes*2+1, 32))
	numMethods := 1 + rng.IntN(min(numProtos*2+1, 32))
	numClasses := 1 + rng.IntN(min(numMethods+1, 16))

	// ------------------------------------------------------------------
	// Layout offsets (all sections are 4-byte aligned)
	// ------------------------------------------------------------------
	align4 := func(n int) int { return (n + 3) &^ 3 }

	stringIdsOff := headerSize
	stringIdsSize := numStrings * 4

	typeIdsOff := align4(stringIdsOff + stringIdsSize)
	typeIdsSize := numTypes * 4

	protoIdsOff := align4(typeIdsOff + typeIdsSize)
	protoIdsSize := numProtos * 12

	fieldIdsOff := align4(protoIdsOff + protoIdsSize)
	fieldIdsSize := numFields * 8

	methodIdsOff := align4(fieldIdsOff + fieldIdsSize)
	methodIdsSize := numMethods * 8

	classDefsOff := align4(methodIdsOff + methodIdsSize)
	classDefsSize := numClasses * 32

	dataOff := align4(classDefsOff + classDefsSize)
	dataSize := size - dataOff
	if dataSize < 0 {
		dataSize = 0
	}

	// ------------------------------------------------------------------
	// Header fields
	// ------------------------------------------------------------------
	// checksum placeholder (adler32-like — 4 bytes at offset 8)
	binary.LittleEndian.PutUint32(buf[8:], rng.Uint32())
	// SHA-1 signature placeholder (20 bytes at offset 12)
	for i := 12; i < 32; i++ {
		buf[i] = byte(rng.Uint32())
	}
	// file_size
	binary.LittleEndian.PutUint32(buf[32:], uint32(size))
	// header_size = 112
	binary.LittleEndian.PutUint32(buf[36:], uint32(headerSize))
	// endian_tag: 0x12345678 = little-endian
	binary.LittleEndian.PutUint32(buf[40:], 0x12345678)
	// link_size, link_off (zero = no static link section)
	binary.LittleEndian.PutUint32(buf[44:], 0)
	binary.LittleEndian.PutUint32(buf[48:], 0)
	// map_off — point into data section
	mapOff := dataOff
	binary.LittleEndian.PutUint32(buf[52:], uint32(mapOff))
	// string_ids
	binary.LittleEndian.PutUint32(buf[56:], uint32(numStrings))
	binary.LittleEndian.PutUint32(buf[60:], uint32(stringIdsOff))
	// type_ids
	binary.LittleEndian.PutUint32(buf[64:], uint32(numTypes))
	binary.LittleEndian.PutUint32(buf[68:], uint32(typeIdsOff))
	// proto_ids
	binary.LittleEndian.PutUint32(buf[72:], uint32(numProtos))
	binary.LittleEndian.PutUint32(buf[76:], uint32(protoIdsOff))
	// field_ids
	binary.LittleEndian.PutUint32(buf[80:], uint32(numFields))
	binary.LittleEndian.PutUint32(buf[84:], uint32(fieldIdsOff))
	// method_ids
	binary.LittleEndian.PutUint32(buf[88:], uint32(numMethods))
	binary.LittleEndian.PutUint32(buf[92:], uint32(methodIdsOff))
	// class_defs
	binary.LittleEndian.PutUint32(buf[96:], uint32(numClasses))
	binary.LittleEndian.PutUint32(buf[100:], uint32(classDefsOff))
	// data_size, data_off
	binary.LittleEndian.PutUint32(buf[104:], uint32(dataSize))
	binary.LittleEndian.PutUint32(buf[108:], uint32(dataOff))

	// ------------------------------------------------------------------
	// String data pool (written into the data section first so we have
	// offsets to fill into the string ID list)
	// ------------------------------------------------------------------
	// Realistic Android class/method/field name fragments
	dexStrings := []string{
		"Ljava/lang/Object;",
		"Ljava/lang/String;",
		"Ljava/lang/StringBuilder;",
		"Landroid/app/Activity;",
		"Landroid/content/Context;",
		"Landroid/util/Log;",
		"Landroid/os/Bundle;",
		"Ljava/io/IOException;",
		"Ljava/util/ArrayList;",
		"Ljava/util/HashMap;",
		"onCreate",
		"onResume",
		"onPause",
		"onClick",
		"toString",
		"equals",
		"hashCode",
		"getClass",
		"<init>",
		"<clinit>",
		"TAG",
		"DEBUG",
		"this",
		"context",
		"intent",
		"result",
		"value",
		"index",
		"count",
		"data",
		"V", // void descriptor
		"I", // int
		"Z", // boolean
		"Ljava/lang/Runnable;",
		"run",
		"start",
		"stop",
	}

	// Write string data into data section and record offsets
	stringDataOffsets := make([]uint32, numStrings)
	cursor := dataOff + 64 // leave 64 bytes at start of data for the map
	if cursor > size {
		cursor = size
	}

	for i := 0; i < numStrings; i++ {
		if cursor >= size {
			stringDataOffsets[i] = uint32(dataOff)
			continue
		}
		s := dexStrings[rng.IntN(len(dexStrings))]
		stringDataOffsets[i] = uint32(cursor)
		// ULEB128-encoded length followed by MUTF-8 string data + NUL
		slen := len(s)
		// Write ULEB128 length
		for {
			b := byte(slen & 0x7F)
			slen >>= 7
			if slen != 0 {
				b |= 0x80
			}
			if cursor < size {
				buf[cursor] = b
				cursor++
			}
			if slen == 0 {
				break
			}
		}
		// Write string bytes + NUL
		for _, c := range []byte(s) {
			if cursor < size {
				buf[cursor] = c
				cursor++
			}
		}
		if cursor < size {
			buf[cursor] = 0x00
			cursor++
		}
	}

	// ------------------------------------------------------------------
	// String ID list — array of uint32 offsets into string data
	// ------------------------------------------------------------------
	for i := 0; i < numStrings; i++ {
		off := stringIdsOff + i*4
		if off+4 <= size {
			binary.LittleEndian.PutUint32(buf[off:], stringDataOffsets[i])
		}
	}

	// ------------------------------------------------------------------
	// Type ID list — each entry is a uint32 index into string IDs
	// ------------------------------------------------------------------
	for i := 0; i < numTypes; i++ {
		off := typeIdsOff + i*4
		if off+4 <= size {
			binary.LittleEndian.PutUint32(buf[off:], uint32(rng.IntN(numStrings)))
		}
	}

	// ------------------------------------------------------------------
	// Proto ID list — shorty_idx, return_type_idx, parameters_off (each 12 bytes)
	// ------------------------------------------------------------------
	for i := 0; i < numProtos; i++ {
		off := protoIdsOff + i*12
		if off+12 <= size {
			binary.LittleEndian.PutUint32(buf[off:], uint32(rng.IntN(numStrings))) // shorty_idx
			binary.LittleEndian.PutUint32(buf[off+4:], uint32(rng.IntN(numTypes))) // return_type_idx
			binary.LittleEndian.PutUint32(buf[off+8:], 0)                          // parameters_off (none)
		}
	}

	// ------------------------------------------------------------------
	// Field ID list — class_idx (u16), type_idx (u16), name_idx (u32) — 8 bytes each
	// ------------------------------------------------------------------
	for i := 0; i < numFields; i++ {
		off := fieldIdsOff + i*8
		if off+8 <= size {
			binary.LittleEndian.PutUint16(buf[off:], uint16(rng.IntN(numTypes)))
			binary.LittleEndian.PutUint16(buf[off+2:], uint16(rng.IntN(numTypes)))
			binary.LittleEndian.PutUint32(buf[off+4:], uint32(rng.IntN(numStrings)))
		}
	}

	// ------------------------------------------------------------------
	// Method ID list — class_idx (u16), proto_idx (u16), name_idx (u32) — 8 bytes each
	// ------------------------------------------------------------------
	for i := 0; i < numMethods; i++ {
		off := methodIdsOff + i*8
		if off+8 <= size {
			binary.LittleEndian.PutUint16(buf[off:], uint16(rng.IntN(numTypes)))
			binary.LittleEndian.PutUint16(buf[off+2:], uint16(rng.IntN(numProtos)))
			binary.LittleEndian.PutUint32(buf[off+4:], uint32(rng.IntN(numStrings)))
		}
	}

	// ------------------------------------------------------------------
	// Class definition list — 32 bytes each
	// Fields: class_idx, access_flags, superclass_idx, interfaces_off,
	//         source_file_idx, annotations_off, class_data_off, static_values_off
	// ------------------------------------------------------------------
	accessFlags := []uint32{0x0001, 0x0011, 0x0101, 0x0001 | 0x0400}
	for i := 0; i < numClasses; i++ {
		off := classDefsOff + i*32
		if off+32 <= size {
			binary.LittleEndian.PutUint32(buf[off:], uint32(rng.IntN(numTypes)))
			binary.LittleEndian.PutUint32(buf[off+4:], accessFlags[rng.IntN(len(accessFlags))])
			binary.LittleEndian.PutUint32(buf[off+8:], uint32(rng.IntN(numTypes)))    // superclass
			binary.LittleEndian.PutUint32(buf[off+12:], 0)                            // interfaces_off
			binary.LittleEndian.PutUint32(buf[off+16:], uint32(rng.IntN(numStrings))) // source_file
			binary.LittleEndian.PutUint32(buf[off+20:], 0)                            // annotations_off
			binary.LittleEndian.PutUint32(buf[off+24:], 0)                            // class_data_off
			binary.LittleEndian.PutUint32(buf[off+28:], 0)                            // static_values_off
		}
	}

	// ------------------------------------------------------------------
	// Map list (at dataOff, 64 bytes reserved)
	// A minimal map: just the header item entry.
	// map_list: size (u32) + list of map_items (12 bytes each)
	// map_item: type (u16), unused (u16), size (u32), offset (u32)
	// ------------------------------------------------------------------
	if mapOff+16 <= size {
		binary.LittleEndian.PutUint32(buf[mapOff:], 1)        // 1 map item
		binary.LittleEndian.PutUint16(buf[mapOff+4:], 0x0000) // TYPE_HEADER_ITEM
		binary.LittleEndian.PutUint16(buf[mapOff+6:], 0)      // unused
		binary.LittleEndian.PutUint32(buf[mapOff+8:], 1)      // count = 1
		binary.LittleEndian.PutUint32(buf[mapOff+12:], 0)     // offset = 0 (header)
	}

	// Fill any remaining data space with realistic Dalvik bytecode patterns
	codeStart := cursor
	if codeStart < size {
		fillDEXCode(rng, buf[codeStart:])
	}

	return buf
}

// fillDEXCode writes plausible Dalvik bytecode instruction patterns.
// Dalvik opcodes are 16-bit units (code units). Common single-code-unit
// opcodes are in the range 0x00–0x6E; we emit realistic-looking streams.
func fillDEXCode(rng *rand.Rand, body []byte) {
	// Common Dalvik opcodes (first byte of a code unit)
	opcodes := []byte{
		0x00, // nop
		0x01, // move vA, vB
		0x06, // move-wide vA, vB
		0x0A, // move-result v0
		0x0E, // return-void
		0x0F, // return vAA
		0x12, // const/4 vA, #+B
		0x13, // const/16 vAA, #+BBBB
		0x1A, // const-string vAA, string@BBBB
		0x1C, // const-class vAA, type@BBBB
		0x1F, // check-cast vAA, type@BBBB
		0x22, // new-instance vAA, type@BBBB
		0x23, // new-array vA, vB, type@CCCC
		0x28, // goto +AA
		0x32, // if-eq vA, vB, +CCCC
		0x38, // if-eqz vAA, +BBBB
		0x44, // aget vAA, vBB, vCC
		0x4B, // aput vAA, vBB, vCC
		0x52, // iget vA, vB, field@CCCC
		0x59, // iput vA, vB, field@CCCC
		0x60, // sget vAA, field@BBBB
		0x67, // sput vAA, field@BBBB
		0x6E, // invoke-virtual {vC,vD,vE,vF,vG}, meth@BBBB
		0x70, // invoke-direct {vC,...}, meth@BBBB
		0x74, // invoke-static {vC,...}, meth@BBBB
		0x90, // add-int vAA, vBB, vCC
		0xA0, // add-long vAA, vBB, vCC
		0xB0, // add-int/2addr vA, vB
		0xD8, // add-int/lit8 vAA, vBB, #+CC
	}

	i := 0
	for i < len(body) {
		op := opcodes[rng.IntN(len(opcodes))]
		body[i] = op
		i++
		// Emit one register/operand byte to complete the 16-bit code unit
		if i < len(body) {
			body[i] = byte(rng.Uint32())
			i++
		}
		// Some opcodes take additional code units (operands)
		extraUnits := 0
		switch op {
		case 0x13, 0x1A, 0x1C, 0x1F, 0x22, 0x32, 0x38, 0x60, 0x67:
			extraUnits = 1 // one more 16-bit operand
		case 0x6E, 0x70, 0x74:
			extraUnits = 2 // method ref + register list
		}
		for j := 0; j < extraUnits*2 && i < len(body); j++ {
			body[i] = byte(rng.Uint32())
			i++
		}
	}
}

// ---------- Python generator ----------

// pySnippets is a pool of syntactically plausible Python code fragments.
// They cover common standard-library patterns, OOP, async, decorators,
// comprehensions, type hints, and data-science idioms.
var pySnippets = []string{
	"import os\nimport sys\nimport json\nimport logging\nfrom pathlib import Path\nfrom typing import Optional, List, Dict, Any\n\nlogger = logging.getLogger(__name__)\n",
	"def read_config(path: str) -> Dict[str, Any]:\n    \"\"\"Load a JSON config file and return its contents.\"\"\"\n    with open(path, 'r', encoding='utf-8') as fh:\n        return json.load(fh)\n",
	"class AppError(Exception):\n    \"\"\"Base application exception.\"\"\"\n    def __init__(self, message: str, code: int = 1) -> None:\n        super().__init__(message)\n        self.code = code\n",
	"def retry(max_attempts: int = 3, delay: float = 1.0):\n    \"\"\"Decorator: retry a function on exception.\"\"\"\n    import time, functools\n    def decorator(fn):\n        @functools.wraps(fn)\n        def wrapper(*args, **kwargs):\n            for attempt in range(max_attempts):\n                try:\n                    return fn(*args, **kwargs)\n                except Exception as exc:\n                    if attempt == max_attempts - 1:\n                        raise\n                    time.sleep(delay * (attempt + 1))\n        return wrapper\n    return decorator\n",
	"import argparse\n\ndef parse_args() -> argparse.Namespace:\n    parser = argparse.ArgumentParser(description='Process files')\n    parser.add_argument('input', help='Input path')\n    parser.add_argument('-o', '--output', default='-', help='Output path')\n    parser.add_argument('-v', '--verbose', action='store_true')\n    parser.add_argument('--limit', type=int, default=0)\n    return parser.parse_args()\n",
	"import hashlib\n\ndef sha256_file(path: str) -> str:\n    h = hashlib.sha256()\n    with open(path, 'rb') as fh:\n        for chunk in iter(lambda: fh.read(65536), b''):\n            h.update(chunk)\n    return h.hexdigest()\n",
	"from dataclasses import dataclass, field\nfrom typing import ClassVar\n\n@dataclass\nclass Record:\n    id: int\n    name: str\n    tags: List[str] = field(default_factory=list)\n    _count: ClassVar[int] = 0\n\n    def __post_init__(self) -> None:\n        Record._count += 1\n\n    @classmethod\n    def total(cls) -> int:\n        return cls._count\n",
	"import sqlite3\nfrom contextlib import contextmanager\n\n@contextmanager\ndef get_db(path: str):\n    conn = sqlite3.connect(path)\n    conn.row_factory = sqlite3.Row\n    try:\n        yield conn\n        conn.commit()\n    except Exception:\n        conn.rollback()\n        raise\n    finally:\n        conn.close()\n",
	"import asyncio\nimport aiohttp\n\nasync def fetch_all(urls: List[str]) -> List[bytes]:\n    async with aiohttp.ClientSession() as session:\n        tasks = [session.get(u) for u in urls]\n        responses = await asyncio.gather(*tasks, return_exceptions=True)\n        results = []\n        for resp in responses:\n            if isinstance(resp, Exception):\n                results.append(b'')\n            else:\n                async with resp:\n                    results.append(await resp.read())\n        return results\n",
	"import re\nfrom typing import Iterator\n\nLOG_RE = re.compile(\n    r'(?P<ts>\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})'\n    r'\\s+(?P<level>DEBUG|INFO|WARNING|ERROR|CRITICAL)'\n    r'\\s+(?P<msg>.+)'\n)\n\ndef parse_log(lines: Iterator[str]) -> Iterator[Dict[str, str]]:\n    for line in lines:\n        m = LOG_RE.match(line.rstrip())\n        if m:\n            yield m.groupdict()\n",
	"from typing import TypeVar, Generic, Callable, Optional\n\nT = TypeVar('T')\n\nclass Maybe(Generic[T]):\n    def __init__(self, value: Optional[T]) -> None:\n        self._value = value\n\n    def map(self, fn: Callable[[T], T]) -> 'Maybe[T]':\n        if self._value is None:\n            return Maybe(None)\n        return Maybe(fn(self._value))\n\n    def get_or(self, default: T) -> T:\n        return self._value if self._value is not None else default\n",
	"import struct\n\ndef pack_header(magic: bytes, version: int, payload_len: int) -> bytes:\n    return struct.pack('>4sHI', magic, version, payload_len)\n\ndef unpack_header(data: bytes):\n    magic, version, payload_len = struct.unpack_from('>4sHI', data)\n    return magic, version, payload_len\n",
	"import threading\nfrom queue import Queue, Empty\n\ndef worker(q: Queue, results: list, stop_event: threading.Event) -> None:\n    while not stop_event.is_set():\n        try:\n            item = q.get(timeout=0.1)\n            results.append(process(item))\n            q.task_done()\n        except Empty:\n            continue\n\ndef process(item):\n    return item\n",
	"import csv\nimport io\n\ndef csv_to_dicts(text: str, delimiter: str = ',') -> List[Dict[str, str]]:\n    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)\n    return [dict(row) for row in reader]\n\ndef dicts_to_csv(rows: List[Dict[str, str]], fields: List[str]) -> str:\n    buf = io.StringIO()\n    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction='ignore')\n    writer.writeheader()\n    writer.writerows(rows)\n    return buf.getvalue()\n",
	"import logging\nimport sys\n\ndef setup_logging(level: str = 'INFO', fmt: Optional[str] = None) -> None:\n    fmt = fmt or '%(asctime)s %(levelname)-8s %(name)s %(message)s'\n    handler = logging.StreamHandler(sys.stderr)\n    handler.setFormatter(logging.Formatter(fmt))\n    root = logging.getLogger()\n    root.addHandler(handler)\n    root.setLevel(getattr(logging, level.upper(), logging.INFO))\n",
	"import functools\nfrom typing import Tuple\n\ndef lru_cache_typed(maxsize: int = 128):\n    def decorator(fn):\n        cached = functools.lru_cache(maxsize=maxsize)(fn)\n        @functools.wraps(fn)\n        def wrapper(*args):\n            return cached(*args)\n        wrapper.cache_info = cached.cache_info\n        wrapper.cache_clear = cached.cache_clear\n        return wrapper\n    return decorator\n",
	"from abc import ABC, abstractmethod\n\nclass Processor(ABC):\n    @abstractmethod\n    def process(self, data: bytes) -> bytes:\n        ...\n\n    @abstractmethod\n    def reset(self) -> None:\n        ...\n\n    def __enter__(self):\n        return self\n\n    def __exit__(self, *_):\n        self.reset()\n",
	"import time\n\nclass RateLimiter:\n    def __init__(self, rate: float, per: float = 1.0) -> None:\n        self._rate = rate\n        self._per = per\n        self._allowance = rate\n        self._last = time.monotonic()\n\n    def acquire(self) -> None:\n        now = time.monotonic()\n        self._allowance += (now - self._last) * (self._rate / self._per)\n        self._last = now\n        if self._allowance > self._rate:\n            self._allowance = self._rate\n        if self._allowance < 1.0:\n            time.sleep((1.0 - self._allowance) * self._per / self._rate)\n            self._allowance = 0.0\n        else:\n            self._allowance -= 1.0\n",
	"import os\nimport tempfile\nfrom contextlib import contextmanager\n\n@contextmanager\ndef atomic_write(path: str, mode: str = 'w', encoding: str = 'utf-8'):\n    dir_ = os.path.dirname(os.path.abspath(path))\n    fd, tmp = tempfile.mkstemp(dir=dir_)\n    try:\n        with os.fdopen(fd, mode, encoding=encoding) as fh:\n            yield fh\n        os.replace(tmp, path)\n    except Exception:\n        os.unlink(tmp)\n        raise\n",
	"from typing import Generator\n\ndef chunked(iterable, size: int) -> Generator:\n    \"\"\"Yield successive chunks of `size` from iterable.\"\"\"\n    buf = []\n    for item in iterable:\n        buf.append(item)\n        if len(buf) == size:\n            yield buf\n            buf = []\n    if buf:\n        yield buf\n",
	"import zlib\nimport base64\n\ndef compress_b64(data: bytes) -> str:\n    return base64.b64encode(zlib.compress(data, level=6)).decode()\n\ndef decompress_b64(s: str) -> bytes:\n    return zlib.decompress(base64.b64decode(s))\n",
	"class Singleton(type):\n    _instances: Dict[type, object] = {}\n\n    def __call__(cls, *args, **kwargs):\n        if cls not in cls._instances:\n            cls._instances[cls] = super().__call__(*args, **kwargs)\n        return cls._instances[cls]\n",
	"import subprocess\nimport shlex\n\ndef run(cmd: str, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:\n    return subprocess.run(\n        shlex.split(cmd),\n        check=check,\n        capture_output=capture,\n        text=True,\n    )\n",
	"CACHE: Dict[str, Any] = {}\n\ndef memoize(key: str, fn: Callable[[], Any], ttl: float = 300.0) -> Any:\n    import time\n    entry = CACHE.get(key)\n    if entry and time.monotonic() - entry['ts'] < ttl:\n        return entry['val']\n    val = fn()\n    CACHE[key] = {'val': val, 'ts': time.monotonic()}\n    return val\n",
	"if __name__ == '__main__':\n    import sys\n    args = parse_args()\n    setup_logging('DEBUG' if args.verbose else 'INFO')\n    try:\n        main(args)\n    except AppError as exc:\n        logger.error('%s', exc)\n        sys.exit(exc.code)\n    except KeyboardInterrupt:\n        sys.exit(130)\n",
	"# fmt: off\nSCHEMA = {\n    'type': 'object',\n    'required': ['id', 'name'],\n    'properties': {\n        'id':    {'type': 'integer', 'minimum': 1},\n        'name':  {'type': 'string',  'minLength': 1, 'maxLength': 255},\n        'email': {'type': 'string',  'format': 'email'},\n        'tags':  {'type': 'array',   'items': {'type': 'string'}},\n        'meta':  {'type': 'object'},\n    },\n    'additionalProperties': False,\n}\n# fmt: on\n",
	"from pathlib import Path\nimport shutil\n\ndef mirror_tree(src: Path, dst: Path, overwrite: bool = False) -> int:\n    dst.mkdir(parents=True, exist_ok=True)\n    count = 0\n    for item in src.rglob('*'):\n        target = dst / item.relative_to(src)\n        if item.is_dir():\n            target.mkdir(exist_ok=True)\n        else:\n            if overwrite or not target.exists():\n                shutil.copy2(item, target)\n                count += 1\n    return count\n",
	"import heapq\nfrom typing import Iterable\n\ndef top_n(items: Iterable, n: int, key=None) -> list:\n    \"\"\"Return the n largest items.\"\"\"\n    return heapq.nlargest(n, items, key=key)\n\ndef bottom_n(items: Iterable, n: int, key=None) -> list:\n    \"\"\"Return the n smallest items.\"\"\"\n    return heapq.nsmallest(n, items, key=key)\n",
	"import hmac\nimport hashlib\nimport secrets\n\ndef sign(payload: bytes, key: bytes) -> str:\n    return hmac.new(key, payload, hashlib.sha256).hexdigest()\n\ndef verify(payload: bytes, key: bytes, sig: str) -> bool:\n    expected = sign(payload, key)\n    return hmac.compare_digest(expected, sig)\n\ndef generate_key(nbytes: int = 32) -> bytes:\n    return secrets.token_bytes(nbytes)\n",
	"\"\"\"Module docstring.\n\nExample::\n\n    >>> result = compute(42)\n    >>> assert result > 0\n\"\"\"\n__version__ = '1.0.0'\n__all__ = ['compute', 'AppError']\n",
	"from typing import Protocol, runtime_checkable\n\n@runtime_checkable\nclass Serializable(Protocol):\n    def to_dict(self) -> dict: ...\n    @classmethod\n    def from_dict(cls, d: dict) -> 'Serializable': ...\n",
}

// genPython produces a synthetic Python source file assembled from
// realistic code snippets. The generator varies shebang lines, encoding
// declarations, and snippet selection to produce diverse but plausible
// Python source files.
func genPython(rng *rand.Rand, size int) []byte {
	var buf []byte

	// Optional shebang (60% of files)
	if rng.Float64() < 0.60 {
		shebangs := []string{
			"#!/usr/bin/env python3\n",
			"#!/usr/bin/python3\n",
			"#!/usr/local/bin/python3\n",
		}
		buf = append(buf, shebangs[rng.IntN(len(shebangs))]...)
	}

	// Optional encoding declaration (30% of files)
	if rng.Float64() < 0.30 {
		buf = append(buf, "# -*- coding: utf-8 -*-\n"...)
	}

	// Fill to target size with snippets
	for len(buf) < size {
		snippet := pySnippets[rng.IntN(len(pySnippets))]
		rem := size - len(buf)
		if len(snippet) <= rem {
			buf = append(buf, snippet...)
		} else {
			buf = append(buf, snippet[:rem]...)
		}
	}

	return buf[:size]
}

// ---------- email generator ----------

// genEmail produces a synthetic RFC 5322 / MIME email message.
//
// Structure:
//   - RFC 5322 headers (From, To, Cc, Date, Subject, Message-ID, MIME headers)
//   - Body: plain text, or multipart/mixed with text + attachment, or
//     multipart/alternative with text + HTML parts
//
// All addresses, subjects, and body text are drawn from realistic pools
// so the resulting files look like genuine business email.
func genEmail(rng *rand.Rand, size int) []byte {
	var buf []byte

	// pools
	firstNames := []string{
		"James", "Sarah", "Michael", "Emily", "David", "Jennifer",
		"Robert", "Jessica", "William", "Ashley", "Richard", "Amanda",
		"Thomas", "Melissa", "Charles", "Stephanie", "Daniel", "Nicole",
		"Matthew", "Elizabeth", "Anthony", "Helen", "Mark", "Donna",
	}
	lastNames := []string{
		"Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia",
		"Miller", "Davis", "Wilson", "Taylor", "Anderson", "Thomas",
		"Jackson", "White", "Harris", "Martin", "Thompson", "Moore",
		"Young", "Allen", "King", "Wright", "Scott", "Green",
	}
	domains := []string{
		"example.com", "corp.example.org", "mail.example.net",
		"enterprise.example.com", "business.example.io",
		"acmecorp.com", "globaltech.net", "northstar.org",
	}
	subjects := []string{
		"Re: Q3 budget review",
		"Action required: please review attached proposal",
		"Meeting follow-up — next steps",
		"FWD: Updated project timeline",
		"Quarterly business review — agenda attached",
		"Security advisory: mandatory patch deployment",
		"Re: Re: Customer escalation — ticket #48291",
		"Weekly status report — week ending Friday",
		"Invitation: All-hands meeting",
		"Re: Vendor contract renewal",
		"Action items from today's sync",
		"Please review: draft policy document",
		"Reminder: expense reports due Friday",
		"New hire onboarding checklist",
		"System maintenance window this weekend",
	}
	bodyParagraphs := []string{
		"I hope this message finds you well. Please find the relevant details below for your review.\n\n",
		"Following up on our conversation from last week — I wanted to share the updated information and get your thoughts before we proceed.\n\n",
		"As discussed in the meeting, we need to finalize the approach by end of week. Please let me know if you have any concerns or questions.\n\n",
		"I've attached the relevant documents for your reference. Please review at your earliest convenience and let me know if anything needs to be updated.\n\n",
		"Thank you for your prompt response. Based on your feedback, we've made the following adjustments to the plan.\n\n",
		"Per our earlier discussion, I'm reaching out to confirm the next steps and ensure we're aligned on the timeline.\n\n",
		"Please note that the deadline for submissions is end of business on Friday. Kindly ensure all required information is included.\n\n",
		"I wanted to bring this to your attention as it may impact the current project schedule. Please advise on how you'd like to proceed.\n\n",
		"Attached please find the draft version of the document. Your feedback is greatly appreciated before we send this to the broader team.\n\n",
		"Just a quick heads-up that the system will be undergoing scheduled maintenance this weekend. Please plan accordingly.\n\n",
		"I've reviewed the materials you sent over and have a few questions I'd like to go over before we finalize the agreement.\n\n",
		"As a reminder, the quarterly reports are due by the end of the month. Please ensure all sections are complete before submitting.\n\n",
		"We've received confirmation from the vendor and are now ready to move forward with the next phase of the project.\n\n",
		"Thank you all for attending today's meeting. Please see the action items below and confirm receipt of your assigned tasks.\n\n",
		"This is a courtesy notification regarding the upcoming changes to the authentication system. No action is required at this time.\n\n",
	}
	closings := []string{
		"Best regards,\n",
		"Kind regards,\n",
		"Thanks,\n",
		"Warm regards,\n",
		"Regards,\n",
		"Sincerely,\n",
		"Thank you,\n",
		"Cheers,\n",
	}
	attachmentNames := []string{
		"Q3_Budget_Review.xlsx",
		"Project_Timeline_v3.pdf",
		"Draft_Policy_Document.docx",
		"Vendor_Agreement_2024.pdf",
		"Onboarding_Checklist.pdf",
		"Meeting_Notes.docx",
		"Security_Advisory.pdf",
	}

	addr := func() string {
		fn := firstNames[rng.IntN(len(firstNames))]
		ln := lastNames[rng.IntN(len(lastNames))]
		dom := domains[rng.IntN(len(domains))]
		return fn + " " + ln + " <" + strings.ToLower(fn[:1]+ln) + "@" + dom + ">"
	}
	msgID := func() string {
		return fmt.Sprintf("<%08x.%08x@%s>", rng.Uint32(), rng.Uint32(),
			domains[rng.IntN(len(domains))])
	}

	// Pick a body structure
	type structure int
	const (
		structPlain structure = iota
		structMultipartAlt
		structMultipartMixed
	)
	st := structure(rng.IntN(3))

	boundary := fmt.Sprintf("----=_Part_%08x_%08x", rng.Uint32(), rng.Uint32())

	from := addr()
	to := addr()
	subject := subjects[rng.IntN(len(subjects))]

	// RFC 5322 date — use a fixed realistic format with a random recent-ish offset
	dateOffsets := []string{
		"Mon, 03 Mar 2025 09:14:22 +0000",
		"Tue, 11 Feb 2025 14:37:08 -0500",
		"Wed, 22 Jan 2025 08:02:55 +0100",
		"Thu, 09 Apr 2025 17:45:30 +0000",
		"Fri, 28 Mar 2025 11:23:47 -0800",
		"Mon, 17 Feb 2025 15:10:00 +0000",
		"Thu, 06 Mar 2025 10:00:00 +0100",
	}
	date := dateOffsets[rng.IntN(len(dateOffsets))]

	// Headers
	buf = append(buf, "MIME-Version: 1.0\r\n"...)
	buf = append(buf, "From: "+from+"\r\n"...)
	buf = append(buf, "To: "+to+"\r\n"...)
	// Optional Cc
	if rng.Float64() < 0.35 {
		buf = append(buf, "Cc: "+addr()+"\r\n"...)
	}
	buf = append(buf, "Date: "+date+"\r\n"...)
	buf = append(buf, "Subject: "+subject+"\r\n"...)
	buf = append(buf, "Message-ID: "+msgID()+"\r\n"...)
	// Optional Reply-To / X-Mailer
	if rng.Float64() < 0.25 {
		buf = append(buf, "Reply-To: "+addr()+"\r\n"...)
	}
	xmailers := []string{
		"Microsoft Outlook 16.0",
		"Apple Mail (3774.600.62)",
		"Thunderbird 115.8.1",
		"Gmail (web)",
	}
	buf = append(buf, "X-Mailer: "+xmailers[rng.IntN(len(xmailers))]+"\r\n"...)

	switch st {
	case structPlain:
		buf = append(buf, "Content-Type: text/plain; charset=utf-8\r\n"...)
		buf = append(buf, "Content-Transfer-Encoding: 7bit\r\n"...)
		buf = append(buf, "\r\n"...)
	case structMultipartAlt:
		buf = append(buf, "Content-Type: multipart/alternative; boundary=\""+boundary+"\"\r\n"...)
		buf = append(buf, "\r\n"...)
	case structMultipartMixed:
		buf = append(buf, "Content-Type: multipart/mixed; boundary=\""+boundary+"\"\r\n"...)
		buf = append(buf, "\r\n"...)
	}

	// Build plain-text body
	plainBody := ""
	numParas := 1 + rng.IntN(4)
	for i := 0; i < numParas; i++ {
		plainBody += bodyParagraphs[rng.IntN(len(bodyParagraphs))]
	}
	closing := closings[rng.IntN(len(closings))]
	fn := firstNames[rng.IntN(len(firstNames))]
	ln := lastNames[rng.IntN(len(lastNames))]
	plainBody += closing + fn + " " + ln + "\r\n"

	switch st {
	case structPlain:
		buf = append(buf, plainBody...)

	case structMultipartAlt:
		// text/plain part
		buf = append(buf, "--"+boundary+"\r\n"...)
		buf = append(buf, "Content-Type: text/plain; charset=utf-8\r\n"...)
		buf = append(buf, "Content-Transfer-Encoding: 7bit\r\n\r\n"...)
		buf = append(buf, plainBody...)
		buf = append(buf, "\r\n"...)
		// text/html part
		buf = append(buf, "--"+boundary+"\r\n"...)
		buf = append(buf, "Content-Type: text/html; charset=utf-8\r\n"...)
		buf = append(buf, "Content-Transfer-Encoding: 7bit\r\n\r\n"...)
		htmlBody := "<html><body><p>" +
			strings.ReplaceAll(strings.ReplaceAll(plainBody, "\r\n", "<br>\n"), "\n", "<br>\n") +
			"</p></body></html>\r\n"
		buf = append(buf, htmlBody...)
		buf = append(buf, "--"+boundary+"--\r\n"...)

	case structMultipartMixed:
		// text/plain part
		buf = append(buf, "--"+boundary+"\r\n"...)
		buf = append(buf, "Content-Type: text/plain; charset=utf-8\r\n"...)
		buf = append(buf, "Content-Transfer-Encoding: 7bit\r\n\r\n"...)
		buf = append(buf, plainBody...)
		buf = append(buf, "\r\n"...)
		// attachment part (base64-encoded random bytes)
		buf = append(buf, "--"+boundary+"\r\n"...)
		attName := attachmentNames[rng.IntN(len(attachmentNames))]
		buf = append(buf, "Content-Type: application/octet-stream; name=\""+attName+"\"\r\n"...)
		buf = append(buf, "Content-Transfer-Encoding: base64\r\n"...)
		buf = append(buf, "Content-Disposition: attachment; filename=\""+attName+"\"\r\n\r\n"...)
		// fill remaining space with base64 lines
		remaining := size - len(buf) - len("\r\n--"+boundary+"--\r\n")
		if remaining > 0 {
			rawBytes := make([]byte, (remaining/4)*3)
			for i := range rawBytes {
				rawBytes[i] = byte(rng.Uint32())
			}
			encoded := base64.StdEncoding.EncodeToString(rawBytes)
			// wrap at 76 chars per MIME spec
			for len(encoded) > 0 {
				lineLen := 76
				if lineLen > len(encoded) {
					lineLen = len(encoded)
				}
				buf = append(buf, encoded[:lineLen]...)
				buf = append(buf, "\r\n"...)
				encoded = encoded[lineLen:]
			}
		}
		buf = append(buf, "--"+boundary+"--\r\n"...)
	}

	// Pad or truncate to exactly size bytes
	if len(buf) < size {
		// pad with repeated body paragraphs to fill
		for len(buf) < size {
			para := bodyParagraphs[rng.IntN(len(bodyParagraphs))]
			rem := size - len(buf)
			if len(para) <= rem {
				buf = append(buf, para...)
			} else {
				buf = append(buf, para[:rem]...)
			}
		}
	}

	return buf[:size]
}

// ---------- Easter Egg generator ----------

// The Easter egg generator systematically exercises the sdhash algorithm by
// sweeping through a multidimensional parameter space. Every file is
// deterministic (seeded by the global PRNG), but collectively the 3 000-file
// corpus covers the full space of interesting sdhash edge cases.
//
// Dimensions
//
//  1. Base content   sparse (very low noise) | random (full noise)
//  2. Insert count   1 → N, where N grows until inserts would dominate the file
//  3. Insert size    minInsertSize (just below one sdhash feature window) →
//                    size/numInserts (inserts fill the whole file at the extreme)
//  4. Insert content
//       Phase A — neutral:    one insert type (document_like)
//       Phase B — uniform:    all inserts from one named type
//                             (document_like | powershell | javascript |
//                              python | email | pe)
//       Phase C — mixed:      inserts cycle through 2, 3, or 4 named types

// sdhashFeatureWindow is the byte width of one sdhash rolling-hash window.
// Inserts begin just below this size to probe the detection boundary.
const sdhashFeatureWindow = 64

// Easter-egg insert-content type constants.
const (
	eeNeutral    = 0 // document_like patterns
	eeDocLike    = 1
	eePowerShell = 2
	eeJavaScript = 3
	eePython     = 4
	eeEmail      = 5
	eePE         = 6
)

// eeEmailSnippets is a small pool of plain email body text used for
// easter-egg email inserts (full RFC 5322 headers are not meaningful at
// insert sizes of tens to hundreds of bytes).
var eeEmailSnippets = []string{
	"Please find the relevant details below for your review and approval.\n\n",
	"Following up on our earlier conversation — please let me know your thoughts.\n\n",
	"As discussed, please review the attached and confirm receipt at your earliest convenience.\n\n",
	"Kindly note the updated deadline and ensure all required materials are submitted on time.\n\n",
	"Thank you for your prompt response. We will proceed as outlined below.\n\n",
	"Per our agreement, the next steps are as follows. Please confirm if you have any questions.\n\n",
	"I wanted to bring this to your attention before the end of business today.\n\n",
	"Please be advised that the system will be unavailable during the maintenance window.\n\n",
}

// makeEEInsert generates `size` bytes of insert content of the given type.
func makeEEInsert(rng *rand.Rand, insertType, size int) []byte {
	if size <= 0 {
		return nil
	}
	buf := make([]byte, size)
	switch insertType {
	case eeNeutral, eeDocLike:
		// Reuse the document-like generator: realistic text entropy.
		src := genDocumentLike(rng, size)
		copy(buf, src)
	case eePowerShell:
		fillSnippetBytes(buf, psSnippets, rng)
	case eeJavaScript:
		fillSnippetBytes(buf, jsSnippets, rng)
	case eePython:
		fillSnippetBytes(buf, pySnippets, rng)
	case eeEmail:
		fillSnippetBytes(buf, eeEmailSnippets, rng)
	case eePE:
		// x86/x64 opcode patterns — high but structured entropy.
		fillTextSection(rng, buf, rng.IntN(2) == 0)
	}
	return buf
}

// fillSnippetBytes fills dst by concatenating randomly selected snippets,
// truncating cleanly at the end.
func fillSnippetBytes(dst []byte, pool []string, rng *rand.Rand) {
	off := 0
	for off < len(dst) {
		s := pool[rng.IntN(len(pool))]
		n := copy(dst[off:], s)
		off += n
	}
}

// genEasterEgg produces a file that systematically exercises sdhash by
// placing structured inserts of varying size, count, and content type into
// a sparse or random base.
func genEasterEgg(rng *rand.Rand, size int) []byte {
	// minInsert is the smallest insert: 8 bytes below the sdhash feature
	// window so that the smallest files sit just outside reliable detection.
	const minInsert = sdhashFeatureWindow - 8 // 56 bytes

	// File must be large enough to hold at least two non-overlapping inserts
	// with spacing; fall back to sparse if the file is tiny.
	if size < minInsert*4 {
		return genSparse(rng, size)
	}

	// ------------------------------------------------------------------
	// Dimension 1: base content
	// ------------------------------------------------------------------
	var buf []byte
	if rng.IntN(2) == 0 {
		buf = genSparse(rng, size)
	} else {
		buf = genRandom(rng, size)
	}

	// ------------------------------------------------------------------
	// Dimension 2: number of inserts
	// Upper bound: stop when inserts would occupy more than 75% of the file.
	// ------------------------------------------------------------------
	maxInserts := (size * 3 / 4) / minInsert
	if maxInserts < 1 {
		maxInserts = 1
	}
	if maxInserts > 8 {
		maxInserts = 8
	}
	numInserts := 1 + rng.IntN(maxInserts)

	// ------------------------------------------------------------------
	// Dimension 3: insert size
	// Sweep from just-below-window up to the point where inserts fill the file.
	// ------------------------------------------------------------------
	maxInsertSize := size / numInserts
	if maxInsertSize < minInsert {
		maxInsertSize = minInsert
	}
	insertSize := minInsert
	if maxInsertSize > minInsert {
		insertSize = minInsert + rng.IntN(maxInsertSize-minInsert+1)
	}

	// ------------------------------------------------------------------
	// Dimension 4: insert content mode
	//   0       neutral (document_like)
	//   1–6     uniform named type
	//   7       mix of 2 named types
	//   8       mix of 3 named types
	//   9       mix of 4 named types
	// ------------------------------------------------------------------
	namedTypes := []int{eeDocLike, eePowerShell, eeJavaScript, eePython, eeEmail, eePE}
	contentMode := rng.IntN(10)

	var insertTypes []int
	switch {
	case contentMode == 0:
		// Phase A: neutral
		insertTypes = []int{eeNeutral}
	case contentMode <= 6:
		// Phase B: uniform named type (modes 1–6 map to the 6 named types)
		insertTypes = []int{namedTypes[contentMode-1]}
	default:
		// Phase C: mix of 2, 3, or 4 types (modes 7, 8, 9)
		mixCount := contentMode - 5 // 2, 3, or 4
		// Pick mixCount distinct types by shuffling namedTypes
		pool := make([]int, len(namedTypes))
		copy(pool, namedTypes)
		rng.Shuffle(len(pool), func(i, j int) { pool[i], pool[j] = pool[j], pool[i] })
		insertTypes = pool[:mixCount]
	}

	// ------------------------------------------------------------------
	// Place inserts evenly across the file
	// ------------------------------------------------------------------
	spacing := size / (numInserts + 1)
	for i := 0; i < numInserts; i++ {
		insertType := insertTypes[i%len(insertTypes)]
		pos := spacing * (i + 1)
		end := pos + insertSize
		if end > size {
			pos = size - insertSize
			end = size
		}
		if pos < 0 {
			pos = 0
			end = min(insertSize, size)
		}
		insert := makeEEInsert(rng, insertType, end-pos)
		copy(buf[pos:end], insert)
	}

	return buf
}

// ---------- large generator ----------

// genLarge produces high-entropy random data with periodic 64-byte structured
// headers every 4 MiB. This exercises the multi-chunk parallel code path in
// sdhash which activates at 32 MiB.
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
	// Header layout: 4-byte magic \x7fLRG | 4-byte LE chunk index | 56 bytes random
	// (The 56 random bytes are the ones already written by the fill pass above.)
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

// ---------- PowerShell snippet pool ----------

// psSnippets is a pool of syntactically plausible PowerShell fragments with
// Windows-style \r\n line endings. genPowerShellPure selects randomly from
// this pool; 20% of selections have \r\n converted to \n.
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

// ---------- JavaScript snippet pool ----------

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

// ===========================================================================
// Section 2 — Corpus assembly, digest-row capture, and anchor accumulation
//
// Everything below is the in-package glue that reproduces the sdhashtest and
// csvhash tools. It is not copied from bindatagenerator.
// ===========================================================================

// bindatagenerator compiled-in defaults (see its const block and
// defaultCategoryConfigs). These must match exactly: they drive the PRNG seed
// chain and therefore the generated bytes.
const (
	bdgMinSize      = 4097       // ssdeep minimum useful size + 1
	bdgMaxSize      = 10_485_760 // 10 MB
	bdgFilesPerType = 3000
	bdgMasterSeed   = int64(20260324)
	bdgMixedBag     = 1200 // mixedbag default count (mixedBagDefault)
)

// corpusDDBlock is the DD-mode block size used by the reference harness
// (sdhashtest ddBlockSize, and the C++ harness it mirrors). 1 MiB.
const corpusDDBlock uint32 = 1048576

// genCatConfig mirrors one entry of bindatagenerator's defaultCategoryConfigs
// resolved against its generatorRegistry. Zero minSize/maxSize/count mean
// "use the global default".
type genCatConfig struct {
	name    string
	gen     func(rng *rand.Rand, size int) []byte
	minSize int
	maxSize int
	count   int
}

// bdgDefaultCategories returns the canonical category list in the exact order
// of bindatagenerator's defaultCategoryConfigs. Order is load-bearing: it
// determines the order in which the shared seed RNG is consumed, so it must
// never change.
func bdgDefaultCategories() []genCatConfig {
	return []genCatConfig{
		{"random", genRandom, 0, 0, 0},
		{"sparse", genSparse, 0, 0, 0},
		{"repetitive", genRepetitive, 0, 0, 0},
		{"structured", genStructured, 0, 0, 0},
		{"low_entropy", genLowEntropy, 0, 0, 0},
		{"subfloor_entropy", genSubfloorEntropy, 0, 0, 0},
		{"document_like", genDocumentLike, 0, 0, 0},
		{"pe", genPE, 0, 0, 0},
		{"elf", genELF, 0, 0, 0},
		{"macho", genMachO, 0, 0, 0},
		{"dex", genDEX, 0, 0, 0},
		{"python", genPython, 0, 0, 0},
		{"email", genEmail, 0, 0, 0},
		{"easter_egg", genEasterEgg, 0, 0, 0},
		{"ole2_vba_dropper", genOLE2VBADropper, 0, 0, 0},
		{"large", genLarge, 33 * 1024 * 1024, 80 * 1024 * 1024, 20},
		{"powershell_pure", genPowerShellPure, 0, 0, 0},
		{"powershell_embedded_b64", genPowerShellEmbeddedB64, 0, 0, 0},
		{"powershell_embedded_hex", genPowerShellEmbeddedHex, 0, 0, 0},
		{"powershell_signed", genPowerShellSigned, 0, 0, 0},
		{"javascript_pure", genJavaScriptPure, 0, 0, 0},
		{"javascript_embedded_b64", genJavaScriptEmbeddedB64, 0, 0, 0},
		{"javascript_embedded_hex", genJavaScriptEmbeddedHex, 0, 0, 0},
	}
}

// corpusWork is one generated input reduced to the cheap metadata needed to
// (re)produce it: the category (anchor bucket), the bare filename (anchor
// key), and the PCG seed + size that deterministically regenerate its bytes.
//
// The corpus is planned as a slice of corpusWork by consuming the shared seed
// RNG sequentially (cheap). The expensive step — running the generator to
// produce the actual bytes — is deferred to generate() so it can be done in
// parallel worker goroutines and the bytes discarded immediately afterward.
// This keeps peak memory bounded to (worker count × file size) rather than the
// full multi-gigabyte corpus.
type corpusWork struct {
	category string
	filename string
	fileSeed int64
	size     int
	gen      func(rng *rand.Rand, size int) []byte
}

// generate reproduces the file's bytes. bindatagenerator seeds each file with
// rand.NewPCG(fileSeed, 0), so this matches its per-file byte output exactly.
func (w corpusWork) generate() []byte {
	return w.gen(rand.New(rand.NewPCG(uint64(w.fileSeed), 0)), w.size)
}

// planNormalCorpus reproduces bindatagenerator's normal (-n) generation plan:
// per-category files drawn from PCG stream 0. It is the corpus the corpushash
// test hashes. filesPerType is the global count; per-category overrides in
// cats take precedence (only "large" overrides in the default set). Only the
// seed RNG is consumed here — no bytes are generated.
func planNormalCorpus(globalMin, globalMax, filesPerType int, cats []genCatConfig) []corpusWork {
	seedRng := rand.New(rand.NewPCG(uint64(bdgMasterSeed), 0))

	var out []corpusWork
	for _, cc := range cats {
		lo, hi := globalMin, globalMax
		if cc.minSize > 0 {
			lo = cc.minSize
		}
		if cc.maxSize > 0 {
			hi = cc.maxSize
		}
		n := filesPerType
		if cc.count > 0 {
			n = cc.count
		}
		sizes := generateSizes(seedRng, n, lo, hi)
		for i, size := range sizes {
			fileSeed := int64(seedRng.Uint64())
			out = append(out, corpusWork{
				category: cc.name,
				filename: fmt.Sprintf("%s_%06d_%d.bin", cc.name, i, size),
				fileSeed: fileSeed,
				size:     size,
				gen:      cc.gen,
			})
		}
	}
	return out
}

// planMixedbagCorpus reproduces bindatagenerator's mixedbag (-m) generation
// plan: totalCount/len(cats) files per category drawn from PCG stream 1. It is
// the corpus the corpuscompare test hashes. Unlike normal generation,
// mixedbag ignores per-category count overrides (every category gets perCat)
// but honors per-category min/max size overrides.
func planMixedbagCorpus(globalMin, globalMax, totalCount int, cats []genCatConfig) []corpusWork {
	perCat := totalCount / len(cats)
	seedRng := rand.New(rand.NewPCG(uint64(bdgMasterSeed), 1))

	var out []corpusWork
	for _, cc := range cats {
		lo, hi := globalMin, globalMax
		if cc.minSize > 0 {
			lo = cc.minSize
		}
		if cc.maxSize > 0 {
			hi = cc.maxSize
		}
		sizes := generateSizes(seedRng, perCat, lo, hi)
		for i, size := range sizes {
			fileSeed := int64(seedRng.Uint64())
			out = append(out, corpusWork{
				category: cc.name,
				filename: fmt.Sprintf("%s_%06d_%d.bin", cc.name, i, size),
				fileSeed: fileSeed,
				size:     size,
				gen:      cc.gen,
			})
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Digest computation
// ---------------------------------------------------------------------------

// computeStreamDigest computes a stream-mode digest, matching sdhashtest's
// computeDigest(path, 0).
func computeStreamDigest(data []byte) (Sdbf, error) {
	factory, err := New(data)
	if err != nil {
		return nil, err
	}
	return factory.Compute()
}

// computeDDDigest computes a DD-mode digest at corpusDDBlock, matching
// sdhashtest's computeDigest(path, ddBlockSize).
func computeDDDigest(data []byte) (Sdbf, error) {
	factory, err := New(data)
	if err != nil {
		return nil, err
	}
	return factory.WithBlockSize(corpusDDBlock).Compute()
}

// ---------------------------------------------------------------------------
// CSV-row field capture (payload columns, in header order)
//
// These reproduce sdhashtest's writeStreamDigestRow / writeDDDigestRow /
// runCorpusCompareScoring field computation and formatting exactly. Only the
// payload columns are returned — the filename/category columns become the
// anchor key/bucket and are supplied separately. Field order and formatting
// (base-10 integers, FormatFloat 'g' precision 17, FormatBool) must match the
// tools byte-for-byte or the anchor changes.
// ---------------------------------------------------------------------------

// streamDigestPayload returns the 14 payload fields of a corpushash stream row
// (all columns after filename and category).
func streamDigestPayload(sd Sdbf) []string {
	hash := strings.TrimRight(sd.String(), "\r\n")
	inputSize := sd.InputSize()
	filterCount := sd.FilterCount()
	filterSize := sd.FilterSize()
	density := sd.FeatureDensity()
	lastCount := LastCount(sd)
	totalElements := TotalElements(sd)

	var minElem, maxElem, meanElem uint32
	var totalHamming uint64
	var minHam, maxHam, meanHam uint32

	if n := filterCount; n > 0 {
		minElem = uint32(math.MaxUint32)
		maxElem = 0
		minHam = uint32(math.MaxUint32)
		maxHam = 0
		var sumH uint64
		for i := uint32(0); i < n; i++ {
			e := ElemCount(sd, i)
			h := uint32(Hamming(sd, i))
			if e < minElem {
				minElem = e
			}
			if e > maxElem {
				maxElem = e
			}
			if h < minHam {
				minHam = h
			}
			if h > maxHam {
				maxHam = h
			}
			sumH += uint64(h)
		}
		meanElem = uint32(math.Round(float64(totalElements) / float64(n)))
		totalHamming = sumH
		meanHam = uint32(math.Round(float64(sumH) / float64(n)))
	}

	return []string{
		hash,
		strconv.FormatUint(inputSize, 10),
		strconv.FormatUint(uint64(filterCount), 10),
		strconv.FormatUint(filterSize, 10),
		strconv.FormatFloat(density, 'g', 17, 64),
		strconv.FormatUint(uint64(lastCount), 10),
		strconv.FormatUint(totalElements, 10),
		strconv.FormatUint(uint64(minElem), 10),
		strconv.FormatUint(uint64(maxElem), 10),
		strconv.FormatUint(uint64(meanElem), 10),
		strconv.FormatUint(totalHamming, 10),
		strconv.FormatUint(uint64(minHam), 10),
		strconv.FormatUint(uint64(maxHam), 10),
		strconv.FormatUint(uint64(meanHam), 10),
	}
}

// ddDigestPayload returns the 7 payload fields of a corpushash DD row.
func ddDigestPayload(sd Sdbf) []string {
	hash := strings.TrimRight(sd.String(), "\r\n")
	inputSize := sd.InputSize()
	filterCount := sd.FilterCount()
	filterSize := sd.FilterSize()
	density := sd.FeatureDensity()
	totalElements := TotalElements(sd)

	var sumH uint64
	for i := uint32(0); i < filterCount; i++ {
		sumH += uint64(Hamming(sd, i))
	}

	return []string{
		hash,
		strconv.FormatUint(inputSize, 10),
		strconv.FormatUint(uint64(filterCount), 10),
		strconv.FormatUint(filterSize, 10),
		strconv.FormatFloat(density, 'g', 17, 64),
		strconv.FormatUint(totalElements, 10),
		strconv.FormatUint(sumH, 10),
	}
}

// comparePayload returns the 4 payload fields of a corpuscompare row
// (density1, density2, score, ok).
func comparePayload(d1, d2 float64, score int, ok bool) []string {
	return []string{
		strconv.FormatFloat(d1, 'g', 17, 64),
		strconv.FormatFloat(d2, 'g', 17, 64),
		strconv.Itoa(score),
		strconv.FormatBool(ok),
	}
}

// ---------------------------------------------------------------------------
// SHA-256 anchor accumulation (reproduces csvhash's three-tier construction)
// ---------------------------------------------------------------------------

// csvhash structural control bytes (§3 of csvhash). None appears in sdhash
// output data, so they are safe delimiters.
const (
	ctrlUS  = byte(0x1F) // Unit Separator — joins the two filenames in a compare key
	ctrlRS  = byte(0x1E) // Record Separator — between key and each payload field
	ctrlETB = byte(0x17) // End of Transmission Block — terminates a canonical record
)

// anchorRecord is one row reduced to its key and canonical-record hash.
type anchorRecord struct {
	key string
	h   [32]byte
}

// canonicalRecord builds the Tier-1 canonical byte string for a row:
//
//	key RS field0 RS field1 … RS field{m-1} ETB
//
// identical to csvhash's buildCanonical.
func canonicalRecord(key string, payload []string) []byte {
	size := len(key) + len(payload) + 1
	for _, f := range payload {
		size += len(f)
	}
	buf := make([]byte, 0, size)
	buf = append(buf, key...)
	for _, f := range payload {
		buf = append(buf, ctrlRS)
		buf = append(buf, f...)
	}
	buf = append(buf, ctrlETB)
	return buf
}

// hashRecord returns SHA-256 of the canonical record (Tier 1).
func hashRecord(key string, payload []string) [32]byte {
	return sha256.Sum256(canonicalRecord(key, payload))
}

// compareKey builds the compare-flavor composite key: filename1 US filename2.
func compareKey(f1, f2 string) string {
	kb := make([]byte, 0, len(f1)+1+len(f2))
	kb = append(kb, f1...)
	kb = append(kb, ctrlUS)
	kb = append(kb, f2...)
	return string(kb)
}

// computeCorpusAnchor implements csvhash Tier 2 (per bucket: sort records by
// key, SHA-256 the concatenated record hashes) and Tier 3 (sort bucket names,
// SHA-256 the concatenated bucket hashes) and returns the final anchor. The
// sort keys make the result independent of the order rows were produced in,
// so parallel digest/score computation is safe.
func computeCorpusAnchor(buckets map[string][]anchorRecord) [32]byte {
	names := make([]string, 0, len(buckets))
	for name := range buckets {
		names = append(names, name)
	}
	slices.Sort(names)

	tier3 := make([]byte, 0, len(names)*32)
	for _, name := range names {
		recs := buckets[name]
		slices.SortFunc(recs, func(a, b anchorRecord) int {
			return strings.Compare(a.key, b.key)
		})
		tier2 := make([]byte, 0, len(recs)*32)
		for _, r := range recs {
			tier2 = append(tier2, r.h[:]...)
		}
		hBucket := sha256.Sum256(tier2)
		tier3 = append(tier3, hBucket[:]...)
	}
	return sha256.Sum256(tier3)
}

// checkAnchor compares a computed anchor against its expected hex constant.
// label names the test family ("corpushash" or "corpuscompare") and mode is
// "stream" or "dd". An empty want means the anchor has not been pinned yet:
// the computed value is reported so it can be verified against the reference
// pipeline and pasted into the constant.
func checkAnchor(t *testing.T, label, mode, want string, got [32]byte) {
	t.Helper()
	gotHex := hex.EncodeToString(got[:])
	if want == "" {
		t.Errorf("%s %s: expected anchor not pinned. "+
			"Verify the value below against your reference pipeline, then set it as the constant:\n  %s",
			label, mode, gotHex)
		return
	}
	if want != gotHex {
		t.Errorf("%s %s: anchor mismatch\n  want: %s\n  got:  %s", label, mode, want, gotHex)
		return
	}
	t.Logf("%s %s: anchor OK: %s", label, mode, gotHex)
}
