package binary

import (
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
)

const MaxReadSize = 16 << 20

var (
	ErrUnmapped       = errors.New("virtual address is not mapped")
	ErrNotFileBacked  = errors.New("virtual address is not file-backed")
	ErrNotExecutable  = errors.New("region is not executable")
	ErrRegionBoundary = errors.New("read crosses a region boundary")
)

type Permissions uint8

const (
	PermRead Permissions = 1 << iota
	PermWrite
	PermExecute
)

type Format string

const (
	FormatELF   Format = "ELF"
	FormatPE    Format = "PE"
	FormatMachO Format = "Mach-O"
)

type Architecture string

const (
	ArchUnknown Architecture = "unknown"
	ArchX86     Architecture = "x86"
	ArchX8664   Architecture = "x86_64"
	ArchARM     Architecture = "arm"
	ArchARM64   Architecture = "arm64"
	ArchRISCV64 Architecture = "riscv64"
)

type Endianness string

const (
	LittleEndian Endianness = "little"
	BigEndian    Endianness = "big"
)

type Info struct {
	Format       Format
	Architecture Architecture
	Bits         uint8
	Endianness   Endianness
	Entry        uint64
	Slice        string
}

type Region struct {
	Name        string
	Address     uint64
	MemorySize  uint64
	FileOffset  uint64
	FileSize    uint64
	Permissions Permissions
}

type Image struct {
	Info     Info
	regions  []Region
	reader   io.ReaderAt
	fileSize uint64
}

// NewImage validates virtual address mappings and file bounds.
// The caller owns reader and must keep it open while the image is used.
func NewImage(
	reader io.ReaderAt,
	fileSize uint64,
	info Info,
	regions []Region,
) (*Image, error) {
	if info.Format == "" || info.Architecture == "" {
		return nil, errors.New("missing image format or architecture")
	}

	if info.Bits != 16 && info.Bits != 32 && info.Bits != 64 {
		return nil, fmt.Errorf("invalid image bitness %d", info.Bits)
	}

	if info.Endianness != LittleEndian &&
		info.Endianness != BigEndian {
		return nil, fmt.Errorf(
			"invalid image endianness %q",
			info.Endianness,
		)
	}

	if reader == nil {
		return nil, errors.New("nil binary reader")
	}

	if fileSize > math.MaxInt64 {
		return nil, fmt.Errorf(
			"binary size exceeds supported reader offsets: %d",
			fileSize,
		)
	}

	if len(regions) == 0 {
		return nil, errors.New("binary contains no loadable regions")
	}

	copied := append([]Region(nil), regions...)

	sort.Slice(copied, func(i, j int) bool {
		return copied[i].Address < copied[j].Address
	})

	for i, region := range copied {
		if region.MemorySize == 0 {
			return nil, fmt.Errorf(
				"region %q has zero memory size",
				region.Name,
			)
		}

		if region.FileSize > region.MemorySize {
			return nil, fmt.Errorf(
				"region %q maps more file bytes than virtual bytes",
				region.Name,
			)
		}

		if region.Address > math.MaxUint64-region.MemorySize {
			return nil, fmt.Errorf(
				"region %q virtual address range overflows",
				region.Name,
			)
		}

		if region.FileOffset > fileSize ||
			region.FileSize > fileSize-region.FileOffset {
			return nil, fmt.Errorf(
				"region %q extends past end of file",
				region.Name,
			)
		}

		if i > 0 {
			previous := copied[i-1]

			if previous.Address+previous.MemorySize > region.Address {
				return nil, fmt.Errorf(
					"overlapping regions %q and %q",
					previous.Name,
					region.Name,
				)
			}
		}
	}

	return &Image{
		Info:     info,
		regions:  copied,
		reader:   reader,
		fileSize: fileSize,
	}, nil
}

func (image *Image) Regions() []Region {
	return append([]Region(nil), image.regions...)
}

func (image *Image) FileSize() uint64 {
	return image.fileSize
}

// RegionAt identifies the region containing a virtual address.
func (image *Image) RegionAt(address uint64) (Region, bool) {
	index := sort.Search(len(image.regions), func(i int) bool {
		return image.regions[i].Address > address
	}) - 1

	if index < 0 {
		return Region{}, false
	}

	region := image.regions[index]

	return region, address-region.Address < region.MemorySize
}

// VirtualToFile converts a virtual address into a file offset.
// Zero-filled memory has no corresponding file offset.
func (image *Image) VirtualToFile(address uint64) (uint64, error) {
	region, ok := image.RegionAt(address)

	if !ok {
		return 0, fmt.Errorf("0x%x: %w", address, ErrUnmapped)
	}

	delta := address - region.Address

	if delta >= region.FileSize {
		return 0, fmt.Errorf(
			"0x%x: %w",
			address,
			ErrNotFileBacked,
		)
	}

	return region.FileOffset + delta, nil
}

// ReadVirtual reads an exact file-backed virtual address range.
func (image *Image) ReadVirtual(
	address uint64,
	size uint64,
) ([]byte, error) {
	return image.read(address, size, false, false)
}

// ReadExecutable only reads file-backed executable memory.
func (image *Image) ReadExecutable(
	address uint64,
	size uint64,
) ([]byte, error) {
	return image.read(address, size, true, false)
}

// ReadMemory includes loader-initialized zero-filled memory.
func (image *Image) ReadMemory(
	address uint64,
	size uint64,
) ([]byte, error) {
	return image.read(address, size, false, true)
}

func (image *Image) read(
	address uint64,
	size uint64,
	executable bool,
	zeroFill bool,
) ([]byte, error) {
	if size > MaxReadSize {
		return nil, fmt.Errorf(
			"requested %d bytes exceeds %d-byte read limit",
			size,
			MaxReadSize,
		)
	}

	if size == 0 {
		return []byte{}, nil
	}

	region, ok := image.RegionAt(address)

	if !ok {
		return nil, fmt.Errorf("0x%x: %w", address, ErrUnmapped)
	}

	if executable && region.Permissions&PermExecute == 0 {
		return nil, fmt.Errorf(
			"region %q: %w",
			region.Name,
			ErrNotExecutable,
		)
	}

	delta := address - region.Address

	if size > region.MemorySize-delta {
		return nil, fmt.Errorf(
			"0x%x + %d: %w",
			address,
			size,
			ErrRegionBoundary,
		)
	}

	if !zeroFill &&
		(delta >= region.FileSize ||
			size > region.FileSize-delta) {
		return nil, fmt.Errorf(
			"0x%x + %d: %w",
			address,
			size,
			ErrNotFileBacked,
		)
	}

	data := make([]byte, int(size))

	if delta >= region.FileSize {
		return data, nil
	}

	backed := size

	if remaining := region.FileSize - delta; backed > remaining {
		backed = remaining
	}

	n, err := image.reader.ReadAt(
		data[:int(backed)],
		int64(region.FileOffset+delta),
	)

	if err != nil {
		return nil, fmt.Errorf(
			"reading region %q at 0x%x: %w",
			region.Name,
			address,
			err,
		)
	}

	if n != int(backed) {
		return nil, fmt.Errorf(
			"reading region %q at 0x%x: %w",
			region.Name,
			address,
			io.ErrUnexpectedEOF,
		)
	}

	return data, nil
}
