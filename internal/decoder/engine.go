package decoder

import (
	"errors"
	"fmt"
	"math"

	"bininspect/internal/binary"
)

func DecodeAt(
	image *binary.Image,
	address uint64,
) (Instruction, error) {
	return DecodeAtMode(image, address, ModeDefault)
}

func DecodeAtMode(
	image *binary.Image,
	address uint64,
	mode DecodeMode,
) (Instruction, error) {
	if image == nil {
		return Instruction{}, errors.New("nil binary image")
	}

	arch := image.Info.Architecture

	if err := validateMode(arch, mode); err != nil {
		return Instruction{}, err
	}

	region, ok := image.RegionAt(address)
	if !ok ||
		region.Permissions&binary.PermExecute == 0 ||
		address-region.Address >= region.FileSize {
		return Instruction{}, fmt.Errorf(
			"%w at %#x", ErrNotExecutable, address,
		)
	}

	maximum := uint64(4)

	switch arch {
	case binary.ArchX86, binary.ArchX8664:
		maximum = 15

	case binary.ArchARM:
		alignment := uint64(4)
		if mode == ModeThumb {
			alignment = 2
		}
		if address%alignment != 0 {
			return Instruction{}, ErrInvalidRange
		}

	case binary.ArchARM64:
		if address%4 != 0 {
			return Instruction{}, ErrInvalidRange
		}

	case binary.ArchRISCV64:
		if address%2 != 0 ||
			image.Info.Endianness != binary.LittleEndian {
			return Instruction{}, ErrUnsupportedArchitecture
		}

	default:
		return Instruction{}, fmt.Errorf(
			"%w: %s",
			ErrUnsupportedArchitecture, arch,
		)
	}

	available := region.FileSize - (address - region.Address)

	if available < maximum {
		maximum = available
	}

	data, err := image.ReadExecutable(address, maximum)
	if err != nil {
		return Instruction{}, fmt.Errorf(
			"reading %#x: %w", address, err,
		)
	}

	var instruction Instruction

	switch arch {
	case binary.ArchX86, binary.ArchX8664:
		instruction, err = decodeX86(
			data, address, arch,
		)

	case binary.ArchARM:
		if mode == ModeThumb {
			// A single decode cannot reconstruct a preceding IT
			// block. Use DecodeRangeMode for Thumb streams.
			instruction, err = decodeThumb(
				data, address, image.Info.Endianness,
			)
		} else {
			instruction, err = decodeARM(
				data, address, image.Info.Endianness,
			)
			mode = ModeARM
		}

	case binary.ArchARM64:
		instruction, err = decodeARM64(
			data, address, image.Info.Endianness,
		)

	case binary.ArchRISCV64:
		instruction, err = decodeRISCV64(
			data, address,
		)
	}

	if err != nil {
		return Instruction{}, err
	}

	if instruction.Size == 0 ||
		uint64(instruction.Size) > uint64(len(data)) {
		return Instruction{}, fmt.Errorf(
			"%w at %#x: invalid instruction length",
			ErrInvalidInstruction, address,
		)
	}

	instruction.Mode = mode
	return instruction, nil
}

func DecodeRange(
	image *binary.Image,
	start, size uint64,
) ([]Instruction, error) {
	return DecodeRangeMode(
		image, start, size, ModeDefault,
	)
}

func DecodeRangeMode(
	image *binary.Image,
	start, size uint64,
	mode DecodeMode,
) ([]Instruction, error) {
	if image == nil {
		return nil, errors.New("nil binary image")
	}

	if err := validateMode(image.Info.Architecture, mode); err != nil {
		return nil, err
	}

	if size == 0 {
		return nil, nil
	}

	if size > binary.MaxReadSize ||
		start > math.MaxUint64-size {
		return nil, ErrInvalidRange
	}

	if mode == ModeThumb {
		region, ok := image.RegionAt(start)

		if !ok ||
			region.Permissions&binary.PermExecute == 0 ||
			start-region.Address >= region.FileSize ||
			size > region.FileSize-(start-region.Address) {
			return nil, ErrInvalidRange
		}

		if start%2 != 0 {
			return nil, ErrInvalidRange
		}

		data, err := image.ReadExecutable(start, size)
		if err != nil {
			return nil, err
		}

		// One decoder instance retains IT-block state.
		return decodeThumbRange(
			data, start, image.Info.Endianness,
		)
	}

	end := start + size
	var instructions []Instruction

	for address := start; address < end; {
		inst, err := DecodeAtMode(image, address, mode)
		if err != nil {
			return instructions, err
		}

		if uint64(inst.Size) > end-address {
			return instructions, fmt.Errorf(
				"%w at %#x: instruction crosses range boundary",
				ErrTruncatedInstruction,
				address,
			)
		}

		instructions = append(instructions, inst)
		address += uint64(inst.Size)
	}

	return instructions, nil
}

func validateMode(
	arch binary.Architecture,
	mode DecodeMode,
) error {
	switch mode {
	case ModeDefault:
		return nil

	case ModeARM, ModeThumb:
		if arch == binary.ArchARM {
			return nil
		}
	}

	return fmt.Errorf(
		"%w: mode %d for %s",
		ErrUnsupportedArchitecture,
		mode,
		arch,
	)
}
