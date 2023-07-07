package maa

import (
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

type simTPM struct {
	*simulator.Simulator
}

func newSimTPM() (simTPM, error) {
	sim, err := simulator.Get()
	if err != nil {
		return simTPM{}, err
	}
	return simTPM{sim}, nil
}

func (simTPM) EventLog() ([]byte, error) {
	return nil, nil
}

func (s simTPM) nvWrite(index tpmutil.Handle, data []byte) error {
	if err := tpm2.NVDefineSpace(s, tpm2.HandleOwner, index, "", "", nil, tpm2.AttrOwnerWrite|tpm2.AttrOwnerRead, uint16(len(data))); err != nil {
		return err
	}
	for i := 0; i < len(data); i += 1024 {
		high := i + 1024
		if len(data) < high {
			high = len(data)
		}
		if err := tpm2.NVWrite(s, tpm2.HandleOwner, index, "", data[i:high], uint16(i)); err != nil {
			return err
		}
	}
	return nil
}
