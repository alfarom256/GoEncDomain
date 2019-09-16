package AntiSandbox

import (
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

/*
typedef enum _NETSETUP_JOIN_STATUS {

    NetSetupUnknownStatus = 0,
    NetSetupUnjoined,
    NetSetupWorkgroupName,
    NetSetupDomainName

} NETSETUP_JOIN_STATUS, *PNETSETUP_JOIN_STATUS;

 */
const (
	NetSetupUnknownStatus  = iota
	NetSetupUnjoined
	NetSetupWorkgroupName
	NetSetupDomainName

	// end iota

	UNLEN = 256
)
 
var (
	opt_netapi = syscall.NewLazyDLL("netapi32.dll")
	opt_NetGetJoinInformation = opt_netapi.NewProc("NetGetJoinInformation")
)

type DWORD uint32

type SBXHost struct {
	NET_ENUM DWORD
	DomainName string
	RAM uint64
}

func GetDomainName() string {
	return ""
}

func (s *SBXHost) IsDomainJoined() bool {
	domainString := make([]uint16, UNLEN+1)
	lpDomainString := uintptr(unsafe.Pointer(&domainString))

	var nameType DWORD
	lpNameType := uintptr(unsafe.Pointer(&nameType))

	null := 0
	lpNull := uintptr(unsafe.Pointer(&null))

	_, _, err := syscall.Syscall(opt_NetGetJoinInformation.Addr(), 3, lpNull, lpDomainString, lpNameType)
	if err != syscall.ERROR_IO_PENDING {
		// there was an error
		return false
	} else {
		time.Sleep(1 * time.Second)
	}

	// opt_NetGetJoinInformation.Call(0, lpDomainString, lpNameType)
	var str_error error
	dec_str := utf16.Decode(domainString)
	tIdx := 0
	for f := range dec_str{
		if dec_str[f] == '\x00'{
			tIdx = f
			break
		}
	}
	s.DomainName = string(utf16.Decode(domainString)[0:tIdx])
	if str_error != nil {
		// there was an error decoding it
		s.DomainName = ""
		return true
	}
	s.NET_ENUM = nameType
	return true
}

func MeasureRAM() uint64 {
	return 0
}

func NewSBX() *SBXHost{
	s := SBXHost{}
	s.IsDomainJoined()
	return &s
}

