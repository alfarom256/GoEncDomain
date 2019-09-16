package OptDNS

import (
	"C"
	"errors"
	"net"
	"strings"
)

type TXT_ENTRY struct {
	host string
	val string
	record string
}

//export LookupTXT
func LookupTXT(host string) ([]TXT_ENTRY, error){

	retVal := make([]TXT_ENTRY, 0)

	res, err := net.LookupTXT(host)
	if err != nil {
		// fail quietly
		return nil, errors.New("Lookup failed for host " + host)
	}

	if len(res) == 0 {
		return nil, errors.New("No TXT records for host " + host)
	}

	for _, v := range res{
		var temp TXT_ENTRY
		spl := strings.Split(v, "=")
		if len(spl) < 2 {
			continue
		}
		temp.val, temp.record = spl[0], spl[1]
		//fmt.Printf("%s %s %s\n", host, temp.val, temp.record)
		retVal = append(retVal, temp)
	}
	return retVal, nil
}
