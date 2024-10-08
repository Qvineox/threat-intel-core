package targets

import (
	"errors"
	"net"
	"net/mail"
	"net/url"
	"strings"
	"unicode"
)

// ScanTarget is a default structure representing a single targeted network host
type ScanTarget struct {
	IPNet   *net.IPNet    `json:"IPNet"`
	Domain  *string       `json:"Domain"`
	Mailbox *mail.Address `json:"Mailbox"`
	URL     *url.URL      `json:"URL"`
}

// AutoTypeScanTarget is used to automatically define target host type.
// Can and should be chained to NewScanTarget.
func AutoTypeScanTarget(host string, allowForking bool) (ScanTargetType, string, bool) {
	if len(host) == 0 {
		return SCAN_TARGET_TYPE_UNKNOWN, host, false
	}

	var type_ ScanTargetType = SCAN_TARGET_TYPE_UNKNOWN

	if strings.Contains(host, "//") { // url
		type_ = SCAN_TARGET_TYPE_URL
	} else if strings.Contains(host, "@") {
		type_ = SCAN_TARGET_TYPE_MAILBOX
	} else if strings.Contains(host, "/") {
		type_ = SCAN_TARGET_TYPE_CIDR
	} else {
		type_ = SCAN_TARGET_TYPE_PQDN
	}

	return type_, host, allowForking
}

func NewScanTarget(targetType ScanTargetType, host string, allowForking bool) (target *ScanTarget, err error) {
	target = &ScanTarget{}

	if len(host) == 0 {
		return nil, errors.New("host is empty")
	} else if targetType == SCAN_TARGET_TYPE_UNKNOWN {
		return nil, errors.New("cant produce target with unknown type")
	}

	switch targetType {
	case SCAN_TARGET_TYPE_CIDR:
		_, target.IPNet, _ = net.ParseCIDR(host)
		if target.IPNet == nil {
			return nil, errors.New("invalid cidr")
		}

	case SCAN_TARGET_TYPE_PQDN:
		// ref: https://stackoverflow.com/questions/11748908/could-a-dns-name-look-like-an-ip-address
		domainParts_ := strings.Split(host, ".")

		for _, p := range domainParts_ {
			if p == "" {
				return nil, errors.New("invalid domain name")
			}
		}

		if unicode.IsDigit(rune(domainParts_[len(domainParts_)-1][0])) {
			return nil, errors.New("top level domain cant start with a digit")
		}

		target.Domain = &host

	case SCAN_TARGET_TYPE_MAILBOX:
		target.Mailbox, err = mail.ParseAddress(host)
		if err != nil {
			return nil, errors.New("invalid mailbox: " + err.Error())
		}

		if !allowForking {
			break
		}

		mailboxParts := strings.Split(target.Mailbox.String(), "@")
		target.Domain = &mailboxParts[len(mailboxParts)-1]

	case SCAN_TARGET_TYPE_URL:
		target.URL, err = url.Parse(host)
		if err != nil {
			return nil, errors.New("invalid url: " + err.Error())
		}

		if !allowForking {
			break
		}

		hostname := target.URL.Hostname()

		ip := net.ParseIP(hostname)
		if ip != nil {
			target.IPNet = &net.IPNet{
				IP:   ip,
				Mask: net.IPv4Mask(255, 255, 255, 255),
			}
		} else {
			target.Domain = &hostname
		}

	default:
		return nil, errors.New("invalid scan target type")
	}

	return target, nil
}

// ScanTargetType defines target host type
type ScanTargetType uint8

const (
	SCAN_TARGET_TYPE_CIDR ScanTargetType = iota
	SCAN_TARGET_TYPE_PQDN
	SCAN_TARGET_TYPE_URL
	SCAN_TARGET_TYPE_MAILBOX
	SCAN_TARGET_TYPE_UNKNOWN = 99
)
