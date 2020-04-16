package main

import (
    "./gopeer"
)

type Node struct {
    Address string
    Certificate string
    Public string
}

const (
	TITLE_TESTCONN   = "[TITLE-TESTCONN]"
	TITLE_EMAIL      = "[TITLE-EMAIL]"
	TITLE_ARCHIVE    = "[TITLE-ARCHIVE]"
	TITLE_LOCALCHAT  = "[TITLE-LOCALCHAT]"
	TITLE_GLOBALCHAT = "[TITLE-GLOBALCHAT]"
)

var (
    ObjectDDOS     = new(DDOS)
    FILENAME       = "private.key"
    KEY_SIZE       = (3 << 10) // 3072 bit
    MESSAGE_SIZE   = (1 << 10) // 1KiB
    PRIVATE_CLIENT = tryGeneratePrivate(FILENAME, KEY_SIZE)
    PUBLIC_RECV    = gopeer.ParsePublic(PEM_PUBLIC_RECV)
)

var (
    LIST_OF_NODES = []Node{
        Node{
            Address: "localhost:8080",
            Certificate: `-----BEGIN CERTIFICATE-----
MIIE+jCCA2KgAwIBAgIIFZsjHl412QkwDQYJKoZIhvcNAQELBQAwgZoxFDASBgNV
BAYTC0hJRERFTi1MQUtFMRQwEgYDVQQIEwtISURERU4tTEFLRTEUMBIGA1UEBxML
SElEREVOLUxBS0UxFDASBgNVBAkTC0hJRERFTi1MQUtFMRQwEgYDVQQREwtISURE
RU4tTEFLRTEUMBIGA1UEChMLSElEREVOLUxBS0UxFDASBgNVBAMTC0hJRERFTi1M
QUtFMB4XDTIwMDQxNjE2MTcwNVoXDTMwMDQxNjE2MTcwNVowgZoxFDASBgNVBAYT
C0hJRERFTi1MQUtFMRQwEgYDVQQIEwtISURERU4tTEFLRTEUMBIGA1UEBxMLSElE
REVOLUxBS0UxFDASBgNVBAkTC0hJRERFTi1MQUtFMRQwEgYDVQQREwtISURERU4t
TEFLRTEUMBIGA1UEChMLSElEREVOLUxBS0UxFDASBgNVBAMTC0hJRERFTi1MQUtF
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAqyGt7ZO5kAzwg98ZQrh3
zv0AZBuQ2cy/ahTsrj2rr1wOhFYJi+XkALqRTpZyKOeoSjw2AsarHgGG3hk/ow8C
lJkGtvnqRscrUOEJIovCNJ1r973y4QvAFaaP3dFqotTx8qGcM/2P3ZnstAGac0AB
puxLrK6OnOH9nQvJb/0bjienTWgHaScZPuq4Hi7CJ+OTFCil1/OXbLupZwBFqrt6
XZjqLKokHkE0ASdm0mC+3VvSC94JKKrQvEdGiPjuYqYnxZzWx7o1tTeuEx5GBHXb
azn4gBIkdCU4xD7w4+nUvl50pJZbY4nZxSUbg06qahCaUXa/UALd+jVqBAAf/j2x
jw+y2O+xziUFQdLFw0zQLqorWgdXS0LAlTNeUWKImXmxDs2aQ8kooDAB3BdE+T87
gGYwA/oueu6RKO1kbaDMmzQiE9W5imq+Oz7p3GK8bGS1q5+KeGTHeJxQFEEZBjXP
DuYi3m0JS9WE6xzF1FConZMInolawiWx1PcjgLy0RVgZAgMBAAGjQjBAMA4GA1Ud
DwEB/wQEAwIChDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDwYDVR0T
AQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAYEARdNuphxAD1K1A0bPjDXDLHq3
DDpqboWaiZZD6aECGJaadkakoIpLsIdo/gKMP9jL+5+W2s5O0qt6ZfTsjy/UvMJH
pLn+XKJTZMBT585DBs1eoYdyo4OUtfjkZOJdh/wucRc+gxK21uTw/7rWu/I1zcBE
cKULD1HlqGpcKvHrhaczPRJJpRFSgwzQcYuJvSc108uLfbz4VomKbkiDoBUQsCEq
hPOWDYw4F3Y6Ta2VBcc6xcEBlz4wY6tXTg2v/Cc2RSD/2Y3gpRXaHzPZLicUXung
4JsKcv7L80skOrkzquZ7sWZ/zuToa5CzWI4vBABoTCUKztRfTrg82QdoeNYkwVSH
BcC/HS6L4tirAm0Mryf59FUhvh1qgqZbVhJCdF48kCTjOczoeSQbGfiB8yZyrHK+
mVJSr6ZVKdFkz0bxKtp0ochOJV8q0PRcWWJ3z9YOXRIQP49YsPMG5Nm2L+5ypvyY
j9W+aIks5I8YZRylPMnWBHPyXIR6JhbZ/u1GCRzh
-----END CERTIFICATE-----
`,
            Public: `-----BEGIN RSA PUBLIC KEY-----
MIIBigKCAYEAwRMUCP+QJmUghFTgPtrA6mLcBjN8DgEZwtsUen0vl5FUARPnLF6P
dXiu+rihzzG5T3o/z+5OqHAC9W1lsCuhMT23I4HfzCovYJWyLqyr6BRh/rwHHOPn
B42eb9VnTAAnRmnTbUAzrYxwqVFRw2UFOuYCIIJ4bpHy3xJKTI4G5EERF6gux5mv
Ld4S66PxqIngvNpKM8I6zd2JyzMj506/u8P2LF/ozSYHut8yrGCCmYUDolfj9+GH
EZbmvn7DHk8qTbOt5QVpBQ5enzdK+awlNcYueZi8xSbKguq0LjTme9N9WNfL46gr
yLgtOoWYNQP/w5DfCnUFpdp+mDeCaTunUNZhPsPmLl0zEdtwX4Mt9FP8iup60mZL
G6SbkTIVsIf9xO1uNriEh45mh+eXTg+tX1xGNbPTXgJQx8e4P3AsG5gu73pHoxkG
211pukYKgrIwbc+l5/qhrIjayzCCTMQb2hmlp+HhQBn0TBKqkPLvnpfnrNA+tsBZ
PRTIt7tl7QApAgMBAAE=
-----END RSA PUBLIC KEY-----
`,
        },
    }
)

const PEM_PUBLIC_RECV = `-----BEGIN RSA PUBLIC KEY-----
MIIBigKCAYEAwF6/bTugCLDH35HLQOIhVmniZ9mXsxtTM2EZn3+lXJV5O/Bv3pVj
7Eqc+n1tgbnb3zS1DBA2i3ahc7jSMhmhWsyHxHSn1ZC81S3jFuAd2XKyJfs0HANA
mXjt/RRic6w9OasOWzuYj5YjPTsAviX2dnW/NoqQV4Tx71ol/TzquCbvAyeqDqrr
wV5FKsiOTpsFytEamRIM/GldgZnrUjZ0+MYvVkVVi2BXtHGbjVAN6o9RVtTtq+Zn
d8oJ+cF50Pno9Y+cqThgmkJYeT3c0iMZ5XmRRM63jhFSkNs6Tn99cIc+nNTORKvJ
ZXvy2Mfqo2iWHwX9qQWXkBlHnsN6xc1du8tHmCBBOVCaziL8hjAMfQUdRSCt6Pnw
6C9bxYVy0Gd4THtj+LV+vX2RRfVZIVI6OIJPhXLUWzrn5OZw4jBbOjeqOMIMEd/0
UsECg8KkgW+w1q/CDP5W60T4tHn+rUmQy5LguOTAE4RFeeuE3h0plPSk13IxgLuk
OCssWlOX1s4bAgMBAAE=
-----END RSA PUBLIC KEY-----
`