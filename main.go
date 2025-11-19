package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"aifia.com/dns-server/servers"
)

func main() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	fmt.Printf("Starting DNS server...\n")

	wg.Add(1)
	go servers.UdpServer(ctx, &wg)
	fmt.Printf("UDP server started\n")

	wg.Add(1)
	go servers.TcpServer(ctx, &wg)
	fmt.Printf("TCP server started\n")

	<-sigs
	fmt.Println("Shutdown signal received, shutting down servers...")

	cancel()

	wg.Wait()

	fmt.Println("All servers shut down gracefully.")
	time.Sleep(1 * time.Second)
}
