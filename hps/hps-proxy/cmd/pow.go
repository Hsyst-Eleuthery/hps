package main

import (
	"crypto/sha256"
	"encoding/binary"
	"log"
	"strings"
	"sync/atomic"
	"time"
)

func RunBootstrapPoW(user, pass string) {
	seed := sha256.Sum256([]byte(strings.TrimSpace(user) + ":" + strings.TrimSpace(pass) + ":hps-proxy-bootstrap"))
	targetBits := 20
	start := time.Now()
	var attempts atomic.Uint64
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	payload := make([]byte, len(seed)+8)
	copy(payload, seed[:])
	for nonce := uint64(0); ; nonce++ {
		binary.BigEndian.PutUint64(payload[len(seed):], nonce)
		hash := sha256.Sum256(payload)
		attempts.Add(1)
		if leadingZeroBits(hash[:]) >= targetBits {
			elapsed := time.Since(start).Seconds()
			rate := float64(attempts.Load()) / maxFloat(elapsed, 0.001)
			log.Printf("[pow] nonce=%d attempts=%d elapsed=%0.2fs rate=%0.0f/s", nonce, attempts.Load(), elapsed, rate)
			return
		}
		select {
		case <-ticker.C:
			elapsed := time.Since(start).Seconds()
			rate := float64(attempts.Load()) / maxFloat(elapsed, 0.001)
			log.Printf("[pow] progresso attempts=%d elapsed=%0.1fs rate=%0.0f/s", attempts.Load(), elapsed, rate)
		default:
		}
	}
}

func leadingZeroBits(hash []byte) int {
	count := 0
	for _, b := range hash {
		if b == 0 {
			count += 8
			continue
		}
		for i := 7; i >= 0; i-- {
			if (b>>i)&1 == 0 {
				count++
			} else {
				return count
			}
		}
	}
	return count
}
