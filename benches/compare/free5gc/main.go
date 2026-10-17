// The NAS library of free5GC, as compare.sh runs it:
//
//	free5gc-nas check 5gs <fixtures>
//	free5gc-nas run <decode|encode> 5gs <messages> <passes>
//
// check prints, for each message of a file of the fixtures, its name,
// whether the library decodes it (1 or 0), and whether it encodes what it
// decoded to the same octets. run does the operation on each message of the
// file, passes times, and prints the nanoseconds, the allocations and the
// octets allocated per message, and the peak memory of the program in KiB.
// The library has 5GS alone.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/free5gc/nas"
)

type message struct {
	name   string
	octets []byte
}

func messages(file string) []message {
	f, err := os.Open(file)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	var all []message
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, octets, _ := strings.Cut(line, "\t")
		decoded, err := hex.DecodeString(strings.TrimSpace(octets))
		if err != nil {
			panic(err)
		}
		all = append(all, message{name, decoded})
	}
	return all
}

// decode reads octets as the library does, with a panic as an error.
func decode(octets []byte) (m *nas.Message, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	m = new(nas.Message)
	copied := append([]byte(nil), octets...)
	err = m.PlainNasDecode(&copied)
	return m, err
}

func encode(m *nas.Message) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return m.PlainNasEncode()
}

func peakMemory() int64 {
	var usage syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &usage)
	return usage.Maxrss
}

func main() {
	usage := "free5gc-nas (check 5gs <fixtures> | run <decode|encode> 5gs <messages> <passes>)"
	args := os.Args[1:]
	switch {
	case len(args) == 3 && args[0] == "check" && args[1] == "5gs":
		for _, m := range messages(args[2]) {
			decoded, err := decode(m.octets)
			decodes, encodes := 0, 0
			if err == nil {
				decodes = 1
				if out, err := encode(decoded); err == nil && bytes.Equal(out, m.octets) {
					encodes = 1
				}
			}
			fmt.Printf("%s\t%d\t%d\n", m.name, decodes, encodes)
		}
	case len(args) == 5 && args[0] == "run" && args[2] == "5gs":
		all := messages(args[3])
		passes, err := strconv.Atoi(args[4])
		if err != nil {
			panic(usage)
		}
		var pass func()
		switch args[1] {
		case "decode":
			pass = func() {
				for _, m := range all {
					decoded := new(nas.Message)
					octets := m.octets
					_ = decoded.PlainNasDecode(&octets)
				}
			}
		case "encode":
			decoded := make([]*nas.Message, len(all))
			for i, m := range all {
				decoded[i], _ = decode(m.octets)
			}
			pass = func() {
				for _, m := range decoded {
					_, _ = m.PlainNasEncode()
				}
			}
		default:
			panic(usage)
		}
		pass()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		start := time.Now()
		for i := 0; i < passes; i++ {
			pass()
		}
		elapsed := time.Since(start)
		runtime.ReadMemStats(&after)
		operations := float64(passes * len(all))
		fmt.Printf("%.1f %.2f %.0f %d\n",
			float64(elapsed.Nanoseconds())/operations,
			float64(after.Mallocs-before.Mallocs)/operations,
			float64(after.TotalAlloc-before.TotalAlloc)/operations,
			peakMemory())
	default:
		panic(usage)
	}
}
