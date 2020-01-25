package main

import(
	"flag"
	"fmt"
	"log"
	"strings"
	"os/exec"
)

func main() {
	f := flag.String("f", "", "file")
	flag.Parse()
	if *f == "" {
		fmt.Println("\"-h\" for help")
	} else {
		checkSec(*f)
	}
}

func checkSec(path string) {
	checkSSP(path)
	checkNX(path)
	checkPIE(path)
	checkRELRO(path)
}

func checkSSP(path string) {
	out, err := exec.Command("readelf", "-s", path).Output()
	if err != nil {
		log.Fatal("checkSSP: ", err)
	}
	if strings.Index(string(out), "__stack_chk_fail") != -1 {
		fmt.Println("[+] SSP: \x1b[32menabled\x1b[37m")
	} else {
		fmt.Println("[+] SSP: \x1b[31mdisabled\x1b[37m")
	}
}

func checkNX(path string) {
	out, err := exec.Command("readelf", "-W", "-l", path).Output()
	if err != nil {
		log.Fatal("checkNX: ", err)
	}
	res := strings.Split(string(out), "\n")
	for i := 0; i < len(res); i++ {
		if strings.Index(string(out), "GNU_STACK") != -1 && strings.Index(string(out), "RWE") != -1 {
			fmt.Println("[+] NX: \x1b[31mdisabled\x1b[37m")
			return
		}
	}
	fmt.Println("[+] NX: \x1b[32menabled\x1b[37m")
}

func checkPIE(path string) {
	out, err := exec.Command("readelf", "-h", path).Output()
	if err != nil {
		log.Fatal("checkPIE: ", err)
	}
	res := strings.Split(string(out), "\n")
	for i := 0; i < len(res); i++ {
		if strings.Index(string(out), "Type") != -1 && strings.Index(string(out), "Shared object file") != -1 {
			fmt.Println("[+] PIE: \x1b[32menabled\x1b[37m")
			return
		}
	}
	fmt.Println("[+] PIE: \x1b[31mdisabled\x1b[37m")
}

func checkRELRO(path string) {
	out, err := exec.Command("readelf", "-l", path).Output()
	if err != nil {
		log.Fatal("checkRELRO: ", err)
	}
	if strings.Index(string(out), "GNU_RELRO") != -1 {
		out, err := exec.Command("readelf", "-d", path).Output()
		if err != nil {
			log.Fatal("checkRELRO: ", err)
		}
		if (strings.Index(string(out), "BIND_NOW")) != -1 {
			fmt.Println("[+] RELRO: \x1b[32menabled\x1b[37m")
		} else {
			fmt.Println("[+] RELRO: \x1b[33mpartial enabled\x1b[37m")
		}
	} else {
		fmt.Println("[+] RELRO: \x1b[31mdisabled\x1b[37m")
	}
}
