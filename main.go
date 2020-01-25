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
	checkSSP(*f)
	checkNX(*f)
}

func checkSSP(path string) {
	out, err := exec.Command("readelf", "-s", path).Output()
	if err != nil {
		log.Fatal("checkSSP: ", err)
	}
	if strings.Index(string(out), "__stack_chk_fail") != -1 {
		fmt.Println("[+] SSP: \x1b[32mon\x1b[37m")
	} else {
		fmt.Println("[+] SSP: \x1b[31moff\x1b[37m")
	}
}

func checkNX(path string) {
	out, err := exec.Command("readelf", "-W", "-l", path).Output()
	if err != nil {
		log.Fatal("checkNX: ", err)
	}
	res := strings.Split(string(out), "\n")
	for i := 0; i < len(res); i++ {
		if strings.Index(string(out), "GNU_STACK") != -1 && strings.Index(string(out), "RWE") != -1{
			fmt.Println("[+] NX: \x1b[31moff\x1b[37m")
			return
		}
	}
	fmt.Println("[+] NX: \x1b[32mon\x1b[37m")
}
