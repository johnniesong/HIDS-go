package core

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

func load_data(pid string) ([]string, error) {

	var str []string

	tcpFile := "/proc/" + pid + "/net/tcp"

	fin, err := os.Open(tcpFile)

	defer fin.Close()

	if err != nil {
		fmt.Println(tcpFile, err)
		return str, err
	}

	r := bufio.NewReader(fin)

	for {
		buf, err := r.ReadString('\n')
		if err == io.EOF {
			break
		}
		str = append(str, buf)
	}

	if len(str) > 0 {
		return str[1:], nil
	}
	return str, nil
}

func hex2dec(hexstr string) string {
	i, _ := strconv.ParseInt(hexstr, 16, 0)
	return strconv.FormatInt(i, 10)
}

func hex_to_ip(hexstr string) (string, string) {
	var ip string
	if len(hexstr) != 8 {
		err := "parse error"
		return ip, err
	}

	i1, _ := strconv.ParseInt(hexstr[6:8], 16, 0)
	i2, _ := strconv.ParseInt(hexstr[4:6], 16, 0)
	i3, _ := strconv.ParseInt(hexstr[2:4], 16, 0)
	i4, _ := strconv.ParseInt(hexstr[0:2], 16, 0)
	ip = fmt.Sprintf("%d.%d.%d.%d", i1, i2, i3, i4)

	return ip, ""
}

func convert_to_ip_port(str string) (string, string) {
	l := strings.Split(str, ":")
	if len(l) != 2 {
		return str, ""
	}

	ip, err := hex_to_ip(l[0])
	if err != "" {
		return str, ""
	}

	return ip, hex2dec(l[1])
}

func remove_all_space(l []string) []string {
	var ll []string
	for _, v := range l {
		if v != "" {
			ll = append(ll, v)
		}
	}

	return ll
}

var STATE = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
}

func SSByPid(pid string) {
	fmt.Println("ss demo use golang")

	lines, err := load_data(pid)
	if err != nil {
		fmt.Println("read pid failed")
	} else {
		fmt.Printf("State\tLocal Address:Port\t\t\tPeer Address:Port\n")
		for _, line := range lines {
			//fmt.Println(line)
			l := remove_all_space(strings.Split(line, " "))
			l_host, l_port := convert_to_ip_port(l[1])
			r_host, r_port := convert_to_ip_port(l[2])
			stats := STATE[l[3]]
			fmt.Printf("%s\t\t%s:%s\t\t\t%s:%s\n", stats, l_host, l_port, r_host, r_port)
		}
	}
}

func checkRShellBySSByPid(pid string) {
	lines, err := load_data(pid)
	if err != nil {
		fmt.Println("read pid failed")
	} else {
		for _, line := range lines {
			l := remove_all_space(strings.Split(line, " "))
			if l[3] == "01" {
				l_host, l_port := convert_to_ip_port(l[1])
				r_host, r_port := convert_to_ip_port(l[2])
				stats := STATE[l[3]]
				fmt.Printf("%s\t\t%s:%s\t\t\t%s:%s\n", stats, l_host, l_port, r_host, r_port)

			}

		}
	}
}
