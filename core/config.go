package core

import (
	_ "bufio"
	"github.com/patrickmn/go-cache"
	_ "io"
	"net"
	_ "os"
	_ "strings"
	"time"
)

var VERSION = 2.4

const IS_DEBUG = true
const PRINT_DEBUG = true
const TEST_CPU_COST = false

// 可能是命令执行的服务名称，判断是否绑定端口
var rceVulList = AddMap(map[string]bool{
	"httpd": true, "tomcat": true, "apache": true, "nginx": true, "java": true,
	"node": true, "php": true,
}, GetWebProcesses())

// 加白
var PreExeCwdWhitelist = map[string]bool{
	"/usr/sbin/ldconfig": true, "/home/q/system/hulk": true, "/home/q/system/hulk/tools": true,
	"/home/ops/ops-agent": true, "/bin/usleep": true, "/usr/bin/seq": true,
}

// 漏洞检查的结果
var bugList = map[string]string{
	"POSSIBLE_RCE":   "Web应用可能存在命令执行漏洞",
	"REVERSE_SHELL":  "系统被反弹SHELL攻击成功",
	"SUID_PRIVILEGE": "可能存在suid提权攻击",
	"SUID_VERIFIED":  "检测到SUID提权成功",
	"NEW_BASH":       "检查到新的BASH产生",
	"SSH_BRUTE":      "有攻击者正在爆破ssh",
}

// 会设置缓存的漏洞类型
var BugCachedList = map[string]bool{
	"POSSIBLE_RCE": true, "REVERSE_SHELL": true,
}

// 两个参数，1过期时间，2强制过期时间
var prepPidCache = cache.New(1*time.Minute, 1*time.Minute)
var processCache = cache.New(2*time.Minute, 2*time.Minute)
var ssCheckCache = cache.New(60*time.Minute, 5*time.Minute)

var ProcessNameWhiteList = map[string]bool{
	"logmon": true, "wonder-agent": true, "/sbin/ldconfig": true, "agent": true, "tAgent": true, "hids-go": true, "ss": true,
}

// 这个时间与整体cache的时间
var CacheCommTime = time.Duration(60 * 5)
var CacheChainTime = time.Duration(60 * 2)
var CacheRCEReportTime = time.Duration(60 * 10) // 触发CMD漏洞告警时候的缓存时间（相同命令）

var IPS = GetIPs()

// message Server
var LOGServer = "http://1.1.1.1/uplog/sec_auto_message_collecter"
var isCheckOwnAsset = false //不检查是否属于自己的资产，会默认返回false结果
var AssetServer = "http://1.1.1.1/isown"

var GAS = 20

func GetIPs() []string {
	var ips []string

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}

	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ips = append(ips, ipnet.IP.String())
			}

		}
	}

	return ips
}
