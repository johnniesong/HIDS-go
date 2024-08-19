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

var VERSION = 5.60

const IS_DEBUG = false    //是否debug模式，影响一些性能检查的开关，开发时需开启，线上时需关闭
const PRINT_DEBUG = false //是否输出debug信息，开发时建议开启
const PRINT_LIVE = true   //是否输出print信息

const TEST_LSOF_P = false

const TEST_CPU_COST = false
const TEST_MEM_COST = false
const TCP_COUNT_LIMIT = 150000
const HTTP_ACCESS_COUNT_LIMIT = 200

// 可能是命令执行的服务名称，判断是否绑定端口
var rceVulList = AddMap(map[string]bool{
	"httpd": true, "tomcat": true, "apache": true, "nginx": true, "java": true,
	"node": true, "php": true, "php-fpm": true,
}, GetWebProcesses())

var rceCheckUserMap = map[string]bool{
	"httpd": true, "tomcat": true, "apache": true, "nginx": true, "java": true,
	"node": true, "www": true, "http": true, "mysql": true, "nobody": true, "php": true, "php-fpm": true,
}

var rceCheckUserBlackMap = map[string]bool{
	"root": false,
}

// 加白的进程
var PreExeCwdWhitelist = map[string]bool{
	"/usr/sbin/ldconfig": true, "/home/q/system/hulk": true, "/home/q/system/hulk/tools": true,
	"/home/ops/ops-agent": true, "/bin/usleep": true, "/usr/bin/seq": true,
}

// 漏洞检查的结果
var bugList = map[string]string{
	"POSSIBLE_RCE":  "Web应用可能存在命令执行漏洞",
	"REVERSE_SHELL": "系统被反弹SHELL攻击成功",
}

// 会设置缓存的漏洞类型
var BugCachedList = map[string]bool{
	"POSSIBLE_RCE": true, "REVERSE_SHELL": true,
}

// 两个参数，1过期时间，2检查过期时间
var prepPidCache = cache.New(1*time.Minute, 1*time.Minute)
var processCache = cache.New(2*time.Minute, 2*time.Minute)
var ssCheckCache = cache.New(10*24*time.Hour, 1*24*time.Hour)
var lsof_PBUGCache = cache.New(4*time.Hour, 50*time.Minute)

// 白名单进程
var ProcessNameWhiteList = map[string]bool{
	"logmon": true, "wonder-agent": true, "/sbin/ldconfig": true, "agent": true, "tAgent": true, "hidsgo": true, "ss": true,
}

// 这个时间与整体cache的时间
var CacheCommTime = time.Duration(60 * 5)
var CacheChainTime = time.Duration(60 * 2)
var CacheRCEReportTime = time.Duration(60 * 10) // 触发CMD漏洞告警时候的缓存时间（相同命令）

var IPSMap map[string]bool //自身ip

var IPS = GetIPs()

// message Server
var LOGServer = "http://1.1.1.1/uplog/sec_auto_message_collecter"
var AssetServer = "http://2.2.2.2/asset/isOwn"
var isCheckOwnAsset = false

var GAS = 5

func GetIPs() []string {
	var ips []string
	IPSMap = map[string]bool{}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}

	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ips = append(ips, ipnet.IP.String())
				IPSMap[ipnet.IP.String()] = true
			}

		}
	}

	return ips
}
