package core

import (
	"fmt"
	"github.com/json-iterator/go"
	pnet "github.com/shirou/gopsutil/net"
	"github.com/shirou/gopsutil/process"
	"github.com/texttheater/golang-levenshtein/levenshtein"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var UidMap map[string]string
var FullUidMap map[string]string

func debug_print(log ...interface{}) {
	if PRINT_DEBUG == true {
		fmt.Println(time.Now(), log)
	}
}

func live_print(log ...interface{}) {
	if PRINT_LIVE == true {
		fmt.Println(time.Now(), log)
	}
}

var privateIPBlocks []*net.IPNet
var Hostname, _ = os.Hostname()

var RegA = regexp.MustCompile("[0-9a-f]{6,12}\\b")
var RegB = regexp.MustCompile("[1-9]")
var RegC = regexp.MustCompile("[b-z]")
var Regid = regexp.MustCompile("[\\s;|&]id[\\s;|&]")
var RegIP = regexp.MustCompile("\\b(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\b")
var RegPort = regexp.MustCompile("\\b\\d{2,5}\\b")

var RceCheckMap map[string]int
var CleanRceCheckMap = false
var ListenPortMap map[string]bool

var AbnormalCmdline map[string]bool
var CheckedProcessMap map[string]bool

var HasCheckedLsofInPeriod = false
var httpAccessCount = 0

const TEXT = 0
const EXEC = 1
const SO = 2
const OTHER = -1

// 初始化内网地址，为了后续判断
func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
	} {
		_, block, _ := net.ParseCIDR(cidr)
		privateIPBlocks = append(privateIPBlocks, block)
	}

}

func isPrivateIP(ip net.IP) bool {
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// 调用资产库接口
func CheckIsOwnAsset(ip string, isIsolate string) bool {
	CheckIsOwnAssetLock.Lock()
	defer CheckIsOwnAssetLock.Unlock()
	if isOwn, isIn := IsOwnAssetAndNotIsolateMap[ip]; isIn == false { //如果不在cache里，就请求检查，并更新cache
		if resp, _ := checkIsOwnAsset(ip, isIsolate); strings.Contains(resp, "false") { //不是公司资产，就是有问题的连接
			IsOwnAssetAndNotIsolateMap[ip] = false
			return false
		} else {
			IsOwnAssetAndNotIsolateMap[ip] = true
			return true
		}
	} else if isOwn == true {
		return true
	} else {
		return false
	}
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

var EntryMap_tmp map[string]int

var SumLsofTimeCostLock sync.Mutex
var SumLsofTimeCost = 0.0

var LsofCheckOpenLock sync.RWMutex
var IsLsofCheckOpen = true
var IsLsofCheckPeriodOpen = true

var CheckIsOwnAssetLock sync.Mutex

// 以下四个结构体是为了字典读写锁,异步读写需要锁
type RWCache struct {
	Lock *sync.RWMutex
	Data map[string]bool
}

func (cache RWCache) Get(key string) bool {
	cache.Lock.RLock()
	defer cache.Lock.RUnlock()
	return cache.Data[key]
}

func (cache RWCache) Set(key string, value bool) {
	cache.Lock.Lock()
	defer cache.Lock.Unlock()
	cache.Data[key] = value
}

func (cache RWCache) Print() {
	cache.Lock.RLock()
	defer cache.Lock.RUnlock()
	for key := range cache.Data {
		debug_print("EntryWhiteListMap:", key)
	}
}

var EntryMapMUTEX sync.Mutex

var EntryWhiteListCache RWCache

var EntryMustCheckList = [...]string{"/bin/bash", "/bin/perl", "/bin/ncat", "python", "php-fpm"}

func InsertToEntryMap(name string) {
	EntryMapMUTEX.Lock()
	defer EntryMapMUTEX.Unlock()
	if _, ok := EntryMap_tmp[name]; ok == false {
		EntryMap_tmp[name] = 0
	} else {
		count := EntryMap_tmp[name]
		EntryMap_tmp[name] = count + 1
	}
}

// 每60分钟计算一次，频率大于0.8每秒的加入
func GenEntryMap() {
	var cycle int64
	var limit float64
	if IS_DEBUG {
		cycle = 30 * 60 //60*60
		limit = 0.8     //0.5
	} else {
		cycle = 30 * 60 //60*60
		limit = 0.8     //0.5
	}

	for {
		time.Sleep(time.Duration(cycle) * time.Second)
		EntryMapMUTEX.Lock()
		for key := range EntryMap_tmp {
			flag := false
			count, _ := EntryMap_tmp[key]
			if float64(count)/float64(cycle) > limit {
				EntryWhiteListCache.Set(key, true)
				for _, item := range EntryMustCheckList {
					if strings.Contains(key, item) { //包含，说明一定要检查
						flag = true
						break
					}
				}
				if flag {
					EntryWhiteListCache.Set(key, false)
					debug_print("delete EntryWhiteListMap:", key)
				}
			}
			delete(EntryMap_tmp, key) //清空，下一小时重新计算
		}
		EntryMapMUTEX.Unlock()
		EntryWhiteListCache.Print()
	}
}

func readProcMaps(pid int32) (string, error) {
	buf, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		//fmt.Fprintf(os.Stderr, "File Read Error: %s\n", err)
		return "", err //read错误
	}

	return string(buf[:400]), nil
}

// 获得进程调用链信息
func getProcessChain(pid int32) (string, error) {
	if cacheResult, found := prepPidCache.Get(fmt.Sprintf("%s_%d", "chain", pid)); found {
		return cacheResult.(string), nil
	}

	if pid != 1 && pid != 2 {
		name, pPid, cmd, _, _, err := getProcessInfo(pid)

		if err != nil {
			return "", err //read错误，进程退出
		}

		NextChainString, _ := getProcessChain(pPid)
		chainString := fmt.Sprintf("%d %s(%s) => %s", pid, name, cmd, NextChainString)

		return chainString, nil
	}

	processCache.Set(fmt.Sprintf("%s_%s", "chain", pid), fmt.Sprintf("%d", pid), CacheChainTime*time.Second)

	return fmt.Sprintf("%d", pid), nil
}

// 获取进程信息，从缓存中读取并且将结果存储到缓存中
// output: 进程名，进程ppid
func getProcessInfo(pid int32) (string, int32, string, string, string, error) {
	pro, err := process.NewProcess(pid)
	if err != nil {
		return "", 0, "", "", "", err
	}

	name, _ := pro.Name()
	ppid, _ := pro.Ppid()
	pcmd, _ := pro.Cmdline()
	pcwd, _ := pro.Cwd()
	pExe, _ := pro.Exe()
	return name, ppid, strings.Replace(pcmd, "\000", " ", -1), pcwd, pExe, nil
}

func getProcessInfoALL(pid int32) (string, int32, string, string, string, []pnet.ConnectionStat, []int32, error) {
	pro, err := process.NewProcess(pid)
	if err != nil {
		return "", 0, "", "", "", nil, nil, err
	}

	name, _ := pro.Name()
	ppid, _ := pro.Ppid()
	pcmd, _ := pro.Cmdline()
	pcwd, _ := pro.Cwd()
	pExe, _ := pro.Exe()
	conn, _ := pro.Connections()
	uids, _ := pro.Uids()
	return name, ppid, strings.Replace(pcmd, "\000", " ", -1), pcwd, pExe, conn, uids, nil
}

func getProcessConnectionsInfoANDUid(pid int32) ([]pnet.ConnectionStat, []int32, error) {
	pro, err := process.NewProcess(pid)
	if err != nil {
		return nil, nil, err
	}

	conn, _ := pro.Connections()
	uids, _ := pro.Uids()
	return conn, uids, err
}

func readFile(filePath string) (string, error) {
	buf, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "File %s  Read Error: %s\n", filePath, err)
		return "", err
	}

	return string(buf), nil
}

// 正则
func regFind(regStr string, text string) ([]string, error) {
	var result []string

	if len(text) == 0 {
		return result, nil
	}

	reg, err := regexp.Compile(regStr)
	if err != nil {
		result = append(result, "")
		return result, err
	}

	result = reg.FindStringSubmatch(text)

	if len(result) > 1 {
		result = result[1:]
	}

	return result, nil
}

// 消息回传
func MessageToServer(logType string, bugDetail interface{}, auditLog interface{}) (string, error) {

	form := url.Values{}

	t, v := reflect.TypeOf(bugDetail), reflect.ValueOf(bugDetail)
	for i := 0; i < t.NumField(); i++ {
		form.Add(t.Field(i).Name, v.Field(i).String())
	}

	t, v = reflect.TypeOf(auditLog), reflect.ValueOf(auditLog)
	for i := 0; i < t.NumField(); i++ {
		form.Add(t.Field(i).Name, v.Field(i).String())
	}

	form.Add("log_type", logType)
	form.Add("ES_TYPE", "hidsgo_bug")
	fmt.Println("Found BUG: ", logType, bugDetail)

	return SendRequest(form)
}

// 这个iscached 只是告警部分 是
func isCached(exe string, A1 string, A2 string, bugType string) bool {
	// 判断当前的告警是否重复，判别项：exe 参数名 漏洞类型
	// 但有部分参数是随机的编码，比如：[whoami] [15f1e28] [15f2c08]，需要用正则表达式去除
	// 如果当前告警未缓存过，会返回false，并且设置10min的缓存
	// 如果告警缓存过，返回true
	if result, _ := regexp.MatchString("^[0-9a-f]{6,20}$", A1); result {
		A1 = "A1A1"
	}
	if result, _ := regexp.MatchString("^[0-9a-f]{6,20}$", A2); result {
		A2 = "A2A2"
	}

	cacheString := fmt.Sprintf("out_%s%s%s%s", exe, A1, A2, bugType)

	if _, found := processCache.Get(cacheString); found {
		return true
	} else {
		processCache.Set(cacheString, "true", CacheRCEReportTime*time.Second)
		return false
	}
}

func SendRequest(form url.Values) (string, error) {
	ipsJson, _ := jsoniter.Marshal(IPS)
	form.Add("origin_ips", string(ipsJson))
	form.Add("hostname", Hostname)

	fmt.Println("Messages out: ", form["Exe"], form["A0"], form["A1"], form["A2"], form["Pid"], form["PPid"])

	if _, ok := form["Type"]; ok {
		if _, ok := form["Exe"]; ok {
			if BugCachedList[form["Type"][0]] && isCached(form["Exe"][0], form["A1"][0], form["A2"][0], form["Type"][0]) {
				fmt.Println("cache found!", strings.NewReader(form.Encode()))
				return "", nil
			}
		}
	}

	resp, err := http.Post(LOGServer, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		fmt.Println("Send Request Error: ", err)
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

type AssetInfo struct {
	T          string `json:"t"`
	Is_isolate string `json:"is_isolate"`
	Target     string `json:"target"`
}

// isolateIsOK 0 是隔离网机器就不行，1 是隔离网段才行
func checkIsOwnAsset(target string, isolateIsOK string) (string, error) {
	if isCheckOwnAsset == false {
		return "false", nil
	}

	data := AssetInfo{T: strconv.Itoa(int(time.Now().Unix())), Is_isolate: isolateIsOK, Target: target}
	jsonData, err := jsoniter.Marshal(data)
	debug_print("checkIsOwnAssetAndNotIsolate", string(jsonData))
	client := http.Client{}
	req, err := http.NewRequest("POST", AssetServer, strings.NewReader(string(jsonData)))
	req.SetBasicAuth("skp", "0fd7ea1c9b2ea5fe903dbfb89f759aab")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Send Request Error: ", err)
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	debug_print("checkIsOwnAssetAndNotIsolate", string(body))
	return string(body), nil
}

func CleanLog() {
	for {
		time.Sleep(10 * time.Minute)
		if IS_DEBUG == true {
			result, _ := execComm("du -sh hidsgo.log")
			if strings.Contains(result, "G") {
				execComm("echo ''>/home/ops/hidsgo/hidsgo.log")
				execComm("echo ''>hidsgo.log")
				execComm("echo ''>/tmp/hidsgo.log")
				fmt.Println("Clean log")
			}
		} else {
			result, _ := execComm("du -sh hidsgo.log")
			if strings.Contains(result, "G") {
				execComm("echo ''>/home/ops/hidsgo/hidsgo.log")
				execComm("echo ''>hidsgo.log")
				execComm("echo ''>/tmp/hidsgo.log")
				fmt.Println("Clean log")
			}
		}
	}
}

func AliveCheck() {

	for {
		// 获取web程序
		cmdString := "ss -n -t -l -p src *:https or src *:http | grep \"users:((\" "
		cmdRes, err := execComm(cmdString)
		if err != nil {
			fmt.Println(err)
		}

		// 为了es查询方便，入库一定要是int数字，所以先转化一下
		form := url.Values{}
		form.Add("CPU_COST", "0")
		form.Add("ES_TYPE", "hidsgo_dot")
		form.Add("version", fmt.Sprintf("%.3f", VERSION))
		form.Add("web_service", string(cmdRes))
		SendRequest(form)
		randomTime := rand.Intn(7200) + 60*60*6 //2+6
		time.Sleep(time.Duration(randomTime) * time.Second)
	}
}

func CPUCheck() {
	HP := 100
	for {
		randomTime := rand.Intn(1200) + 600
		time.Sleep(time.Duration(randomTime) * time.Second)
		// 获取cpu占用率
		cpuPercent := "top -b -n 10 | grep hidsgo | awk -F ' ' '{print $9}'"
		percent, err := execComm(cpuPercent)
		if err != nil {
			fmt.Println(err)
		}
		cpuSum := 0.0
		percent_list := strings.Split(strings.TrimSpace(percent), "\n")
		for _, item := range percent_list {
			cpuTmp, _ := strconv.ParseFloat(strings.TrimSpace(item), 3)
			cpuSum += cpuTmp
		}
		if cpuMin := cpuSum / 10.0; cpuMin > 10.0 { //warning
			form := url.Values{}
			form.Add("CPU_COST", strconv.Itoa(int(cpuMin)))
			form.Add("ES_TYPE", "hidsgo_dot")
			form.Add("version", fmt.Sprintf("%.3f", VERSION))
			SendRequest(form)

			if cpuMin > 80.0 {
				HP -= 40
			} else if cpuMin > 40.0 {
				HP -= 20
			} else if HP < 100 {
				HP += 10
			}

			if HP <= 0 {
				form := url.Values{}
				form.Add("ES_TYPE", "hidsgo_kill")
				form.Add("version", fmt.Sprintf("%.3f", VERSION))
				SendRequest(form)
				fmt.Println("Kill hidsgo!!!")
				execComm("kill -9 " + strconv.Itoa(os.Getpid()))
			}
			live_print("Keep hidsgo!!!, cpuMin:", cpuMin, "HP:", HP)
		}

	}
}

func regFindAll(regStr string, text string) ([]string, error) {
	var result []string

	if len(text) == 0 {
		return result, nil
	}

	reg, err := regexp.Compile(regStr)
	if err != nil {
		result = append(result, "")
		return result, err
	}

	for _, value := range reg.FindAllStringSubmatch(text, -1) {
		result = append(result, value[1])
	}

	return result, nil
}

func GetWebProcesses() map[string]bool {
	// 获取占用了80相关端口的进程名，防止编译型web的漏报，比如beego
	// 返回示例：map[python:true hello:true]

	var result = map[string]bool{}

	cmdRes, err := execComm("ss -n -t -l -p src *:https or src *:http | grep \"users:((\" ")

	if err != nil {
		return result
	}

	regRes, err := regFindAll("users:\\(\\(\"(.*?)\"", string(cmdRes))

	if err != nil {
		return result
	}

	for _, value := range regRes {
		result[value] = true
	}
	for item := range result {
		fmt.Println("GetWebProcesses", item, result[item])
	}

	return result
}

func AddMap(m1 map[string]bool, m2 map[string]bool) map[string]bool {
	for k, v := range m2 {
		m1[k] = v
	}

	return m1
}

// 执行命令
func execComm(cmd string) (string, error) {
	if cacheResult, found := prepPidCache.Get(fmt.Sprintf("%s_%s", "exec", cmd)); found {
		return cacheResult.(string), nil
	}

	result := ""

	cmdHandler := exec.Command("/bin/bash", "-c", cmd)
	cmdRes, err := cmdHandler.Output()

	if err != nil {
		fmt.Println("execComm error", cmd)
		return result, err
	}

	processCache.Set(fmt.Sprintf("%s_%s", "exec", cmd), string(cmdRes), CacheCommTime*time.Second)
	return string(cmdRes), nil
}

func execCommAndLimitCPU(cmd string, limitCmd string) (string, error) {
	if cacheResult, found := prepPidCache.Get(fmt.Sprintf("%s_%s", "exec", cmd)); found {
		return cacheResult.(string), nil
	}

	result := ""

	cmdHandler := exec.Command("/bin/bash", "-c", cmd)
	go FindSScmdAndCpuLimit(limitCmd)
	cmdRes, err := cmdHandler.Output()

	if err != nil {
		return result, err
	}

	processCache.Set(fmt.Sprintf("%s_%s", "exec", cmd), string(cmdRes), CacheCommTime*time.Second)
	return string(cmdRes), nil
}

func FindSScmdAndCpuLimit(cmd string) {
	pid, err := getCmdPid(cmd)
	if err == nil {
		debug_print("FindcmdAndCpuLimit:", strconv.Itoa(pid))
		cpuLimit(pid, -9) //gas无穷大
	}
}

func getCmdPid(cmd1 string) (ssPid int, err error) {
	cmd := "ps aux|grep '" + cmd1 + "'|grep -v 'grep'"
	//cmd:="ps aux|grep hidsgo|grep "+strconv.Itoa(os.Getpid())
	//debug_print("getSSPid",cmd)
	ssRes, err := execComm(cmd)
	if err == nil && len(ssRes) > 10 {
		//debug_print("getSSPid",ssRes)
		ssList := strings.Split(strings.TrimSpace(ssRes), " ")
		ssPid := 0
		//debug_print("len ssList:",strconv.Itoa(len(ssList)))
		for index, v := range ssList {
			//debug_print(v)
			if index != 0 && len(v) > 0 {
				debug_print("find:", ssList[index])
				ssPid, _ = strconv.Atoi(ssList[index])
				break
			}
		}

		if len(ssList) > 0 {
			caller := ssList[0]
			if caller == "root" && ssPid != 0 {
				return ssPid, nil
			} else {
				return -1, err
			}
		} else {
			return -1, err
		}
	} else {
		return -1, err
	}
}

// 以前有用，现在没用了，cpu消耗达标
func cpuLimit(pid int, gas int) (err error) {
	pro, err := os.FindProcess(pid)
	if gas != -9 && gas < 0 {
		return err
	}
	gas -= 1
	//check process is alive
	if err != nil {
		//debug_print("cpuLimit err 1")
		return err
	} else {
		err := pro.Signal(syscall.Signal(0))
		if err != nil {
			//debug_print("cpuLimit err 2")
			return err
		}
	}
	time.Sleep(100 * time.Millisecond)
	pro.Signal(syscall.SIGSTOP)
	//debug_print("cpuLimit sleep: ",strconv.Itoa(pid))
	time.Sleep(4000 * time.Millisecond)
	pro.Signal(syscall.SIGCONT)
	//fmt.Println("%v",pro.Signal(syscall.SIGCONT))
	//syscall.Kill(pid, syscall.SIGCONT)
	if err := cpuLimit(pid, gas); err != nil {
		return nil
	}
	return nil
}

func CheckResourceAndKillSelf() { //20分钟检查1次，大于30%，出现3次，就kill
	HP := 100
	for {
		time.Sleep(60 * 20 * time.Second)
		SumLsofTimeCostLock.Lock()
		timeCost := SumLsofTimeCost
		SumLsofTimeCost = 0.0
		SumLsofTimeCostLock.Unlock()
		if timeCost > 60.0*6 {
			HP -= 40
			if HP <= 0 {
				form := url.Values{}
				form.Add("ES_TYPE", "hidsgo_kill")
				form.Add("version", fmt.Sprintf("%.3f", VERSION))
				form.Add("timeCost", fmt.Sprintf("%.3f", timeCost))
				SendRequest(form)
				fmt.Println("Kill hidsgo!!!, timeCost:", timeCost)
				execComm("kill -9 " + strconv.Itoa(os.Getpid()))
			}
		}
		fmt.Println("Keep hidsgo!!!, timeCost:", timeCost, "HP:", HP)
	}
}

// tcp连接数过高会导致检查时cpu负载超标
func getTCPLinkCount() int {
	result, err := execComm("ss -s|grep TCP|awk '{print $2}'")
	live_print("TCP count: ", result)
	if err != nil {
		fmt.Println("getSSLinkCount error")
	} else {
		if len(result) > 0 {
			rawResult := strings.Split(result, "\n")
			if len(rawResult) > 1 {
				count, _ := strconv.Atoi(rawResult[1])
				return count
			} else if len(rawResult) > 0 {
				count, _ := strconv.Atoi(rawResult[0])
				return count
			} else {
				return 0
			}

		}
	}
	return 0
}

func CheckLsofCheckPeriodOpen() {
	tcpLinkCount := getTCPLinkCount()
	if tcpLinkCount > TCP_COUNT_LIMIT {
		//form := url.Values{}
		//form.Add("ES_TYPE", "hidsgo_kill_Rshell")
		//form.Add("version", fmt.Sprintf("%.3f", VERSION))
		//form.Add("tcpLinkCount", fmt.Sprintf("%d", tcpLinkCount))
		//SendRequest(form)
		fmt.Println("Kill Lsof_P!!!, tcpLinkCount:", tcpLinkCount)
		IsLsofCheckPeriodOpen = false
	} else {
		IsLsofCheckPeriodOpen = true
		fmt.Println("Keep Lsof_P!!!, tcpLinkCount:", tcpLinkCount)
	}

}

func CheckResourceAndCloseLsofCheck() { //20分钟检查1次，大于30%，出现3次，就kill lsof
	HP := 100
	for {
		time.Sleep(60 * 20 * time.Second)
		SumLsofTimeCostLock.Lock()
		timeCost := SumLsofTimeCost
		SumLsofTimeCost = 0.0
		SumLsofTimeCostLock.Unlock()
		if timeCost > 60.0*10 {
			HP -= 140
		} else if timeCost > 60.0*8 {
			HP -= 50
		} else if timeCost > 60.0*6 {
			HP -= 40
		} else if HP < 100 {
			HP += 10
		}

		if HP <= 0 {
			form := url.Values{}
			form.Add("ES_TYPE", "hidsgo_kill_Rshell")
			form.Add("version", fmt.Sprintf("%.3f", VERSION))
			form.Add("timeCost", fmt.Sprintf("%.3f", timeCost))
			SendRequest(form)
			fmt.Println("Kill Lsof!!!, timeCost:", timeCost)

			LsofCheckOpenLock.Lock()
			IsLsofCheckOpen = false
			LsofCheckOpenLock.Unlock()
			break
		}
		fmt.Println("Keep Lsof!!!, timeCost:", timeCost, "HP:", HP)
	}
}

func IsSimilarByLevenshtein(s1 string, s2 string, ratio float64) bool {
	distance := levenshtein.RatioForStrings([]rune(s1), []rune(s2), levenshtein.DefaultOptions)
	//fmt.Printf(`Distance between "%s" and "%s" computed as %f`, s1, s2, distance)
	if distance >= ratio {
		return true
	} else {
		return false
	}
}

// 本地监听的端口可以加白
func CacheListenPort() map[string]bool {
	listenPort := map[string]bool{}
	result, _ := execComm("ss -n -t -l")
	if len(result) > 0 {
		resultList := strings.Split(strings.TrimSpace(result), "\n")
		for index, item := range resultList {
			if index != 0 {
				item = strings.Replace(item, ":::", ":", 1)
				rawResult := strings.Split(item, ":")[1]
				rawResult2 := strings.Split(rawResult, " ")[0]
				fmt.Println("ListenPort:", rawResult2)
				listenPort[rawResult2] = true
			}
		}
	}
	return listenPort
}

// 获取进程uid，后面检查备用
func CacheUidMapByPasswd() (map[string]string, map[string]string) {
	//var uidMap map[string]string
	uidMap := map[string]string{}
	FullUidMap := map[string]string{}
	result, _ := execComm("cat /etc/passwd")
	if len(result) > 10 {
		resultList := strings.Split(strings.TrimSpace(result), "\n")
		for _, item := range resultList {
			info := strings.Split(item, ":")
			userName := info[0]
			uid := info[2]
			if rceCheckUserMap[userName] {
				uidMap[userName] = uid
				fmt.Println("CacheUidMapByPasswd", uid, userName)
			}
			FullUidMap[userName] = uid
		}
	}
	return uidMap, FullUidMap
}

func CacheUidMapByPS(uidMap map[string]string) map[string]string {
	//var uidMap map[string]string
	result, _ := execComm("ps -ef|grep -v \"grep\"|grep -E \"php-fpm\"|awk '{print $1}' ") //除php外，其他的在调研，否则可能纳入很多非web应用账号。java可以通过
	if len(result) > 0 {
		resultList := strings.Split(strings.TrimSpace(result), "\n")
		for _, item := range resultList {
			userName := item
			if _, found := uidMap[userName]; found == false {
				uid := FullUidMap[userName]
				if _, found := rceCheckUserBlackMap[userName]; found == false {
					uidMap[userName] = uid
					fmt.Println("CacheUidMapByPS", uid, userName)
				}
			}
		}
	}
	return uidMap
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// cwd 是文件执行目录
func getFileListByCwd(cwd string) ([]string, int) {
	fileList := make([]string, 0, 4)
	recent3Count := 0
	//result,err:= execComm("ls -1 --file-type -t "+"\""+cwd+"\"  |grep -v \"/\" |head -n 3 ")
	result, err := execComm("ls -1 --file-type -t " + "\"" + cwd + "\"  |grep -v \"/\" |grep -v log |head -n 3 ") //时间倒叙top3
	//result,err:= execComm("ls -1 --file-type -t "+"\""+cwd+"\"  |grep -v \"/\" |grep -E \"\\.php|\\.jsp|\\.jar\"|head -n 3 ")
	fmt.Println(result)
	if err != nil {
		fmt.Println("getFileListByCwd error", cwd)
	} else {
		if len(result) > 0 {
			resultList := strings.Split(result, "\n")
			fmt.Println("resultList:", resultList)
			for _, item := range resultList {
				if len(item) > 0 {
					//fmt.Println("item:",item)
					if checkFileIsRecent3(cwd + "/" + item) { //top3内有几个是48h内
						recent3Count += 1
					} else {
						live_print("checkFileIsRecent3 failed,", cwd+"/"+item)
					}
					fileList = append(fileList, item)
				}
			}
			if checkFileIsRecent3(cwd) { //把cwd本身也加进去
				recent3Count += 1
			} else {
				live_print("checkFileIsRecent3 failed,", cwd)
			}
		} else {
			live_print("getFileListByCwd failed, no file found")
		}
	}
	return fileList, recent3Count
}

// 判断文件变更时间是否最近48h
func checkFileIsRecent3(filePath string) bool {
	result, err := execComm("stat \"" + filePath + "\" | grep -i Modify |awk '{print $2}'")
	fmt.Println(result)
	if err != nil {
		fmt.Println("checkFileIsRecent3 error", filePath)
	} else {
		if len(result) > 0 {
			targetTime := strings.TrimSpace(strings.Trim(result, "\n"))

			sub := subTime(targetTime)
			live_print(filePath, "sub:", sub)
			if sub <= 48 && sub > 0 {
				return true
			}
		}
	}
	return false
}

func subTime(targetTime string) int {
	format := "2006-01-02"
	now, _ := time.Parse(format, time.Now().Format(format))
	target, _ := time.Parse(format, targetTime)

	return int(now.Sub(target).Hours())
}

func getFilePathByName(name string, cwd string) []string {
	live_print("cwd!!!!!!", cwd)
	filePaths := make([]string, 0, 4)
	if cwd != "" {
		filePaths = append(filePaths, cwd+"/"+name)
	} else {
		result, err := execComm("whereis -b " + name)
		fmt.Println(result)
		if err != nil {
			fmt.Println("getFilePathByName error", name)
		} else {
			if len(result) > 0 {
				tmpResult := strings.Split(result, " ")
				for _, item := range tmpResult {
					if strings.ContainsAny(item, "/") {
						filePaths = append(filePaths, item+"/"+name)
					}
				}
			}
		}
	}
	return filePaths

}

func getFileTypeInfo(filePath string) int {
	result, err := execComm("file -ibL " + filePath)
	fmt.Println(result)
	if err != nil {
		fmt.Println("getFileTypeInfo error", filePath)
	} else {
		if len(result) > 0 {
			live_print(result)
			if strings.Contains(result, "text") {
				return TEXT
			} else if strings.Contains(result, "executable") {
				return EXEC
			} else if strings.Contains(result, "sharedlib") {
				return SO
			} else {
				return OTHER
			}
		}
	}
	return -9
}
