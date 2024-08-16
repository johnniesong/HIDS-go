package core

import (
	"fmt"
	"github.com/json-iterator/go"
	"github.com/shirou/gopsutil/v4/process"
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

func debug_print(log ...string) {
	if PRINT_DEBUG == true {
		fmt.Println(time.Now(), log)
	}
}

var privateIPBlocks []*net.IPNet

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
		return "", err
	}

	return string(buf[:400]), nil
}

func getProcessChain(pid int32) (string, error) {
	if cacheResult, found := prepPidCache.Get(fmt.Sprintf("%s_%d", "chain", pid)); found {
		return cacheResult.(string), nil
	}

	if pid != 1 && pid != 2 {
		name, pPid, cmd, _, _, err := getProcessInfo(pid)

		if err != nil {
			return "", err
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

func readFile(filename string) (string, error) {
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		//fmt.Fprintf(os.Stderr, "File Read Error: %s\n", err)
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
	form.Add("ES_TYPE", "hids-go-go_bug")
	fmt.Println("Found BUG: ", logType, bugDetail)

	return SendRequest(form)
}

// 这个iscached 只是告警部分
func isCached(exe string, A1 string, A2 string, bugType string) bool {
	// 判断当前的告警是否重复，判别项：exe 参数名 漏洞类型
	// 但有部分参数是随机的编码，比如：[whoami] [15f1e28] [15f2c08]，需要用正则表达式去除
	// 如果当前告警未缓存过，会返回false，并且设置10min的缓存
	// 如果告警缓存过，返回true
	if result, _ := regexp.MatchString("^[0-9a-f]{4,20}$", A1); result {
		A1 = ""
	}
	if result, _ := regexp.MatchString("^[0-9a-f]{4,20}$", A2); result {
		A2 = ""
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

	fmt.Println("Messages out: ", form["Exe"], form["A0"], form["A1"], form["A2"], form["Pid"], form["PPid"])

	if _, ok := form["Type"]; ok {
		if BugCachedList[form["Type"][0]] && isCached(form["Exe"][0], form["A1"][0], form["A2"][0], form["Type"][0]) {
			fmt.Println("cache found!", strings.NewReader(form.Encode()))
			return "", nil
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

func checkIsOwnAssetAndNotIsolate(target string) (string, error) {
	if isCheckOwnAsset == false { //不检查是否属于自己的资产，会默认返回false结果
		return "false", nil
	}
	data := AssetInfo{T: strconv.Itoa(int(time.Now().Unix())), Is_isolate: "0", Target: target}
	jsonData, err := jsoniter.Marshal(data)
	debug_print("checkIsOwnAssetAndNotIsolate", string(jsonData))
	client := http.Client{}
	req, err := http.NewRequest("POST", AssetServer, strings.NewReader(string(jsonData)))
	req.SetBasicAuth("skp", "1")
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
		if IS_DEBUG == true {
			time.Sleep(60 * 60 * 24 * 1 * time.Second)
			execComm("echo ''>/home/ops/hids/hids-go.log")
			execComm("echo ''>hids-go.log")
			execComm("echo ''>/tmp/hids-go.log")
			fmt.Println("Clean log")
		} else {
			time.Sleep(60 * 60 * 24 * 2 * time.Second)
			execComm("echo -n ''>/home/ops/hids/hids-go.log")
			execComm("echo -n ''>hids-go.log")
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
		form.Add("ES_TYPE", "hids-go_dot")
		form.Add("version", fmt.Sprintf("%.3f", VERSION))
		form.Add("web_service", string(cmdRes))
		SendRequest(form)
		randomTime := rand.Intn(7200) + 60*60*6 //2+6
		time.Sleep(time.Duration(randomTime) * time.Second)
	}
}

func CPUCheck() {

	for {
		randomTime := rand.Intn(600) + 600
		time.Sleep(time.Duration(randomTime) * time.Second)
		// 获取cpu占用率
		cpuPercent := "top -b -n 10 | grep hids-go | awk -F ' ' '{print $9}'"
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
			form.Add("ES_TYPE", "hids-go_dot")
			form.Add("version", fmt.Sprintf("%.3f", VERSION))
			SendRequest(form)
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
		fmt.Println(item, result[item])
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
		return result, err
	}

	processCache.Set(fmt.Sprintf("%s_%s", "exec", cmd), string(cmdRes), CacheCommTime*time.Second)
	return string(cmdRes), nil
}

func execCommAndLimitCPU(cmd string) (string, error) {
	if cacheResult, found := prepPidCache.Get(fmt.Sprintf("%s_%s", "exec", cmd)); found {
		return cacheResult.(string), nil
	}

	result := ""

	cmdHandler := exec.Command("/bin/bash", "-c", cmd)
	go FindSScmdAndCpuLimit()
	cmdRes, err := cmdHandler.Output()

	if err != nil {
		return result, err
	}

	processCache.Set(fmt.Sprintf("%s_%s", "exec", cmd), string(cmdRes), CacheCommTime*time.Second)
	return string(cmdRes), nil
}

var IsOwnAssetAndNotIsolateMap map[string]bool

// 检查对应的容器进程是否有建立连接
// 返回值1: bool, 是否有端口监听
// 返回值2: string, 端口相关情况
func checkProcessListenPort_V3(pid int32, bug *BugDetail) (bool, string) {
	//for k,v:=range(IsOwnAssetAndNotIsolateMap){
	//	debug_print("IsOwnAssetAndNotIsolateMap",k,strconv.FormatBool(v))
	//}
	time.Sleep(500 * time.Microsecond)
	ssRes, _ := execCommAndLimitCPU("ss -a -np|grep ESTAB|grep pid=" + strconv.Itoa(int(pid)) + ",")
	ssList := strings.Split(strings.TrimSpace(ssRes), "\n")
	for _, v := range ssList {
		fmt.Println(v)
		if len(v) > 10 {
			ssItemList := make([]string, 0, 6)
			for _, item := range strings.Split(strings.TrimSpace(v), "  ") {
				if len(item) > 1 {
					ssItemList = append(ssItemList, item)
				}
			}
			for index, item1 := range ssItemList {
				debug_print(strconv.Itoa(index), item1)
			}
			//protocol:=ssItemList[0]
			sip_sport := strings.TrimSpace(ssItemList[2])
			dip_dport := strings.TrimSpace(ssItemList[3])
			processInfo := ssItemList[4]
			//sip:=strings.Split(sip_sport,":")[0]
			//dip:=strings.Split(dip_dport,":")[0]

			if strings.Contains(sip_sport, "* ") && strings.Contains(dip_dport, "* ") {
				continue
			}
			// 去除一些已知的Agent导致的误报
			if strings.Contains(processInfo, "tmon") || strings.Contains(processInfo, "hooagent") || strings.Contains(processInfo, "wonder-agent") {
				continue
			}
			//if isPrivateIP(net.ParseIP(sip)) && isPrivateIP(net.ParseIP(dip)){
			//	continue
			//}
			countOfBash := strings.Count(processInfo, "\"bash\"")
			countOfSh := strings.Count(processInfo, "\"sh\"")
			countOfProcess := strings.Count(processInfo, "),(") + 1

			if (countOfBash > 0 || countOfSh > 0) && (countOfSh+countOfBash < countOfProcess) {
				bug.SSCheckSPort = sip_sport
				bug.SSCheckDPort = dip_dport
				return true, v
			}
		}
	}

	return false, ""
}

// 检查对应的容器进程是否有建立连接
// 返回值1: bool, 是否有端口监听
// 返回值2: string, 端口相关情况
func checkProcessListenPort_V2(pid int32) (bool, string) {
	debug_print("11111111111111")
	for k, v := range IsOwnAssetAndNotIsolateMap {
		debug_print("IsOwnAssetAndNotIsolateMap", k, strconv.FormatBool(v))
	}
	time.Sleep(1 * time.Second)
	ssRes, _ := execCommAndLimitCPU("ss -a -np|grep ESTAB|grep pid=" + strconv.Itoa(int(pid)) + ",")
	ssList := strings.Split(strings.TrimSpace(ssRes), "\n")
	for _, v := range ssList {
		fmt.Println(v)
		if len(v) > 10 {
			ssItemList := make([]string, 0, 6)
			for _, item := range strings.Split(strings.TrimSpace(v), "  ") {
				if len(item) > 1 {
					ssItemList = append(ssItemList, item)
				}
			}
			for index, item1 := range ssItemList {
				debug_print(strconv.Itoa(index), item1)
			}
			//protocol:=ssItemList[0]
			sip_sport := strings.TrimSpace(ssItemList[2])
			dip_dport := strings.TrimSpace(ssItemList[3])
			processInfo := ssItemList[4]
			sip := strings.Split(sip_sport, ":")[0]
			dip := strings.Split(dip_dport, ":")[0]

			if strings.Contains(sip_sport, "* ") && strings.Contains(dip_dport, "* ") {
				continue
			}
			// 去除一些已知的Agent导致的误报
			if strings.Contains(processInfo, "tmon") || strings.Contains(processInfo, "hooagent") || strings.Contains(processInfo, "wonder-agent") {
				continue
			}
			if isPrivateIP(net.ParseIP(sip)) && isPrivateIP(net.ParseIP(dip)) {
				continue
			}
			countOfBash := strings.Count(processInfo, "\"bash\"")
			countOfSh := strings.Count(processInfo, "\"sh\"")
			countOfProcess := strings.Count(processInfo, "),(") + 1

			if (countOfBash > 0 || countOfSh > 0) && (countOfSh+countOfBash < countOfProcess) { //在里面判断，不是公司资产就报警
				if strings.HasPrefix(dip, "* ") == true { //* XXXXX 肯定不是公司资产，甚至不是ip。。。
					return true, v
				}
				if isOwn, isIn := IsOwnAssetAndNotIsolateMap[dip]; isIn == false { //如果不在cache里，就请求检查，并更新cache
					if resp, _ := checkIsOwnAssetAndNotIsolate(dip); strings.Contains(resp, "false") { //不是公司资产，就是有问题的连接
						IsOwnAssetAndNotIsolateMap[dip] = false
						return true, v
					} else {
						IsOwnAssetAndNotIsolateMap[dip] = true
					}
				} else if isOwn == false { //在cache里，不是自己的资产且非隔离
					return true, v
				}
			}
		}
	}

	return false, ""
}

func FindSScmdAndCpuLimit() {
	//time.Sleep(3000*time.Millisecond)
	ssPid, err := getSSPid()
	if err == nil {
		debug_print("FindSScmdAndCpuLimit:", strconv.Itoa(ssPid))
		cpuLimit(ssPid, -9) //gas无穷大
	}
}

func getSSPid() (ssPid int, err error) {
	cmd := "ps aux|grep 'ss -a -np'|grep -v 'grep'"
	//cmd:="ps aux|grep hids-go|grep "+strconv.Itoa(os.Getpid())
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
	time.Sleep(500 * time.Millisecond)
	pro.Signal(syscall.SIGSTOP)
	//debug_print("cpuLimit sleep: ",strconv.Itoa(pid))
	time.Sleep(1200 * time.Millisecond)
	pro.Signal(syscall.SIGCONT)
	//fmt.Println("%v",pro.Signal(syscall.SIGCONT))
	//syscall.Kill(pid, syscall.SIGCONT)
	if err := cpuLimit(pid, gas); err != nil {
		return nil
	}
	return nil
}
