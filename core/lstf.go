package core

import (
	"fmt"
	"github.com/yuuki/lstf/tcpflow"
	"net"
	"strconv"
	"strings"
)

//这里主要是对lstf 的封装，通过netlink先检查一次，提高性能,lsof太重了

func GetHostFlows() [][]string {
	options := tcpflow.GetHostFlowsOption{Processes: false, Filter: tcpflow.FilterAll, Numeric: true}
	flows, err := tcpflow.GetHostFlows(&options)
	if err != nil {
		fmt.Println("failed to get host flows: %v", err)
	}
	result := make([][]string, 0, 10)
	for _, flow := range flows {
		item := strings.Fields(flow.String())
		//fmt.Println(item)
		result = append(result, item)
		//fmt.Println(flow)
	}
	return result
}

func HasAbnormalConnect() bool {
	lstfInfo := GetHostFlows()
	for _, info := range lstfInfo {
		status := info[1]
		//sip:=strings.Split(info[0],":")[0]
		dip := strings.Split(info[2], ":")[0]
		if status == "-->" {
			if isPrivateIP(net.ParseIP(dip)) {
				continue
			}

			if _, found := IPSMap[dip]; found == true {
				continue
			}
			//
			//if _,found:=IPSGrayCache.Get(dip);found==true{
			//	continue
			//}

			if CheckIsOwnAsset(dip, "0") == false {
				live_print("HasAbnormalConnect:", dip)
				//IPSGrayCache.Set(dip,true,2*24*time.Hour)
				return true
			}
		}
	}
	return false
}

func HasAbnormalConnectByDip(tdip string, maxCount int) bool {
	lstfInfo := GetHostFlows()
	for _, info := range lstfInfo {
		status := info[1]
		count, err := strconv.Atoi(info[3])
		if err != nil {
			count = 1
		}
		sip := strings.Split(info[0], ":")[0]
		dip := strings.Split(info[2], ":")[0]
		fmt.Println(dip)
		if status == "-->" && tdip == dip && maxCount >= count {
			live_print("HasAbnormalConnectByTarget found!!!!!!", status, sip, tdip, dip)
			return true
		}
	}
	return false
}

func HasAbnormalConnectByTarget(target string, maxCount int) bool {
	tsip := strings.Split(target, "->")[0]
	tdip := strings.Split(target, "->")[1]
	lstfInfo := GetHostFlows()
	for _, info := range lstfInfo {
		status := info[1]
		count, err := strconv.Atoi(info[3])
		if err != nil {
			count = 1
		}
		sip := strings.Split(info[0], ":")[0]
		dip := info[2]
		if maxCount >= count && status == "-->" && tdip == dip && strings.HasPrefix(tsip, sip) {
			live_print("HasAbnormalConnectByTarget found!!!!!!", status, sip, tsip, tdip, dip)
			return true
		}
	}
	return false
}
